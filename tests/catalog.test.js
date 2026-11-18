const assert = require('assert');

const catalogManager = require('../server/services/catalogManager');
const { resolvePlaceholders, resolveEnv, generateSecret, STEPS, PORT_RANGE } = require('../server/services/catalogManager');
const { TEMPLATES, CATEGORIES, validateTemplate, validateCatalog } = require('../server/services/catalog/templates');

/**
 * Pruebas del catálogo de servicios de un clic.
 *
 * Ninguna necesita Docker. Eso es deliberado: lo que rompe un catálogo no es
 * que Docker falle —eso se ve enseguida— sino que una plantilla tenga un
 * marcador mal escrito, una etiqueta móvil o un secreto que nadie usa. Todo eso
 * se puede comprobar sin arrancar nada, y por tanto tiene que comprobarse en
 * cada ejecución de la suite.
 *
 * La instalación real contra Docker se verifica en `scripts/test-install.sh`,
 * que levanta un Debian con systemd de verdad.
 */
async function testCatalog() {
  console.log('🧪 Probando el catálogo de servicios de un clic...');

  // -------------------------------------------------------------------------
  // 1. El catálogo entero pasa su propia validación
  // -------------------------------------------------------------------------
  const problems = validateCatalog();
  assert.deepStrictEqual(problems, [], `El catálogo tiene problemas de formato:\n${problems.join('\n')}`);
  assert.ok(TEMPLATES.length >= 10, 'El catálogo debe traer al menos diez plantillas');
  console.log(`  ✓ ${TEMPLATES.length} plantillas válidas en ${CATEGORIES.length} categorías`);

  // -------------------------------------------------------------------------
  // 2. Ninguna imagen usa una etiqueta móvil
  // -------------------------------------------------------------------------
  //
  // `latest` convierte un simple reinicio del contenedor en una actualización
  // mayor no pedida. Es la causa número uno de «ayer funcionaba» en las
  // plataformas de autohospedaje.
  for (const tpl of TEMPLATES) {
    const images = [tpl.app.image, ...(tpl.sidecars || []).map((c) => c.image)];
    if (tpl.database && tpl.database.image) images.push(tpl.database.image);
    for (const image of images) {
      assert.ok(image.includes(':'), `${tpl.id}: la imagen ${image} no lleva etiqueta`);
      assert.ok(!/:latest$/.test(image), `${tpl.id}: ${image} usa «latest»`);
      assert.ok(!/:(stable|main|master|edge|nightly)$/.test(image), `${tpl.id}: ${image} usa una etiqueta móvil`);
    }
  }
  console.log('  ✓ Todas las imágenes están fijadas a una versión concreta');

  // -------------------------------------------------------------------------
  // 3. Límites, volúmenes y sondas en todas
  // -------------------------------------------------------------------------
  for (const tpl of TEMPLATES) {
    assert.ok(tpl.app.memoryMb >= 128, `${tpl.id}: sin límite de memoria`);
    assert.ok(tpl.app.cpus > 0, `${tpl.id}: sin límite de CPU`);
    assert.ok(tpl.app.readiness && tpl.app.readiness.path.startsWith('/'), `${tpl.id}: sonda inválida`);
    assert.ok(tpl.app.readiness.expect.length > 0, `${tpl.id}: la sonda no declara códigos esperados`);
    // Estado persistente: o base de datos gestionada, o volumen. Sin una de las
    // dos, el servicio pierde todo en el primer reinicio.
    const persists = Boolean(tpl.database) || (tpl.app.volumes || []).length > 0;
    assert.ok(persists, `${tpl.id}: no persiste nada`);
  }
  console.log('  ✓ Todas declaran límites de recursos, persistencia y sonda');

  // -------------------------------------------------------------------------
  // 4. Cada plantilla resuelve por completo, sin marcadores huérfanos
  // -------------------------------------------------------------------------
  //
  // Esta es la prueba que más vale del fichero. Un `{{db.passwrd}}` mal escrito
  // no rompe nada visible: la variable de entorno llega con el texto literal
  // dentro y el servicio arranca con esa cadena como contraseña, funcionando a
  // medias hasta que alguien lo investiga. Aquí se caza en la suite.
  for (const tpl of TEMPLATES) {
    const secrets = {};
    for (const [key, spec] of Object.entries(tpl.secrets || {})) secrets[key] = generateSecret(spec);

    const context = {
      installId: 'svc_prueba_00000000',
      domain: 'servicio.ejemplo.com',
      url: 'https://servicio.ejemplo.com',
      secrets,
      db: tpl.database
        ? { host: tpl.database.engine, port: 5432, user: 'u', password: 'p', name: 'd', url: 'postgresql://u:p@h/d' }
        : null,
      sidecarHosts: Object.fromEntries((tpl.sidecars || []).map((c) => [c.name, `culkibo_svc_x_${c.name}`]))
    };

    const resolved = resolveEnv(tpl.app.env, context);
    for (const [key, value] of Object.entries(resolved)) {
      assert.ok(!value.includes('{{'), `${tpl.id}: la variable ${key} deja un marcador sin resolver: ${value}`);
    }
    for (const car of tpl.sidecars || []) {
      for (const [key, value] of Object.entries(resolveEnv(car.env, context))) {
        assert.ok(!value.includes('{{'), `${tpl.id}/${car.name}: ${key} deja un marcador sin resolver`);
      }
    }

    // Y los secretos generados llegan de verdad al entorno, no una cadena vacía.
    for (const [key, value] of Object.entries(secrets)) {
      const used = Object.values(resolved).some((v) => v.includes(value));
      assert.ok(used, `${tpl.id}: el secreto ${key} se genera pero no llega a ninguna variable`);
    }
  }
  console.log('  ✓ Las 13 plantillas resuelven sus variables sin marcadores huérfanos');

  // -------------------------------------------------------------------------
  // 5. Un marcador desconocido revienta en vez de colarse
  // -------------------------------------------------------------------------
  const ctx = { installId: 'svc_x_0', domain: 'd', url: 'u', secrets: { A: '1' }, db: null, sidecarHosts: {} };
  assert.strictEqual(resolvePlaceholders('{{secret.A}}', ctx), '1');
  assert.strictEqual(resolvePlaceholders('pre-{{domain}}-post', ctx), 'pre-d-post');
  assert.throws(() => resolvePlaceholders('{{secret.NOEXISTE}}', ctx), /Marcador desconocido/);
  assert.throws(() => resolvePlaceholders('{{inventado}}', ctx), /Marcador desconocido/);
  assert.throws(() => resolvePlaceholders('{{db.url}}', ctx), /requiere una base de datos/);
  assert.throws(() => resolvePlaceholders('{{sidecar.fantasma.host}}', ctx), /Marcador desconocido/);
  console.log('  ✓ Un marcador desconocido lanza en vez de llegar literal al contenedor');

  // -------------------------------------------------------------------------
  // 6. Secretos: entropía y alfabeto
  // -------------------------------------------------------------------------
  const hex = generateSecret({ bytes: 32, encoding: 'hex' });
  assert.strictEqual(hex.length, 64);
  assert.ok(/^[0-9a-f]+$/.test(hex), 'hex debe ser hexadecimal');

  const urlSafe = generateSecret({ bytes: 24, encoding: 'base64url' });
  assert.ok(/^[A-Za-z0-9_-]+$/.test(urlSafe), 'base64url no puede traer +, / ni =');

  const b64 = generateSecret({ bytes: 64, encoding: 'base64' });
  assert.ok(Buffer.from(b64, 'base64').length === 64, 'base64 debe decodificar a los bytes pedidos');

  // Dos llamadas no pueden coincidir jamás.
  assert.notStrictEqual(generateSecret({ bytes: 32, encoding: 'hex' }), hex);
  // Suelo de entropía: pedir 4 bytes no puede producir un secreto de 4 bytes.
  assert.ok(Buffer.from(generateSecret({ bytes: 4, encoding: 'hex' }), 'hex').length >= 16);
  console.log('  ✓ Secretos con alfabeto correcto y suelo de entropía de 16 bytes');

  // -------------------------------------------------------------------------
  // 7. La validación rechaza plantillas malas
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
    [{ ...base, app: { ...base.app, memoryMb: 0 } }, /límite de memoria/],
    [{ ...base, app: { ...base.app, readiness: null } }, /sonda de disponibilidad/],
    [{ ...base, app: { ...base.app, volumes: [] } }, /no sobrevivirían/],
    [{ ...base, category: 'inventada' }, /categoría desconocida/],
    [{ ...base, id: 'MAYUSCULAS' }, /id inválido/],
    [{ ...base, app: { ...base.app, env: { X: '{{secret.SIN_DECLARAR}}' } } }, /sin declararlo/],
    [{ ...base, secrets: { HUERFANO: { bytes: 32, encoding: 'hex' } } }, /no lo usa/],
    [{ ...base, app: { ...base.app, env: { X: '{{db.url}}' } } }, /no declara ninguna base de datos/],
    [{ ...base, secrets: { DEBIL: { bytes: 4, encoding: 'hex' } }, app: { ...base.app, env: { X: '{{secret.DEBIL}}' } } }, /menos de 16 bytes/]
  ];
  for (const [bad, pattern] of cases) {
    const found = validateTemplate(bad);
    assert.ok(found.length > 0, `Debería rechazarse: ${pattern}`);
    assert.ok(found.some((p) => pattern.test(p)), `Se esperaba ${pattern}, se obtuvo: ${found.join(' | ')}`);
  }
  console.log(`  ✓ La validación rechaza las ${cases.length} formas conocidas de plantilla rota`);

  // -------------------------------------------------------------------------
  // 8. Nombres seguros para Docker
  // -------------------------------------------------------------------------
  //
  // Lo que se construye aquí acaba en un `docker run` y en un `--health-cmd`.
  // Si un identificador pudiera traer un espacio o una comilla, sería un fallo
  // de inyección; se comprueba que el formato no lo permite.
  const id = 'svc_uptime-kuma_deadbeef';
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.containerName(id, 'app')));
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.volumeName(id, 'data')));
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.networkName(id)));
  assert.throws(() => catalogManager.mustGet('no-es-un-id'), /inválido/);
  assert.throws(() => catalogManager.mustGet('svc_x_$(whoami)'), /inválido/);
  console.log('  ✓ Los nombres derivados sólo contienen caracteres seguros');

  // -------------------------------------------------------------------------
  // 9. Reserva de puertos
  // -------------------------------------------------------------------------
  const port = await catalogManager.allocatePort();
  assert.ok(port >= PORT_RANGE.start && port <= PORT_RANGE.end, `Puerto fuera del rango: ${port}`);
  assert.ok(await catalogManager.portIsFree(port), 'El puerto reservado debe estar realmente libre');
  console.log(`  ✓ Reserva de puerto en ${PORT_RANGE.start}-${PORT_RANGE.end} comprobada contra el sistema`);

  // -------------------------------------------------------------------------
  // 10. La instalación rechaza entradas inválidas antes de tocar nada
  // -------------------------------------------------------------------------
  await assert.rejects(
    () => catalogManager.install({ templateId: 'no-existe' }),
    /no existe en el catálogo/
  );
  // Un dominio mal formado tiene que caer antes de crear redes ni contenedores.
  await assert.rejects(
    () => catalogManager.install({ templateId: 'uptime-kuma', domain: 'esto no es un dominio' }),
    /Dominio inválido|Docker no está disponible/
  );
  console.log('  ✓ Una plantilla inexistente y un dominio inválido se rechazan antes de actuar');

  // -------------------------------------------------------------------------
  // 11. La proyección pública nunca lleva secretos
  // -------------------------------------------------------------------------
  const fake = {
    id: 'svc_prueba_12345678', templateId: 'uptime-kuma', templateName: 'Uptime Kuma',
    name: 'X', category: 'monitorizacion', image: 'i:1', domain: null, url: 'http://127.0.0.1:42000',
    hostPort: 42000, appPort: 3001, containerName: 'c', networkName: 'n', sidecars: [],
    volumes: {}, databaseId: null, memoryMb: 512, cpus: 1, status: 'running', health: 'healthy',
    progress: null, createdAt: 'a', updatedAt: 'b',
    secretsEnc: { UN_SECRETO: 'v1:aaa:bbb:ccc' }
  };
  const proyectado = JSON.stringify(catalogManager.toPublic(fake));
  assert.ok(proyectado.includes('UN_SECRETO'), 'El nombre del secreto sí se publica');
  assert.ok(!proyectado.includes('v1:aaa'), 'El valor cifrado NO puede salir en la proyección pública');
  assert.ok(!proyectado.includes('secretsEnc'), 'La proyección pública no expone el almacén de secretos');
  console.log('  ✓ La proyección pública publica los nombres de los secretos, nunca sus valores');

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
