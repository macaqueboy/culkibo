const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const EventEmitter = require('events');

const databaseManager = require('./databaseManager');
const domainManager = require('./domainManager');
const ingressManager = require('./ingressManager');
const { atomicWriteJsonSync } = require('./ssrfGuard');
const { TEMPLATES, CATEGORIES, validateCatalog } = require('./catalog/templates');

const CATEGORY_MAP = new Map(CATEGORIES.map((c) => [c.id, c.label]));
const CATEGORIES_WITH_COUNT = CATEGORIES.map((c) => ({
  ...c,
  count: TEMPLATES.filter((t) => t.category === c.id).length
}));
const TEMPLATE_MAP = new Map(TEMPLATES.map((t) => [t.id, t]));

/**
 * Instalador de servicios del catálogo.
 *
 * ---------------------------------------------------------------------------
 * QUÉ SE REUTILIZA Y POR QUÉ
 * ---------------------------------------------------------------------------
 *
 * Este módulo NO reimplementa el aprovisionamiento de bases de datos ni el
 * lanzador de `docker`. Los toma de `databaseManager`, que ya resolvió los dos
 * problemas difíciles y los tiene cubiertos por pruebas:
 *
 *   - `databaseManager.provision()` para la base de datos de aplicación de las
 *     plantillas que la necesitan. Consecuencia directa y deseada: la base de
 *     n8n o de Ghost hereda contraseña generada, cifrado en reposo, copias
 *     programadas, retención y subida a S3. Un servicio del catálogo no es un
 *     ciudadano de segunda.
 *   - `databaseManager.docker(argv)` para hablar con Docker. Es el único
 *     invocador auditado del proyecto que nunca construye una cadena de shell.
 *     Duplicarlo significaría dos sitios que arreglar el día que esté mal.
 *
 * Lo que sí es propio de aquí, porque no existía: red por instalación, reserva
 * de puerto en bucle local, secretos de aplicación, ficheros de configuración
 * montados, sonda HTTP de disponibilidad y el alta del dominio.
 *
 * ---------------------------------------------------------------------------
 * MODELO DE EXPOSICIÓN
 * ---------------------------------------------------------------------------
 *
 * Cada servicio publica su puerto HTTP SÓLO en `127.0.0.1`. Nunca en `0.0.0.0`,
 * y no es configurable. El motivo es el mismo que documenta `databaseManager`:
 * en Linux, `docker run -p` escribe en la cadena DOCKER de iptables, que se
 * evalúa ANTES que UFW. Un puerto publicado en `0.0.0.0` está abierto a
 * internet aunque el cortafuegos del usuario diga lo contrario.
 *
 * El acceso público llega por Caddy, que termina TLS en el 443 y reenvía al
 * puerto local. Así el único camino desde fuera pasa por HTTPS y por una ruta
 * que Culkibo conoce.
 */

const DATA_FILE = path.join(__dirname, '..', '..', 'data', 'services.json');
const KEY_FILE = path.join(__dirname, '..', '..', 'data', '.services.key');
const FILES_ROOT = path.join(__dirname, '..', '..', 'data', 'services');
const TMP_DIR = path.join(__dirname, '..', '..', 'data', '.tmp');

/**
 * Rango de puertos de bucle local reservado al catálogo.
 *
 * Alto y acotado a propósito: fuera del rango efímero que el núcleo reparte
 * (32768-60999 en Linux), para que un puerto reservado hoy no se lo lleve
 * mañana una conexión saliente cualquiera.
 */
const PORT_RANGE_START = 42000;
const PORT_RANGE_END = 42999;

/** Pasos de una instalación. El panel los pinta en este orden. */
const STEPS = [
  { key: 'validar', label: 'Comprobando requisitos' },
  { key: 'red', label: 'Creando la red aislada' },
  { key: 'base_datos', label: 'Aprovisionando la base de datos' },
  { key: 'auxiliares', label: 'Levantando servicios auxiliares' },
  { key: 'descarga', label: 'Descargando la imagen' },
  { key: 'arranque', label: 'Arrancando el contenedor' },
  { key: 'dominio', label: 'Publicando el dominio con HTTPS' },
  { key: 'sonda', label: 'Esperando a que responda' },
  { key: 'listo', label: 'Instalación terminada' }
];

const DEFAULT_READY_TIMEOUT_MS = 120000;

// ---------------------------------------------------------------------------
// Validación
// ---------------------------------------------------------------------------

const INSTALL_ID_RE = /^svc_[a-z0-9-]{2,32}_[0-9a-f]{8}$/;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/;

function assertInstallId(id) {
  if (!INSTALL_ID_RE.test(String(id || ''))) throw new Error('Identificador de instalación inválido');
  return String(id);
}

// ---------------------------------------------------------------------------
// Cifrado en reposo
// ---------------------------------------------------------------------------

/**
 * Misma construcción que `databaseManager`, con su propia clave y su propio
 * fichero. Separar las claves significa que filtrar `services.json` no expone
 * las contraseñas de las bases de datos, y al revés.
 */
function loadOrCreateKey() {
  try {
    if (fs.existsSync(KEY_FILE)) {
      const key = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
      if (key.length === 32) return key;
    }
  } catch (e) {}
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  fs.writeFileSync(KEY_FILE, key.toString('hex'), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(KEY_FILE, 0o600); } catch (e) {}
  return key;
}

function encryptSecret(plain, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${enc.toString('base64')}`;
}

function decryptSecret(blob, key) {
  const parts = String(blob || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') return String(blob || '');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[1], 'base64'));
  decipher.setAuthTag(Buffer.from(parts[2], 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
}

/**
 * Genera un secreto con la codificación que pida la plantilla.
 *
 * `base64url` por defecto donde el valor va a acabar dentro de una URI: `+`,
 * `/` y `=` obligan a escapar y media biblioteca cliente del mundo se equivoca
 * al hacerlo. Donde el proyecto de destino exige base64 clásico —Phoenix y su
 * `SECRET_KEY_BASE`— se usa base64, porque ahí el valor no viaja en ninguna URI.
 */
function generateSecret({ bytes = 32, encoding = 'base64url' } = {}) {
  const buf = crypto.randomBytes(Math.max(16, Math.min(128, bytes)));
  if (encoding === 'hex') return buf.toString('hex');
  if (encoding === 'base64') return buf.toString('base64');
  return buf.toString('base64url');
}

// ---------------------------------------------------------------------------
// Sustitución de marcadores
// ---------------------------------------------------------------------------

/**
 * Reemplaza `{{...}}` en un valor de entorno.
 *
 * Deliberadamente NO es un motor de plantillas: sólo conoce los marcadores de
 * la lista y cualquier otro se considera un error de la plantilla. Si dejara
 * pasar lo desconocido, un `{{db.password}}` mal escrito llegaría literal a la
 * variable de entorno y el servicio arrancaría con la cadena «{{db.passwrd}}»
 * como contraseña, funcionando a medias hasta que alguien lo investigase.
 */
function resolvePlaceholders(value, context) {
  return String(value).replace(/\{\{([a-zA-Z0-9_.]+)\}\}/g, (full, expr) => {
    const parts = expr.split('.');

    if (expr === 'domain') return context.domain || '';
    if (expr === 'url') return context.url || '';
    if (expr === 'install.id') return context.installId;

    if (parts[0] === 'secret' && parts.length === 2) {
      if (!(parts[1] in context.secrets)) throw new Error(`Marcador desconocido: ${full}`);
      return context.secrets[parts[1]];
    }

    if (parts[0] === 'db' && parts.length === 2) {
      if (!context.db) throw new Error(`${full} requiere una base de datos y la plantilla no declara ninguna`);
      if (!(parts[1] in context.db)) throw new Error(`Marcador desconocido: ${full}`);
      return String(context.db[parts[1]]);
    }

    if (parts[0] === 'sidecar' && parts.length === 3 && parts[2] === 'host') {
      const host = context.sidecarHosts[parts[1]];
      if (!host) throw new Error(`Marcador desconocido: ${full}`);
      return host;
    }

    throw new Error(`Marcador desconocido: ${full}`);
  });
}

function resolveEnv(env, context) {
  const out = {};
  for (const [key, value] of Object.entries(env || {})) {
    out[key] = resolvePlaceholders(value, context);
  }
  return out;
}

// ---------------------------------------------------------------------------

class CatalogManager extends EventEmitter {
  constructor() {
    super();
    /** @type {{ version: number, installations: any[] }} */
    this.state = { version: 1, installations: [] };
    /** @type {Buffer | null} */
    this.key = null;
    /** @type {Set<string>} Instalaciones en curso en ESTE proceso, para no lanzar dos a la vez. */
    this.inFlight = new Set();
    /** @type {Set<number>} Puertos reservados en memoria antes de añadir el registro (evita TOCTOU). */
    this.pendingPorts = new Set();
    /** @type {Buffer | null} */
    this._catalogSerializedCache = null;
    this.ensureDirs();
    this.load();
  }

  ensureDirs() {
    for (const dir of [path.dirname(DATA_FILE), FILES_ROOT, TMP_DIR]) {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    }
  }

  get cryptoKey() {
    if (!this.key) this.key = loadOrCreateKey();
    return this.key;
  }

  load() {
    try {
      if (fs.existsSync(DATA_FILE)) {
        const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
        if (parsed && Array.isArray(parsed.installations)) {
          this.state = {
            version: 1,
            installations: parsed.installations.map((i) => ({
              sidecars: [],
              volumes: {},
              secretsEnc: {},
              ...i,
              // Una instalación que se quedó a medias porque el daemon murió no
              // puede volver como «instalando»: nadie la está instalando ya.
              status: i.status === 'installing' ? 'error' : i.status,
              lastError: i.status === 'installing'
                ? 'La instalación se interrumpió al detenerse el daemon. Elimínala y vuelve a intentarlo.'
                : i.lastError || null
            }))
          };
        }
      }
    } catch (err) {
      console.error('[Catálogo] No se pudo leer services.json:', err.message);
    }
  }

  save() {
    this._catalogSerializedCache = null;
    try {
      atomicWriteJsonSync(DATA_FILE, this.state, 0o600);
    } catch (err) {
      console.error('[Catálogo] No se pudo guardar services.json:', err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Catálogo
  // -------------------------------------------------------------------------

  /** Las plantillas, sin la maquinaria interna que el panel no necesita. */
  listTemplates() {
    const installed = new Map();
    for (const inst of this.state.installations) {
      installed.set(inst.templateId, (installed.get(inst.templateId) || 0) + 1);
    }

    return TEMPLATES.map((t) => ({
      id: t.id,
      name: t.name,
      category: t.category,
      categoryLabel: CATEGORY_MAP.get(t.category) || t.category,
      summary: t.summary,
      description: t.description,
      website: t.website,
      licence: t.licence,
      tags: t.tags || [],
      image: t.app.image,
      port: t.app.port,
      memoryMb: t.app.memoryMb,
      cpus: t.app.cpus,
      // Suma de todo lo que va a arrancar: sin esto, alguien con 2 GB instala
      // Plausible y descubre el problema cuando el núcleo mata el contenedor.
      totalMemoryMb:
        t.app.memoryMb +
        (t.database ? (t.database.memoryMb || 512) : 0) +
        (t.sidecars || []).reduce((sum, c) => sum + c.memoryMb, 0),
      database: t.database ? { engine: t.database.engine, image: t.database.image || null } : null,
      sidecars: (t.sidecars || []).map((c) => ({ name: c.name, image: c.image, memoryMb: c.memoryMb })),
      secretNames: Object.keys(t.secrets || {}),
      nextSteps: t.nextSteps || [],
      notes: t.notes || [],
      installedCount: installed.get(t.id) || 0
    }));
  }

  listCategories() {
    return CATEGORIES_WITH_COUNT;
  }

  /** Buffer JSON pre-serializado para GET /api/catalog. */
  getCatalogSerialized() {
    if (!this._catalogSerializedCache) {
      this._catalogSerializedCache = Buffer.from(JSON.stringify({
        categories: this.listCategories(),
        templates: this.listTemplates(),
        installations: this.list()
      }), 'utf8');
    }
    return this._catalogSerializedCache;
  }

  getTemplate(templateId) {
    const tpl = TEMPLATE_MAP.get(templateId);
    if (!tpl) throw new Error(`La plantilla «${templateId}» no existe en el catálogo`);
    return tpl;
  }

  // -------------------------------------------------------------------------
  // Docker (siempre argv, nunca cadena de shell)
  // -------------------------------------------------------------------------

  docker(args, options) {
    return databaseManager.docker(args, options);
  }

  isDockerAvailable(force) {
    return databaseManager.isDockerAvailable(force);
  }

  // -------------------------------------------------------------------------
  // Nombres y puertos
  // -------------------------------------------------------------------------

  containerName(installId, role = 'app') { return `culkibo_svc_${installId.slice(4)}_${role}`; }
  volumeName(installId, key) { return `culkibo_svcdata_${installId.slice(4)}_${key}`; }
  networkName(installId) { return `culkibo_net_${installId}`; }

  /** Puertos que este registro ya tiene reservados. */
  reservedPorts() {
    return new Set(this.state.installations.map((i) => i.hostPort).filter(Boolean));
  }

  /**
   * ¿Se puede escuchar en este puerto de bucle local ahora mismo?
   *
   * Consultar sólo nuestro propio registro no basta: el puerto puede estar en
   * manos de otro programa del host. Se comprueba de verdad intentando
   * enlazarlo, que es la única respuesta que no miente.
   */
  portIsFree(port) {
    return new Promise((resolve) => {
      const probe = net.createServer();
      probe.once('error', () => resolve(false));
      probe.once('listening', () => probe.close(() => resolve(true)));
      probe.listen(port, '127.0.0.1');
    });
  }

  async allocatePort() {
    const reserved = this.reservedPorts();
    for (let port = PORT_RANGE_START; port <= PORT_RANGE_END; port++) {
      if (reserved.has(port) || this.pendingPorts.has(port)) continue;
      this.pendingPorts.add(port);
      if (await this.portIsFree(port)) return port;
      this.pendingPorts.delete(port);
    }
    throw new Error(`No queda ningún puerto libre entre ${PORT_RANGE_START} y ${PORT_RANGE_END}`);
  }

  // -------------------------------------------------------------------------
  // Progreso
  // -------------------------------------------------------------------------

  setProgress(record, stepKey, message, extra = {}, { persist = true } = {}) {
    const index = STEPS.findIndex((s) => s.key === stepKey);
    record.progress = {
      step: stepKey,
      stepIndex: index < 0 ? 0 : index,
      totalSteps: STEPS.length,
      label: (STEPS[index] || {}).label || stepKey,
      message,
      startedAt: record.progress ? record.progress.startedAt : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...extra
    };
    record.updatedAt = record.progress.updatedAt;
    if (persist) this.save();
    else this._catalogSerializedCache = null;
    this.emit('service_progress', { id: record.id, name: record.name, ...record.progress });
  }

  // -------------------------------------------------------------------------
  // Instalación
  // -------------------------------------------------------------------------

  /**
   * Prepara el registro y lanza la instalación en segundo plano.
   *
   * Se devuelve enseguida a propósito: descargar Metabase o Stirling PDF son
   * varios cientos de megas y una petición HTTP que espera a eso muere por
   * timeout en cualquier proxy. El progreso viaja por WebSocket
   * (`service_progress`) y también queda en el registro, para que recargar la
   * página no pierda el hilo.
   */
  async install(opts = {}) {
    const tpl = this.getTemplate(String(opts.templateId || ''));

    if (!(await this.isDockerAvailable(true))) {
      throw new Error('Docker no está disponible: el catálogo de servicios lo necesita');
    }

    const domain = opts.domain ? String(opts.domain).trim().toLowerCase() : null;
    if (domain) {
      if (!DOMAIN_RE.test(domain)) {
        throw new Error(`Dominio inválido: «${domain}». Usa un nombre completo, por ejemplo n8n.midominio.com`);
      }
      if (domainManager.getByHostname(domain)) {
        throw new Error(`El dominio ${domain} ya está configurado en Culkibo`);
      }
    }

    const id = `svc_${tpl.id}_${crypto.randomBytes(4).toString('hex')}`;
    const hostPort = await this.allocatePort();

    const secrets = {};
    for (const [key, spec] of Object.entries(tpl.secrets || {})) {
      secrets[key] = generateSecret(spec);
    }

    /** @type {any} */
    const record = {
      id,
      templateId: tpl.id,
      name: String(opts.name || tpl.name).slice(0, 80),
      templateName: tpl.name,
      category: tpl.category,
      image: tpl.app.image,
      domain,
      url: domain ? `https://${domain}` : `http://127.0.0.1:${hostPort}`,
      domainId: null,
      hostPort,
      appPort: tpl.app.port,
      containerName: this.containerName(id, 'app'),
      networkName: this.networkName(id),
      volumes: Object.fromEntries((tpl.app.volumes || []).map((v) => [v.name, this.volumeName(id, v.name)])),
      sidecars: (tpl.sidecars || []).map((c) => ({
        name: c.name,
        image: c.image,
        containerName: this.containerName(id, c.name),
        volumes: Object.fromEntries((c.volumes || []).map((v) => [v.name, this.volumeName(id, `${c.name}_${v.name}`)]))
      })),
      databaseId: null,
      secretsEnc: Object.fromEntries(
        Object.entries(secrets).map(([k, v]) => [k, encryptSecret(v, this.cryptoKey)])
      ),
      memoryMb: tpl.app.memoryMb,
      cpus: tpl.app.cpus,
      status: 'installing',
      health: 'unknown',
      lastError: null,
      progress: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.state.installations.push(record);
    this.pendingPorts.delete(hostPort);
    this.setProgress(record, 'validar', `Preparando la instalación de ${tpl.name}`);

    this.inFlight.add(id);
    // Sin `await`: el llamante recibe el registro y sigue el progreso por
    // WebSocket. El `catch` está aquí y no en el llamante porque si no, un
    // fallo de instalación sería un unhandledRejection.
    this.runInstall(record, tpl, secrets)
      .catch((err) => {
        record.status = 'error';
        /** @type {Record<string, any>} */
        const redactBag = { ...secrets };
        if (record.databaseId) {
          try {
            const dbCreds = databaseManager.getCredentials(record.databaseId);
            if (dbCreds && dbCreds.password) redactBag.__db_password = dbCreds.password;
          } catch (e) {}
        }
        record.lastError = this.redact(err.message, redactBag);
        this.setProgress(record, record.progress ? record.progress.step : 'validar', `Falló: ${record.lastError}`, {
          failed: true
        });
        this.emit('service_failed', { id: record.id, name: record.name, error: record.lastError });
      })
      .finally(() => this.inFlight.delete(id));

    return this.toPublic(record);
  }

  /** Quita cualquier secreto de un mensaje antes de guardarlo o enseñarlo. */
  redact(message, secrets) {
    let out = String(message || '');
    for (const value of Object.values(secrets || {})) {
      if (value && String(value).length >= 8) out = out.split(String(value)).join('«oculto»');
    }
    return out.slice(0, 600);
  }

  async runInstall(record, tpl, secrets) {
    // --- 1. Red aislada -----------------------------------------------------
    //
    // Una red bridge por instalación, no una compartida. Es la diferencia
    // concreta con el fallo de Dokploy que documenta `databaseManager`: en una
    // red plana, un contenedor comprometido ve las bases de datos de todos los
    // demás servicios del host.
    this.setProgress(record, 'red', 'Creando la red aislada de la instalación');
    await databaseManager.ensureNetwork(record.id);

    // --- 2. Base de datos gestionada ---------------------------------------
    /** @type {any} */
    let dbContext = null;
    if (tpl.database) {
      this.setProgress(record, 'base_datos', `Aprovisionando ${tpl.database.engine}`);
      const provisioned = await databaseManager.provision({
        projectId: record.id,
        engine: tpl.database.engine,
        image: tpl.database.image || undefined,
        name: `${record.name} · datos`,
        dbName: tpl.database.dbName,
        username: tpl.database.username || 'culkibo',
        memoryMb: tpl.database.memoryMb || 512,
        cpus: tpl.database.cpus || 1
      });
      record.databaseId = provisioned.id;
      this.save();

      const creds = databaseManager.getCredentials(provisioned.id);
      // El host es el alias corto de la red (`postgres`, `mysql`, `valkey`),
      // que `databaseManager` asigna con `--network-alias`. Es más estable que
      // el nombre del contenedor y hace legibles las variables de entorno.
      const alias = tpl.database.engine;
      dbContext = {
        host: alias,
        port: creds.port,
        user: creds.username,
        password: creds.password,
        name: creds.dbName || '',
        url: databaseManager.buildConnectionString(
          databaseManager.get(provisioned.id),
          creds.password,
          { host: alias }
        )
      };
    }

    const context = {
      installId: record.id,
      domain: record.domain,
      url: record.url,
      secrets,
      db: dbContext,
      sidecarHosts: Object.fromEntries(record.sidecars.map((c) => [c.name, c.containerName]))
    };

    // --- 3. Auxiliares ------------------------------------------------------
    if (record.sidecars.length > 0) {
      this.setProgress(record, 'auxiliares', `Levantando ${record.sidecars.length} servicio(s) auxiliar(es)`);
      for (const spec of tpl.sidecars) {
        const stored = record.sidecars.find((c) => c.name === spec.name);
        await this.pullImage(spec.image);
        await this.runContainer({
          containerName: stored.containerName,
          image: spec.image,
          networkName: record.networkName,
          networkAlias: spec.name,
          env: resolveEnv(spec.env, context),
          volumes: (spec.volumes || []).map((v) => `${stored.volumes[v.name]}:${v.path}`),
          files: this.materialiseFiles(record.id, spec.name, spec.files || []),
          memoryMb: spec.memoryMb,
          cpus: spec.cpus,
          command: spec.command || null,
          publish: null,
          labels: { 'culkibo.service': record.id, 'culkibo.role': spec.name }
        });
      }
    }

    // --- 4. Imagen principal ------------------------------------------------
    //
    // El `pull` es un paso propio y no parte del `run` porque es el que tarda:
    // sin separarlo, el panel se queda tres minutos en «arrancando» sin que
    // nada esté arrancando todavía.
    this.setProgress(record, 'descarga', `Descargando ${tpl.app.image}`);
    await this.pullImage(tpl.app.image);

    // --- 5. Contenedor principal -------------------------------------------
    this.setProgress(record, 'arranque', 'Arrancando el contenedor');
    const containerId = await this.runContainer({
      containerName: record.containerName,
      image: tpl.app.image,
      networkName: record.networkName,
      networkAlias: 'app',
      env: resolveEnv(tpl.app.env, context),
      volumes: (tpl.app.volumes || []).map((v) => `${record.volumes[v.name]}:${v.path}`),
      files: this.materialiseFiles(record.id, 'app', tpl.app.files || []),
      memoryMb: record.memoryMb,
      cpus: record.cpus,
      command: tpl.app.command || null,
      // Sólo bucle local. Ver el comentario de cabecera.
      publish: `127.0.0.1:${record.hostPort}:${tpl.app.port}`,
      labels: { 'culkibo.service': record.id, 'culkibo.role': 'app' }
    });
    record.containerId = containerId;
    record.status = 'running';
    this.save();

    // --- 6. Dominio ---------------------------------------------------------
    if (record.domain) {
      this.setProgress(record, 'dominio', `Publicando ${record.domain} con HTTPS`);
      const created = await domainManager.addDomain({
        hostname: record.domain,
        // `targetPod: 'service'` es lo que hace que `ingressManager` sepa que
        // detrás no hay un pod sino un servicio del catálogo, y etiquete la
        // ruta con su nombre en vez de con «Desarrollo».
        targetPod: 'service',
        targetPort: record.hostPort,
        cloudflareProxied: false,
        routingMode: 'direct_dns'
      });
      record.domainId = created.id;
      await domainManager.updateDomain(created.id, { serviceId: record.id, serviceName: record.name });
      this.save();
      // Reconciliar publica la ruta en Caddy. Nunca lanza: si no hay plano de
      // datos, el servicio queda instalado y accesible en bucle local, y el
      // panel lo dice.
      const ingress = await ingressManager.reconcile();
      record.ingress = {
        applied: Boolean(ingress && ingress.applied),
        reason: ingress && ingress.reason ? ingress.reason : null
      };
      this.save();
    }

    // --- 7. Sonda -----------------------------------------------------------
    const readiness = tpl.app.readiness;
    this.setProgress(record, 'sonda', 'Esperando a que el servicio responda');
    const probe = await this.waitUntilReady(record, readiness);
    record.health = probe.healthy ? 'healthy' : 'unhealthy';
    record.lastProbe = probe;
    record.status = probe.healthy ? 'running' : 'degraded';
    if (!probe.healthy) {
      record.lastError =
        `El contenedor arrancó pero no respondió a tiempo en ${readiness.path} ` +
        `(último resultado: ${probe.detail}). Revisa los registros.`;
    }
    this.save();

    this.setProgress(
      record,
      'listo',
      probe.healthy
        ? `${record.name} está en marcha en ${record.url}`
        : `${record.name} arrancó, pero todavía no responde. Revisa los registros.`,
      { healthy: probe.healthy }
    );
    this.emit('service_installed', this.toPublic(record));
  }

  /**
   * Escribe en disco los ficheros de configuración de una plantilla y devuelve
   * los montajes que hay que pasar a `docker run`.
   *
   * Sólo de lectura dentro del contenedor (`:ro`): son configuración nuestra,
   * no datos del servicio, y un contenedor que pueda reescribirlos rompe la
   * reproducibilidad de la instalación en el primer reinicio.
   */
  materialiseFiles(installId, role, files) {
    if (!files || files.length === 0) return [];
    const dir = path.join(FILES_ROOT, installId, role);
    fs.mkdirSync(dir, { recursive: true });
    return files.map((file) => {
      const hostPath = path.join(dir, file.name);
      fs.writeFileSync(hostPath, file.content, { encoding: 'utf8', mode: 0o644 });
      // Docker quiere barras normales incluso cuando el daemon corre en
      // Windows contra un motor Linux.
      return `${hostPath.split(path.sep).join('/')}:${file.path}:ro`;
    });
  }

  async pullImage(image) {
    // 15 minutos: Metabase y Stirling PDF pasan del medio giga y hay VPS con
    // 20 Mbit de bajada.
    await this.docker(['pull', image], { timeout: 900000 });
  }

  /**
   * Un `docker run` con todas las protecciones puestas.
   *
   * Los secretos van por `--env-file` con permisos 0600 y nunca por
   * `-e CLAVE=valor`, que dejaría el valor en el argv del proceso `docker` del
   * host y lo haría legible con `ps` para cualquier usuario de la máquina. Es
   * la misma decisión que documenta `databaseManager.provision()`.
   */
  async runContainer(spec) {
    const envFile = path.join(TMP_DIR, `svcenv_${crypto.randomBytes(8).toString('hex')}`);

    const args = [
      'run', '-d',
      '--name', spec.containerName,
      '--restart', 'unless-stopped',
      '--network', spec.networkName,
      '--network-alias', spec.networkAlias,
      '--env-file', envFile,
      '--memory', `${spec.memoryMb}m`,
      // Igualar memory-swap a memory desactiva el swap. Sin esto el límite no
      // limita: sólo empuja el contenedor al disco y degrada el host entero.
      '--memory-swap', `${spec.memoryMb}m`,
      '--cpus', String(spec.cpus),
      '--pids-limit', '1024',
      '--security-opt', 'no-new-privileges',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${spec.labels['culkibo.service']}`
    ];

    for (const [key, value] of Object.entries(spec.labels)) {
      args.push('--label', `${key}=${value}`);
    }
    for (const volume of spec.volumes) args.push('-v', volume);
    for (const file of spec.files) args.push('-v', file);
    if (spec.publish) args.push('-p', spec.publish);

    args.push(spec.image);
    if (spec.command) args.push(...spec.command);

    try {
      fs.writeFileSync(
        envFile,
        Object.entries(spec.env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n',
        { encoding: 'utf8', mode: 0o600 }
      );
      const { stdout } = await this.docker(args, { timeout: 180000 });
      return stdout.trim().slice(0, 64);
    } finally {
      // El fichero con los secretos vive lo que tarda docker en leerlo.
      try { fs.unlinkSync(envFile); } catch (e) {}
    }
  }

  // -------------------------------------------------------------------------
  // Sonda de disponibilidad
  // -------------------------------------------------------------------------

  /**
   * Una petición HTTP contra el puerto publicado.
   *
   * `redirect: 'manual'` para que un 302 cuente como 302 y no se siga hasta un
   * destino que puede estar fuera del host. Muchos servicios recién instalados
   * redirigen a su asistente inicial, y eso es exactamente «está sano».
   */
  async probeOnce(hostPort, readiness) {
    const url = `http://127.0.0.1:${hostPort}${readiness.path}`;
    try {
      const res = await fetch(url, {
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
        headers: { 'User-Agent': 'Culkibo/1.0 (sonda de disponibilidad)' }
      });
      return {
        healthy: readiness.expect.includes(res.status),
        status: res.status,
        detail: `HTTP ${res.status}`
      };
    } catch (err) {
      return { healthy: false, status: null, detail: err.name === 'TimeoutError' ? 'sin respuesta en 5 s' : err.message };
    }
  }

  async waitUntilReady(record, readiness) {
    const deadline = Date.now() + (readiness.timeoutMs || DEFAULT_READY_TIMEOUT_MS);
    let last = { healthy: false, detail: 'sin intentar' };
    let attempt = 0;

    while (Date.now() < deadline) {
      attempt++;
      last = await this.probeOnce(record.hostPort, readiness);
      if (last.healthy) {
        return { ...last, attempts: attempt, checkedAt: new Date().toISOString() };
      }
      // Emitir progreso por WebSocket sin saturar el disco con save() en cada sondeo.
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      this.setProgress(
        record,
        'sonda',
        `Esperando respuesta en ${readiness.path} (${last.detail}); quedan ${left} s`,
        { attempts: attempt },
        { persist: attempt === 1 || attempt % 5 === 0 }
      );
      const delay = attempt <= 2 ? 400 : attempt <= 5 ? 800 : 1500;
      await new Promise((r) => setTimeout(r, delay));
    }

    return { ...last, attempts: attempt, checkedAt: new Date().toISOString() };
  }

  /** Vuelve a sondear un servicio ya instalado y actualiza su estado. */
  async refreshHealth(id) {
    const record = this.mustGet(id);
    const tpl = this.getTemplate(record.templateId);
    const probe = await this.probeOnce(record.hostPort, tpl.app.readiness);
    record.health = probe.healthy ? 'healthy' : 'unhealthy';
    record.lastProbe = { ...probe, attempts: 1, checkedAt: new Date().toISOString() };
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  // -------------------------------------------------------------------------
  // Ciclo de vida
  // -------------------------------------------------------------------------

  mustGet(id) {
    assertInstallId(id);
    const record = this.state.installations.find((i) => i.id === id);
    if (!record) throw new Error(`La instalación ${id} no existe`);
    return record;
  }

  allContainerNames(record) {
    return [record.containerName, ...record.sidecars.map((c) => c.containerName)];
  }

  async start(id) {
    const record = this.mustGet(id);
    // Los auxiliares primero: la aplicación suele morir si su ClickHouse o su
    // base de datos todavía no están escuchando.
    if (record.databaseId) {
      try { await databaseManager.start(record.databaseId); } catch (e) {}
    }
    for (const car of record.sidecars) {
      await this.docker(['start', car.containerName], { timeout: 60000 });
    }
    await this.docker(['start', record.containerName], { timeout: 60000 });
    record.status = 'running';
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  async stop(id) {
    const record = this.mustGet(id);
    await this.docker(['stop', record.containerName], { timeout: 90000 });
    for (const car of record.sidecars) {
      try { await this.docker(['stop', car.containerName], { timeout: 90000 }); } catch (e) {}
    }
    record.status = 'stopped';
    record.health = 'unknown';
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  async restart(id) {
    await this.stop(id);
    return this.start(id);
  }

  async logs(id, { lines = 200 } = {}) {
    const record = this.mustGet(id);
    const count = Math.max(1, Math.min(2000, parseInt(String(lines), 10) || 200));
    const { stdout, stderr } = await this.docker(
      ['logs', '--tail', String(count), record.containerName],
      { timeout: 20000 }
    );
    // Docker manda a stderr todo lo que el proceso escribió en su stderr, que
    // en la mayoría de estas imágenes es el registro entero. Se unen los dos.
    const secrets = this.decryptSecrets(record);
    if (record.databaseId) {
      try {
        const dbCreds = databaseManager.getCredentials(record.databaseId);
        if (dbCreds && dbCreds.password) secrets.__db_password = dbCreds.password;
      } catch (e) {}
    }
    return {
      id: record.id,
      containerName: record.containerName,
      output: this.redact(`${stdout}${stderr}`, secrets)
    };
  }

  /**
   * Desinstala.
   *
   * Los volúmenes NO se borran por defecto, y tampoco la base de datos. Borrar
   * datos sin que se pidan explícitamente es la clase de comportamiento que
   * hace que nadie vuelva a instalar tu software.
   */
  async remove(id, { deleteVolumes = false } = {}) {
    const record = this.mustGet(id);
    const removed = {
      containers: /** @type {string[]} */ ([]),
      volumes: /** @type {string[]} */ ([]),
      network: /** @type {string | null} */ (null),
      database: /** @type {string | null} */ (null),
      domain: /** @type {string | null} */ (null)
    };

    if (await this.isDockerAvailable()) {
      for (const name of this.allContainerNames(record)) {
        try {
          await this.docker(['rm', '-f', name], { timeout: 90000 });
          removed.containers.push(name);
        } catch (e) {}
      }
    }

    if (record.databaseId) {
      try {
        await databaseManager.remove(record.databaseId, { deleteVolume: deleteVolumes, deleteBackups: deleteVolumes });
        removed.database = record.databaseId;
      } catch (e) {}
    }

    if (deleteVolumes && (await this.isDockerAvailable())) {
      const volumes = [
        ...Object.values(record.volumes),
        ...record.sidecars.flatMap((c) => Object.values(c.volumes))
      ];
      for (const volume of volumes) {
        try {
          await this.docker(['volume', 'rm', volume], { timeout: 30000 });
          removed.volumes.push(volume);
        } catch (e) {}
      }
      try { fs.rmSync(path.join(FILES_ROOT, record.id), { recursive: true, force: true }); } catch (e) {}
    }

    // La red se va siempre: sin contenedores dentro no sirve de nada y dejarla
    // acumula una interfaz bridge por instalación borrada.
    if (await this.isDockerAvailable()) {
      try {
        await this.docker(['network', 'rm', record.networkName], { timeout: 20000 });
        removed.network = record.networkName;
      } catch (e) {}
    }

    if (record.domainId) {
      try {
        await domainManager.deleteDomain(record.domainId);
        removed.domain = record.domain;
      } catch (e) {}
      try { await ingressManager.reconcile(); } catch (e) {}
    }

    this.state.installations = this.state.installations.filter((i) => i.id !== id);
    this.save();
    this.emit('service_removed', { id, name: record.name, volumesDeleted: deleteVolumes });

    return { success: true, id, volumesDeleted: deleteVolumes, ...removed };
  }

  // -------------------------------------------------------------------------
  // Proyección
  // -------------------------------------------------------------------------

  decryptSecrets(record) {
    const out = {};
    for (const [key, blob] of Object.entries(record.secretsEnc || {})) {
      try { out[key] = decryptSecret(blob, this.cryptoKey); } catch (e) {}
    }
    return out;
  }

  /**
   * Proyección pública. Nunca lleva secretos: para eso está `/secrets`, que es
   * un endpoint aparte y deliberadamente incómodo de llamar por accidente.
   */
  toPublic(record) {
    const tpl = TEMPLATE_MAP.get(record.templateId);
    return {
      id: record.id,
      templateId: record.templateId,
      templateName: record.templateName || (tpl ? tpl.name : record.templateId),
      name: record.name,
      category: record.category,
      categoryLabel: CATEGORY_MAP.get(record.category) || record.category,
      image: record.image,
      domain: record.domain,
      url: record.url,
      hostPort: record.hostPort,
      appPort: record.appPort,
      containerName: record.containerName,
      networkName: record.networkName,
      sidecars: record.sidecars.map((c) => ({ name: c.name, image: c.image, containerName: c.containerName })),
      databaseId: record.databaseId,
      memoryMb: record.memoryMb,
      cpus: record.cpus,
      status: record.status,
      health: record.health,
      progress: record.progress,
      ingress: record.ingress || null,
      lastProbe: record.lastProbe || null,
      lastError: record.lastError || null,
      secretNames: Object.keys(record.secretsEnc || {}),
      nextSteps: tpl ? (tpl.nextSteps || []).map((s) => s.split('{{url}}').join(record.url)) : [],
      notes: tpl ? tpl.notes || [] : [],
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };
  }

  list() {
    return this.state.installations.map((i) => this.toPublic(i));
  }

  get(id) {
    return this.toPublic(this.mustGet(id));
  }

  /**
   * Único punto que devuelve los secretos en claro. Igual que
   * `databaseManager.getCredentials`: endpoint propio, para que ni una captura
   * del panel ni un `curl /api/catalog/installations` los filtren.
   */
  getSecrets(id) {
    const record = this.mustGet(id);
    /** @type {any} */
    const out = { id: record.id, name: record.name, secrets: this.decryptSecrets(record), database: null };
    if (record.databaseId) {
      try { out.database = databaseManager.getCredentials(record.databaseId); } catch (e) {}
    }
    return out;
  }

  /** Problemas de formato del catálogo. Vacío significa catálogo sano. */
  selfCheck() {
    return validateCatalog();
  }
}

const catalogManager = Object.assign(new CatalogManager(), {
  CatalogManager,
  resolvePlaceholders,
  resolveEnv,
  generateSecret,
  STEPS,
  PORT_RANGE: { start: PORT_RANGE_START, end: PORT_RANGE_END }
});

module.exports = catalogManager;
