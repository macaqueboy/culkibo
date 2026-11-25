const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const EventEmitter = require('events');

const { atomicWriteJsonSync, formatDockerEnvFile } = require('./ssrfGuard');
const {
  TEMPLATES,
  CATEGORIES,
  validateCatalog,
  IMAGE_RE,
  FLOATING_TAG_RE,
  FILE_NAME_RE,
  SHM_SIZE_RE
} = require('./catalog/templates');
const portRegistry = require('./portRegistry');

// Carga perezosa: GET /api/catalog solo necesita las plantillas y nunca debe
// arrastrar databaseManager/domainManager/ingressManager en el arranque en frío.
/** @type {any} */
let _dbManager = null;
function getDbManager() {
  if (!_dbManager) _dbManager = require('./databaseManager');
  return _dbManager;
}
/** @type {any} */
let _domainManager = null;
function getDomainManager() {
  if (!_domainManager) _domainManager = require('./domainManager');
  return _domainManager;
}
/** @type {any} */
let _ingressManager = null;
function getIngressManager() {
  if (!_ingressManager) _ingressManager = require('./ingressManager');
  return _ingressManager;
}

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

const DATA_DIR_DEFAULT = path.join(__dirname, '..', '..', 'data');
const BACKUP_IMAGE = 'alpine:3.21.3';
const BACKUP_ID_RE = /^vbk_[0-9a-zA-Z_-]{6,64}$/;
const TZ_RE = /^[A-Za-z0-9_\/+\-]{1,64}$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,120}$/;

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
// Validación y helpers puros
// ---------------------------------------------------------------------------

const INSTALL_ID_RE = /^svc_[a-z0-9-]{2,32}_[0-9a-f]{8}$/;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/;

function assertInstallId(id) {
  if (!INSTALL_ID_RE.test(String(id || ''))) throw new Error('Identificador de instalación inválido');
  return String(id);
}

/** Zona horaria efectiva del servidor (nunca fija un país concreto a menos que el entorno lo pida). */
function defaultTimezone() {
  const envTz = String(process.env.TZ || '').trim();
  if (envTz && TZ_RE.test(envTz)) return envTz;
  try {
    const intlTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (intlTz && TZ_RE.test(intlTz)) return intlTz;
  } catch (e) {}
  return 'UTC';
}

/** Separa repositorio y etiqueta de una referencia OCI (soporta registros con puerto como `localhost:5000/img:1.0`). */
function parseImageRef(image) {
  const raw = String(image || '').trim();
  const lastColon = raw.lastIndexOf(':');
  const lastSlash = raw.lastIndexOf('/');
  if (lastColon <= lastSlash || lastColon === -1) return { repo: raw, tag: '' };
  return { repo: raw.slice(0, lastColon), tag: raw.slice(lastColon + 1) };
}

/** Calcula la imagen destino de un auxiliar acoplado cuando se actualiza la imagen principal. */
function resolveCoupledSidecarImage(spec, currentSidecarImage, newAppImage) {
  if (spec && spec.coupledTagOnly) {
    const { repo } = parseImageRef(spec.image || currentSidecarImage);
    const { tag } = parseImageRef(newAppImage);
    return `${repo}:${tag}`;
  }
  return newAppImage;
}

/**
 * Ordena topológicamente los auxiliares respetando `dependsOn` y separa los
 * que arrancan antes de `app` (`preApp`) de los workers que esperan a que
 * `app` migre el esquema y pase salud (`postApp`).
 * @param {any[]} sidecars
 */
function orderSidecars(sidecars = []) {
  const list = Array.isArray(sidecars) ? sidecars : [];
  const byName = new Map(list.map((c) => [c.name, c]));
  /** @type {any[]} */
  const ordered = [];
  /** @type {Map<string, number>} */
  const state = new Map();

  const visit = (car) => {
    const st = state.get(car.name);
    if (st === 2) return;
    if (st === 1) throw new Error(`Dependencia circular entre auxiliares: «${car.name}»`);
    state.set(car.name, 1);
    for (const depName of car.dependsOn || []) {
      const dep = byName.get(depName);
      if (!dep) throw new Error(`El auxiliar «${car.name}» depende de «${depName}», que no existe`);
      visit(dep);
    }
    state.set(car.name, 2);
    ordered.push(car);
  };

  for (const car of list) visit(car);

  return {
    ordered,
    preApp: ordered.filter((c) => !c.startAfterApp),
    postApp: ordered.filter((c) => Boolean(c.startAfterApp))
  };
}

/**
 * Valida un mapa de variables de entorno personalizadas.
 * @param {Record<string, any>} overrides
 * @param {{ allowDelete?: boolean }} [opts]
 */
function validateEnvOverrides(overrides, { allowDelete = true } = {}) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new Error('Debes indicar un objeto de variables de entorno');
  }
  /** @type {Array<[string, string | null]>} */
  const entries = [];
  for (const [rawKey, rawVal] of Object.entries(overrides)) {
    const k = String(rawKey || '').trim();
    if (!ENV_KEY_RE.test(k)) {
      throw new Error(`Nombre de variable inválido: «${k}»`);
    }
    if (rawVal === null || rawVal === undefined) {
      if (allowDelete) entries.push([k, null]);
      continue;
    }
    const val = String(rawVal);
    if (/[\r\n\0]/.test(val)) {
      throw new Error(`La variable ${k} no puede contener saltos de línea ni bytes nulos`);
    }
    entries.push([k, val]);
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Cifrado en reposo
// ---------------------------------------------------------------------------

/**
 * Misma construcción que `databaseManager`, con su propia clave y su propio
 * fichero. Separar las claves significa que filtrar `services.json` no expone
 * las contraseñas de las bases de datos, y al revés.
 */
function loadOrCreateKey(keyFile, dataFile) {
  if (fs.existsSync(keyFile)) {
    const raw = fs.readFileSync(keyFile, 'utf8').trim();
    const key = Buffer.from(raw, 'hex');
    if (key.length !== 32) {
      throw new Error(`Clave de cifrado ${keyFile} corrupta (longitud inválida). No se sobrescribe para evitar pérdida de secretos.`);
    }
    return key;
  }
  // Defensa anti-pérdida: nunca generar clave nueva si ya existen secretos cifrados en services.json
  if (fs.existsSync(dataFile)) {
    try {
      const storeRaw = fs.readFileSync(dataFile, 'utf8');
      if (/"v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+"/.test(storeRaw)) {
        throw new Error(`Falta ${keyFile} pero ${dataFile} contiene secretos cifrados. Restaura la clave antes de continuar.`);
      }
    } catch (err) {
      if (/Falta /.test(err.message)) throw err;
    }
  }
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  try {
    fs.writeFileSync(keyFile, key.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  } catch (err) {
    if (err && err.code === 'EEXIST') {
      const existing = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
      if (existing.length === 32) return existing;
    }
    throw err;
  }
  try { fs.chmodSync(keyFile, 0o600); } catch (e) {}
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

    if (expr === 'domain') return context.domain || (context.hostPort ? `127.0.0.1:${context.hostPort}` : 'localhost');
    if (expr === 'host') return context.domain || '127.0.0.1';
    if (expr === 'protocol') return context.domain ? 'https' : 'http';
    if (expr === 'wsProtocol') return context.domain ? 'wss' : 'ws';
    if (expr === 'isHttps') return context.domain ? 'true' : 'false';
    if (expr === 'url') return context.url || '';
    if (expr === 'tz') return context.tz || defaultTimezone();
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
  /** @param {{ dataDir?: string | null, registerPorts?: boolean }} [options] */
  constructor(options = {}) {
    super();
    this.dataDir = options.dataDir ? path.resolve(options.dataDir) : DATA_DIR_DEFAULT;
    this.dataFile = path.join(this.dataDir, 'services.json');
    this.keyFile = path.join(this.dataDir, '.services.key');
    this.filesRoot = path.join(this.dataDir, 'services');
    this.backupsRoot = path.join(this.dataDir, 'service-backups');
    this.tmpDir = path.join(this.dataDir, '.tmp');
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
    /** @type {boolean | null} */
    this._swapLimitSupported = null;
    this.ensureDirs();
    this.load();
    if (options.registerPorts !== false) {
      portRegistry.registerProvider('catalogManager', () => this.allAllocatedPorts());
    }
  }

  ensureDirs() {
    for (const dir of [this.dataDir, this.filesRoot, this.backupsRoot, this.tmpDir]) {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    }
  }

  get cryptoKey() {
    if (!this.key) this.key = loadOrCreateKey(this.keyFile, this.dataFile);
    return this.key;
  }

  load() {
    try {
      if (fs.existsSync(this.dataFile)) {
        const parsed = JSON.parse(fs.readFileSync(this.dataFile, 'utf8'));
        if (parsed && Array.isArray(parsed.installations)) {
          this.state = {
            version: 1,
            installations: parsed.installations.map((i) => ({
              sidecars: [],
              volumes: {},
              secretsEnc: {},
              extraPorts: {},
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
      atomicWriteJsonSync(this.dataFile, this.state, 0o600);
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
    return getDbManager().docker(args, options);
  }

  isDockerAvailable(force) {
    return getDbManager().isDockerAvailable(force);
  }

  // -------------------------------------------------------------------------
  // Nombres y puertos
  // -------------------------------------------------------------------------

  containerName(installId, role = 'app') { return `culkibo_svc_${installId.slice(4)}_${role}`; }
  volumeName(installId, key) { return `culkibo_svcdata_${installId.slice(4)}_${key}`; }
  networkName(installId) { return `culkibo_net_${installId}`; }

  /** Todos los puertos reservados por todas las instalaciones (principal + `extraPorts`). */
  allAllocatedPorts() {
    /** @type {number[]} */
    const out = [];
    for (const i of this.state.installations) {
      if (!i) continue;
      if (i.hostPort) out.push(i.hostPort);
      for (const ep of Object.values(i.extraPorts || {})) {
        if (ep) out.push(Number(ep));
      }
    }
    return out;
  }

  /** Puertos que este registro ya tiene reservados (principal + `extraPorts`). */
  reservedPorts() {
    return new Set(this.allAllocatedPorts());
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

  async allocatePort(owner = `cat_${Date.now()}`) {
    const port = await portRegistry.allocate({
      kind: 'catalog',
      owner,
      start: PORT_RANGE_START,
      end: PORT_RANGE_END,
      extraExcluded: new Set([...this.pendingPorts, ...this.allAllocatedPorts()])
    });
    this.pendingPorts.add(port);
    return port;
  }

  /** Libera un puerto reservado previamente con `allocatePort` (útil en rollbacks y pruebas). */
  releasePort(port, owner = null) {
    this.pendingPorts.delete(port);
    portRegistry.release(port, owner);
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
    this.emit('service_progress', {
      id: record.id,
      name: record.name,
      status: record.status,
      ...record.progress,
      progress: record.progress
    });
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

    // Validar overrides de entorno y zona horaria ANTES de reservar puertos o tocar Docker
    /** @type {Array<[string, string | null]>} */
    let initialEnvEntries = [];
    if (opts.env !== undefined && opts.env !== null) {
      initialEnvEntries = validateEnvOverrides(opts.env, { allowDelete: false });
    }
    let tz = defaultTimezone();
    if (opts.tz !== undefined && opts.tz !== null && String(opts.tz).trim()) {
      const rawTz = String(opts.tz).trim();
      if (!TZ_RE.test(rawTz)) throw new Error(`Zona horaria inválida: «${rawTz}»`);
      tz = rawTz;
    }

    if (!(await this.isDockerAvailable(true))) {
      throw new Error('Docker no está disponible: el catálogo de servicios lo necesita');
    }

    const domain = opts.domain ? String(opts.domain).trim().toLowerCase() : null;
    if (domain) {
      if (!DOMAIN_RE.test(domain)) {
        throw new Error(`Dominio inválido: «${domain}». Usa un nombre completo, por ejemplo n8n.midominio.com`);
      }
      if (getDomainManager().getByHostname(domain)) {
        throw new Error(`El dominio ${domain} ya está configurado en Culkibo`);
      }
    }

    const id = `svc_${tpl.id}_${crypto.randomBytes(4).toString('hex')}`;
    const hostPort = await this.allocatePort(id);

    /** @type {any} */
    let record;
    const secrets = {};
    try {
      for (const [key, spec] of Object.entries(tpl.secrets || {})) {
        secrets[key] = generateSecret(spec);
      }

      /** @type {Record<string, string>} */
      const customEnvEnc = {};
      for (const [k, v] of initialEnvEntries) {
        if (v !== null) customEnvEnc[k] = encryptSecret(v, this.cryptoKey);
      }

      record = {
        id,
        templateId: tpl.id,
        name: String(opts.name || tpl.name).slice(0, 80),
        templateName: tpl.name,
        category: tpl.category,
        image: tpl.app.image,
        domain,
        url: domain ? `https://${domain}` : `http://127.0.0.1:${hostPort}`,
        tz,
        domainId: null,
        hostPort,
        appPort: tpl.app.port,
        extraPorts: {},
        containerName: this.containerName(id, 'app'),
        networkName: this.networkName(id),
        volumes: Object.fromEntries((tpl.app.volumes || []).map((v) => [v.name, this.volumeName(id, v.name)])),
        sidecars: (tpl.sidecars || []).map((c) => ({
          name: c.name,
          image: c.image,
          containerName: this.containerName(id, c.name),
          startAfterApp: Boolean(c.startAfterApp),
          coupledWithApp: Boolean(c.coupledWithApp),
          coupledTagOnly: Boolean(c.coupledTagOnly),
          volumes: Object.fromEntries((c.volumes || []).map((v) => [v.name, this.volumeName(id, `${c.name}_${v.name}`)]))
        })),
        databaseId: null,
        secretsEnc: Object.fromEntries(
          Object.entries(secrets).map(([k, v]) => [k, encryptSecret(v, this.cryptoKey)])
        ),
        customEnvEnc,
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
    } finally {
      this.pendingPorts.delete(hostPort);
      portRegistry.release(hostPort, id);
    }
    this.setProgress(record, 'validar', `Preparando la instalación de ${tpl.name}`);

    this.inFlight.add(id);
    this.runInstall(record, tpl, secrets)
      .catch((err) => {
        record.status = 'error';
        /** @type {Record<string, any>} */
        const redactBag = { ...secrets, ...this.decryptCustomEnv(record) };
        if (record.databaseId) {
          try {
            const dbCreds = getDbManager().getCredentials(record.databaseId);
            if (dbCreds && dbCreds.password) redactBag.__db_password = dbCreds.password;
          } catch (e) {}
        }
        record.lastError = this.redact(err.message, redactBag);
        this.setProgress(record, record.progress ? record.progress.step : 'validar', `Falló: ${record.lastError}`, {
          failed: true
        });
        this.emit('service_failed', { id: record.id, name: record.name, error: record.lastError });
        try {
          const ts = require('./telemetryService');
          ts.recordFeatureUsage(`catalog:${record.templateId}`, false);
          ts.captureOperationFailure({
            operation: 'catalog_install',
            stage: record.progress ? record.progress.step : 'install',
            kind: record.templateId,
            message: record.lastError
          });
        } catch (e) {}
      })
      .finally(() => this.inFlight.delete(id));

    return this.toPublic(record);
  }

  /**
   * Quita cualquier secreto de un mensaje antes de guardarlo o enseñarlo.
   * @param {string} message
   * @param {Record<string, any>} secrets
   * @param {number | null} [maxLength]
   */
  redact(message, secrets, maxLength = 600) {
    let out = String(message || '');
    for (const value of Object.values(secrets || {})) {
      if (value && String(value).length >= 8) out = out.split(String(value)).join('«oculto»');
    }
    return maxLength === null || maxLength === Infinity ? out : out.slice(0, maxLength);
  }

  /**
   * Espera a que la base de datos gestionada alcance `healthy` y falla de forma
   * explícita si vence el tiempo límite (nunca continúa a ciegas).
   */
  async waitDbReady(databaseId, timeoutMs = 90000) {
    const databaseManager = getDbManager();
    const budget = Math.max(1000, Number(timeoutMs) || 90000);
    const deadline = Date.now() + budget;
    let lastHealth = 'unknown';
    while (Date.now() < deadline) {
      try {
        const st = await databaseManager.refreshHealth(databaseId);
        if (st && st.health) lastHealth = st.health;
        if (lastHealth === 'healthy') return;
      } catch (e) {
        lastHealth = e.message || 'error';
      }
      await new Promise((r) => setTimeout(r, Math.min(1500, Math.max(50, deadline - Date.now()))));
    }
    throw new Error(`La base de datos ${databaseId} no alcanzó estado saludable en ${Math.round(budget / 1000)} s (último estado: ${lastHealth})`);
  }

  /**
   * Arranca y verifica un auxiliar concreto (usado en arranque por fases pre/post-app).
   * @param {any} record
   * @param {any} spec
   * @param {any} context
   * @param {Record<string, string>} customEnv
   */
  async startSingleSidecarForInstall(record, spec, context, customEnv) {
    const stored = record.sidecars.find((c) => c.name === spec.name);
    if (!stored) return;
    await this.pullImage(spec.image);
    const sidecarEnv = spec.coupledWithApp
      ? { ...resolveEnv(spec.env, context), ...customEnv }
      : resolveEnv(spec.env, context);
    await this.runContainer({
      containerName: stored.containerName,
      image: spec.image,
      networkName: record.networkName,
      networkAlias: spec.name,
      env: sidecarEnv,
      volumes: (spec.volumes || []).map((v) => `${stored.volumes[v.name]}:${v.path}`),
      files: this.materialiseFiles(record.id, spec.name, spec.files || []),
      memoryMb: spec.memoryMb,
      cpus: spec.cpus,
      command: spec.command || null,
      publish: null,
      labels: { 'culkibo.service': record.id, 'culkibo.role': spec.name }
    });
    await this.waitSidecarReady(stored.containerName, spec.readiness || null);
  }

  async runInstall(record, tpl, secrets) {
    // --- 1. Red aislada -----------------------------------------------------
    //
    // Una red bridge por instalación, no una compartida. Es la diferencia
    // concreta con el fallo de Dokploy que documenta `databaseManager`: en una
    // red plana, un contenedor comprometido ve las bases de datos de todos los
    // demás servicios del host.
    this.setProgress(record, 'red', 'Creando la red aislada de la instalación');
    const databaseManager = getDbManager();
    await databaseManager.ensureNetwork(record.id);

    // --- 2. Base de datos gestionada ---------------------------------------
    /** @type {any} */
    let dbContext = null;
    if (tpl.database) {
      const dbImage = tpl.database.image ? String(tpl.database.image).trim() : undefined;
      if (dbImage && (!IMAGE_RE.test(dbImage) || FLOATING_TAG_RE.test(dbImage))) {
        throw new Error(`Imagen de base de datos inválida o móvil en «${tpl.id}»: ${dbImage}`);
      }
      this.setProgress(
        record,
        'base_datos',
        dbImage ? `Aprovisionando ${tpl.database.engine} (${dbImage})` : `Aprovisionando ${tpl.database.engine}`
      );
      const provisioned = await databaseManager.provision({
        projectId: record.id,
        engine: tpl.database.engine,
        image: dbImage,
        name: `${record.name} · datos`,
        dbName: tpl.database.dbName,
        username: tpl.database.username || 'culkibo',
        memoryMb: tpl.database.memoryMb || 512,
        cpus: tpl.database.cpus || 1
      });
      record.databaseId = provisioned.id;
      record.databaseImage = dbImage || provisioned.image || null;
      this.save();

      // Fail-fast: esperar a que la BD esté realmente saludable antes de arrancar auxiliares/app
      await this.waitDbReady(provisioned.id, tpl.database.readyTimeoutMs || 90000);

      const creds = databaseManager.getCredentials(provisioned.id);
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
      hostPort: record.hostPort,
      url: record.url,
      tz: record.tz || defaultTimezone(),
      secrets,
      db: dbContext,
      sidecarHosts: Object.fromEntries(record.sidecars.map((c) => [c.name, c.containerName]))
    };
    const customEnv = this.decryptCustomEnv(record);
    const { preApp, postApp } = orderSidecars(tpl.sidecars || []);

    // --- 3. Auxiliares previos a la app (en orden topológico y esperando salud uno a uno) ---
    if (preApp.length > 0) {
      this.setProgress(record, 'auxiliares', `Levantando ${preApp.length} servicio(s) auxiliar(es) previos`);
      for (const spec of preApp) {
        await this.startSingleSidecarForInstall(record, spec, context, customEnv);
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
    /** @type {string[]} */
    const extraPublishes = [];
    if (Array.isArray(tpl.app.extraPorts) && tpl.app.extraPorts.length > 0) {
      record.extraPorts = record.extraPorts || {};
      for (const ep of tpl.app.extraPorts) {
        const cPort = Number(ep.containerPort);
        if (!Number.isInteger(cPort) || cPort <= 0 || cPort >= 65536) continue;
        let hPort = record.extraPorts[String(cPort)];
        if (!hPort) {
          const epOwner = `svc_ep_${record.id}_${cPort}`;
          hPort = await portRegistry.allocate({
            kind: 'catalog',
            owner: epOwner,
            start: PORT_RANGE_START,
            end: PORT_RANGE_END,
            extraExcluded: new Set([...this.pendingPorts, ...this.allAllocatedPorts()])
          });
          this.pendingPorts.add(hPort);
          try {
            record.extraPorts[String(cPort)] = hPort;
            this.save();
          } finally {
            this.pendingPorts.delete(hPort);
            portRegistry.release(hPort, epOwner);
          }
        }
        extraPublishes.push(`127.0.0.1:${hPort}:${cPort}`);
      }
      this.save();
    }
    const containerId = await this.runContainer({
      containerName: record.containerName,
      image: tpl.app.image,
      networkName: record.networkName,
      networkAlias: 'app',
      env: { ...resolveEnv(tpl.app.env, context), ...customEnv },
      volumes: (tpl.app.volumes || []).map((v) => `${record.volumes[v.name]}:${v.path}`),
      files: this.materialiseFiles(record.id, 'app', tpl.app.files || []),
      memoryMb: record.memoryMb,
      cpus: record.cpus,
      shmSize: tpl.app.shmSize || null,
      command: tpl.app.command || null,
      // Sólo bucle local. Ver el comentario de cabecera.
      publish: [`127.0.0.1:${record.hostPort}:${tpl.app.port}`, ...extraPublishes],
      labels: { 'culkibo.service': record.id, 'culkibo.role': 'app' }
    });
    record.containerId = containerId;
    record.status = 'running';
    this.save();

    // --- 6. Dominio ---------------------------------------------------------
    if (record.domain) {
      this.setProgress(record, 'dominio', `Publicando ${record.domain} con HTTPS`);
      const dm = getDomainManager();
      const created = await dm.addDomain({
        hostname: record.domain,
        targetPod: 'service',
        targetPort: record.hostPort,
        cloudflareProxied: false,
        routingMode: 'direct_dns'
      });
      record.domainId = created.id;
      await dm.updateDomain(created.id, { serviceId: record.id, serviceName: record.name });
      this.save();
      const ingress = await getIngressManager().reconcile();
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

    // --- 8. Auxiliares posteriores a la app (workers tras migración) --------
    if (postApp.length > 0 && probe.healthy) {
      this.setProgress(record, 'auxiliares', `Levantando ${postApp.length} worker(s) dependiente(s)`);
      for (const spec of postApp) {
        await this.startSingleSidecarForInstall(record, spec, context, customEnv);
      }
    }

    this.setProgress(
      record,
      'listo',
      probe.healthy
        ? `${record.name} está en marcha en ${record.url}`
        : `${record.name} arrancó, pero todavía no responde. Revisa los registros.`,
      { healthy: probe.healthy }
    );
    this.emit('service_installed', this.toPublic(record));
    try { require('./telemetryService').recordFeatureUsage(`catalog:${record.templateId}`, Boolean(probe.healthy)); } catch (e) {}
  }

  /** Conexión TCP real con timeout limpio (usada por `waitSidecarReady` en sondas `type: 'tcp'`). */
  _tcpConnect(host, port, timeoutMs = 2500) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port });
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (err) reject(err);
        else resolve(true);
      };
      socket.setTimeout(timeoutMs, () => {
        const err = new Error(`Timeout TCP tras ${timeoutMs} ms`);
        /** @type {any} */ (err).code = 'ETIMEDOUT';
        done(err);
      });
      socket.once('connect', () => done(null));
      socket.once('error', (err) => done(err));
    });
  }

  /**
   * Espera a que un auxiliar esté arrancado y, si declara `readiness` (`exec` o `tcp`),
   * supere su comprobación interna antes de continuar (fail-fast en timeout, siempre vía
   * `docker` argv o socket TCP nativo, nunca shell).
   * @param {string} containerName
   * @param {any} readiness
   * @param {{ runningTimeoutMs?: number, hostOverride?: string }} [opts]
   */
  async waitSidecarReady(containerName, readiness, opts = {}) {
    const runBudget = Math.max(500, Number(opts.runningTimeoutMs) || 15000);
    const runningDeadline = Date.now() + runBudget;
    let isRunning = false;
    while (Date.now() < runningDeadline) {
      try {
        const { stdout } = await this.docker(['inspect', '--format', '{{.State.Running}}', containerName], { timeout: 5000 });
        if (stdout.trim() === 'true') {
          isRunning = true;
          break;
        }
      } catch (e) {}
      await new Promise((r) => setTimeout(r, Math.min(800, Math.max(50, runningDeadline - Date.now()))));
    }
    if (!isRunning) {
      throw new Error(`El servicio auxiliar «${containerName}» no alcanzó el estado running a tiempo`);
    }

    if (!readiness || typeof readiness !== 'object') return { ok: true, mode: 'running' };

    if (readiness.type === 'exec' && Array.isArray(readiness.cmd) && readiness.cmd.length > 0) {
      const cmd = readiness.cmd.map((a) => String(a));
      const budget = Math.max(500, Math.min(180000, Number(readiness.timeoutMs) || 30000));
      const deadline = Date.now() + budget;
      let lastErr = 'sin respuesta';
      while (Date.now() < deadline) {
        try {
          await this.docker(['exec', containerName, ...cmd], { timeout: 5000 });
          return { ok: true, mode: 'exec' };
        } catch (e) {
          lastErr = e.message || 'exec falló';
        }
        await new Promise((r) => setTimeout(r, Math.min(1000, Math.max(50, deadline - Date.now()))));
      }
      throw new Error(`El servicio auxiliar «${containerName}» no superó su sonda exec a tiempo (${lastErr})`);
    }

    if (readiness.type === 'tcp' && Number.isInteger(readiness.port) && readiness.port > 0 && readiness.port < 65536) {
      const budget = Math.max(500, Math.min(180000, Number(readiness.timeoutMs) || 30000));
      const deadline = Date.now() + budget;
      let lastErr = 'sin respuesta TCP';
      while (Date.now() < deadline) {
        try {
          const { stdout } = await this.docker(
            ['inspect', '--format', '{{.State.Running}}|{{.State.Restarting}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', containerName],
            { timeout: 5000 }
          );
          const [running, restarting, ipsRaw] = String(stdout || '').trim().split('|');
          if (running !== 'true') {
            lastErr = 'contenedor detenido';
          } else {
            const ip = opts.hostOverride || String(ipsRaw || '').trim().split(/\s+/).find(Boolean);
            if (!ip) {
              lastErr = 'sin IP en la red aislada';
            } else {
              try {
                await this._tcpConnect(ip, readiness.port, Math.min(2500, Math.max(300, deadline - Date.now())));
                return { ok: true, mode: 'tcp', ip, port: readiness.port };
              } catch (tcpErr) {
                const code = tcpErr && tcpErr.code;
                // En Docker Desktop (Windows/macOS) las IPs del puente Linux VM no son enrutables desde el host.
                if (
                  process.platform !== 'linux' &&
                  !opts.hostOverride &&
                  (code === 'ENETUNREACH' || code === 'EHOSTUNREACH') &&
                  restarting !== 'true'
                ) {
                  return { ok: true, mode: 'tcp_vm_fallback', ip, port: readiness.port };
                }
                lastErr = tcpErr.message || String(code || 'tcp error');
              }
            }
          }
        } catch (e) {
          lastErr = e.message || 'inspect falló';
        }
        await new Promise((r) => setTimeout(r, Math.min(1000, Math.max(50, deadline - Date.now()))));
      }
      throw new Error(`El servicio auxiliar «${containerName}» no escuchó en TCP :${readiness.port} a tiempo (${lastErr})`);
    }

    return { ok: true, mode: 'running' };
  }

  /**
   * Escribe en disco los ficheros de configuración de una plantilla y devuelve
   * las especificaciones de montaje (`{ hostPath, targetPath }`) que `runContainer`
   * convierte en `--mount type=bind,...,readonly` (seguro en Windows y Linux).
   */
  materialiseFiles(installId, role, files) {
    if (!files || files.length === 0) return [];
    const safeRole = String(role || '');
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(safeRole)) {
      throw new Error(`Rol de contenedor inválido al materializar ficheros: «${safeRole}»`);
    }
    const dir = path.resolve(this.filesRoot, installId, safeRole);
    const rootResolved = path.resolve(this.filesRoot);
    if (!dir.startsWith(rootResolved + path.sep)) {
      throw new Error('Ruta de destino fuera del directorio de servicios');
    }
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    return files.map((file) => {
      const fileName = String(file.name || '');
      if (!FILE_NAME_RE.test(fileName) || fileName === '.' || fileName === '..' || fileName.includes('..')) {
        throw new Error(`Nombre de fichero de configuración inválido: «${fileName}»`);
      }
      const targetPath = String(file.path || '');
      if (!targetPath.startsWith('/') || targetPath.includes('docker.sock') || /[\r\n\0,]/.test(targetPath)) {
        throw new Error(`Ruta de montaje inválida en fichero de configuración: «${targetPath}»`);
      }
      const hostPath = path.resolve(dir, fileName);
      if (!hostPath.startsWith(dir + path.sep)) {
        throw new Error(`Nombre de fichero fuera del directorio permitido: «${fileName}»`);
      }
      const normalisedHost = hostPath.split(path.sep).join('/');
      if (/[\r\n\0,]/.test(normalisedHost)) {
        throw new Error(`La ruta de host contiene caracteres no soportados por --mount: «${normalisedHost}»`);
      }
      fs.writeFileSync(hostPath, file.content, { encoding: 'utf8', mode: 0o644 });
      // Forzar 0644 explícito para ignorar UMask=0027 de systemd y evitar EACCES en contenedores no-root
      if (process.platform !== 'win32') {
        try { fs.chmodSync(dir, 0o755); fs.chmodSync(hostPath, 0o644); } catch (e) {}
      }
      return { hostPath: normalisedHost, targetPath };
    });
  }

  /** Detecta de forma perezosa si el kernel soporta `--memory-swap` (evita fallos en Linux cgroup v2 sin swapaccount). */
  async supportsMemorySwap() {
    if (this._swapLimitSupported !== null) return this._swapLimitSupported;
    try {
      const { stdout } = await this.docker(['info', '--format', '{{.SwapLimit}}'], { timeout: 5000 });
      const val = String(stdout || '').trim().toLowerCase();
      if (val === 'false' || val === '0') {
        this._swapLimitSupported = false;
        return false;
      }
      this._swapLimitSupported = true;
      return true;
    } catch (e) {
      return true;
    }
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
    const envFile = path.join(this.tmpDir, `svcenv_${crypto.randomBytes(8).toString('hex')}`);
    const allowSwapLimit = await this.supportsMemorySwap();

    const args = [
      'run', '-d',
      '--name', spec.containerName,
      '--restart', 'unless-stopped',
      '--network', spec.networkName,
      '--network-alias', spec.networkAlias,
      '--env-file', envFile,
      '--memory', `${spec.memoryMb}m`,
      ...(allowSwapLimit ? ['--memory-swap', `${spec.memoryMb}m`] : []),
      '--cpus', String(spec.cpus),
      '--pids-limit', '1024',
      '--security-opt', 'no-new-privileges',
      '--log-driver', 'json-file',
      '--log-opt', 'max-size=10m',
      '--log-opt', 'max-file=3',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${spec.labels['culkibo.service']}`
    ];

    if (spec.shmSize) {
      const shm = String(spec.shmSize).trim();
      if (!SHM_SIZE_RE.test(shm)) {
        throw new Error(`Tamaño shmSize inválido: «${shm}»`);
      }
      args.push('--shm-size', shm);
    }

    for (const [key, value] of Object.entries(spec.labels)) {
      args.push('--label', `${key}=${value}`);
    }
    for (const volume of spec.volumes) {
      if (String(volume).includes('docker.sock')) {
        throw new Error('Montaje de docker.sock prohibido en el catálogo de servicios');
      }
      args.push('-v', volume);
    }
    for (const file of spec.files) {
      if (file && typeof file === 'object' && file.hostPath && file.targetPath) {
        if (String(file.hostPath).includes('docker.sock') || String(file.targetPath).includes('docker.sock')) {
          throw new Error('Montaje de docker.sock prohibido en ficheros de configuración');
        }
        args.push('--mount', `type=bind,source=${file.hostPath},target=${file.targetPath},readonly`);
      } else {
        if (String(file).includes('docker.sock')) {
          throw new Error('Montaje de docker.sock prohibido en ficheros de configuración');
        }
        args.push('-v', String(file));
      }
    }
    if (Array.isArray(spec.publish)) {
      for (const p of spec.publish) { if (p) args.push('-p', p); }
    } else if (spec.publish) {
      args.push('-p', spec.publish);
    }

    args.push(spec.image);
    if (spec.command) args.push(...spec.command);

    try {
      fs.mkdirSync(this.tmpDir, { recursive: true });
      fs.writeFileSync(
        envFile,
        formatDockerEnvFile(spec.env),
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

  /** Vuelve a sondear un servicio ya instalado y actualiza su estado (recuperando `degraded` -> `running`). */
  async refreshHealth(id) {
    const record = this.mustGet(id);
    const tpl = this.getTemplate(record.templateId);
    const probe = await this.probeOnce(record.hostPort, tpl.app.readiness);
    record.health = probe.healthy ? 'healthy' : 'unhealthy';
    if (probe.healthy && record.status === 'degraded') {
      record.status = 'running';
      record.lastError = null;
    }
    record.lastProbe = { ...probe, attempts: 1, checkedAt: new Date().toISOString() };
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  /** Desencripta variables de entorno personalizadas guardadas por el usuario en la instalación. */
  decryptCustomEnv(record) {
    /** @type {Record<string, string>} */
    const out = {};
    for (const [k, blob] of Object.entries(record.customEnvEnc || {})) {
      try { out[k] = decryptSecret(blob, this.cryptoKey); } catch (e) {}
    }
    return out;
  }

  /** Reconstruye el contexto completo de plantilla (incluyendo BD, secretos, zona horaria y sidecars). */
  buildRuntimeContext(record, tpl) {
    const secrets = this.decryptSecrets(record);
    /** @type {any} */
    let dbContext = null;
    if (tpl.database && record.databaseId) {
      const dm = getDbManager();
      const creds = dm.getCredentials(record.databaseId);
      const alias = tpl.database.engine;
      dbContext = {
        host: alias,
        port: creds.port,
        user: creds.username,
        password: creds.password,
        name: creds.dbName || '',
        url: dm.buildConnectionString(dm.get(record.databaseId), creds.password, { host: alias })
      };
    }
    return {
      installId: record.id,
      domain: record.domain,
      hostPort: record.hostPort,
      url: record.url,
      tz: record.tz || defaultTimezone(),
      secrets,
      db: dbContext,
      sidecarHosts: Object.fromEntries((record.sidecars || []).map((c) => [c.name, c.containerName]))
    };
  }

  /**
   * Devuelve las variables efectivas (con secretos redactados) + overrides
   * personalizados del usuario. Expone tanto `overrides`/`env` (consumido por
   * `ServiceCatalog.tsx` y `api.ts`) como `customEnv`/`templateKeys` por
   * retrocompatibilidad.
   */
  getEnv(id) {
    const record = this.mustGet(id);
    const tpl = this.getTemplate(record.templateId);
    const customEnv = this.decryptCustomEnv(record);
    const templateKeys = Object.keys(tpl.app.env || {});
    const secretKeys = Object.keys(tpl.secrets || {});
    /** @type {Record<string, string>} */
    const maskedTemplateEnv = {};
    try {
      const ctx = {
        installId: record.id,
        domain: record.domain,
        hostPort: record.hostPort,
        url: record.url,
        tz: record.tz || defaultTimezone(),
        secrets: Object.fromEntries(secretKeys.map((k) => [k, '••••••••'])),
        db: tpl.database
          ? { host: tpl.database.engine, port: 0, user: tpl.database.username || 'culkibo', password: '••••••••', name: tpl.database.dbName || '', url: '••••••••' }
          : null,
        sidecarHosts: Object.fromEntries((record.sidecars || []).map((c) => [c.name, c.containerName]))
      };
      const resolved = resolveEnv(tpl.app.env, ctx);
      for (const [k, v] of Object.entries(resolved)) {
        maskedTemplateEnv[k] = String(v).includes('••••••••') ? '••••••••' : v;
      }
    } catch (e) {
      for (const k of templateKeys) maskedTemplateEnv[k] = String(tpl.app.env[k] || '');
    }
    return {
      id: record.id,
      env: { ...maskedTemplateEnv, ...customEnv },
      overrides: customEnv,
      customEnv,
      templateKeys,
      customKeys: Object.keys(customEnv),
      secretKeys
    };
  }

  /**
   * Recrea un contenedor auxiliar aplicando su contexto vigente, overrides
   * (si está acoplado) y una imagen opcional.
   * @param {any} record
   * @param {any} sidecarSpec
   * @param {any} storedSidecar
   * @param {{ imageOverride?: string | null }} [opts]
   */
  async recreateSidecarContainer(record, sidecarSpec, storedSidecar, { imageOverride = null } = {}) {
    const tpl = this.getTemplate(record.templateId);
    const context = this.buildRuntimeContext(record, tpl);
    const customEnv = this.decryptCustomEnv(record);
    const effectiveEnv = sidecarSpec.coupledWithApp
      ? { ...resolveEnv(sidecarSpec.env, context), ...customEnv }
      : resolveEnv(sidecarSpec.env, context);
    const targetImage = imageOverride || storedSidecar.image || sidecarSpec.image;

    try { await this.docker(['stop', '-t', '20', storedSidecar.containerName], { timeout: 60000 }); } catch (e) {}
    try { await this.docker(['rm', '-f', storedSidecar.containerName], { timeout: 30000 }); } catch (e) {}

    const containerId = await this.runContainer({
      containerName: storedSidecar.containerName,
      image: targetImage,
      networkName: record.networkName,
      networkAlias: sidecarSpec.name,
      env: effectiveEnv,
      volumes: (sidecarSpec.volumes || []).map((v) => `${storedSidecar.volumes[v.name]}:${v.path}`),
      files: this.materialiseFiles(record.id, sidecarSpec.name, sidecarSpec.files || []),
      memoryMb: sidecarSpec.memoryMb,
      cpus: sidecarSpec.cpus,
      command: sidecarSpec.command || null,
      publish: null,
      labels: { 'culkibo.service': record.id, 'culkibo.role': sidecarSpec.name }
    });
    storedSidecar.image = targetImage;
    record.updatedAt = new Date().toISOString();
    this.save();
    return containerId;
  }

  /**
   * Recrea el contenedor principal de una instalación aplicando nueva imagen o variables de entorno,
   * con rollback automático al estado anterior si el nuevo arranque falla.
   * @param {any} record
   * @param {{ imageOverride?: string | null }} [opts]
   */
  async recreateAppContainer(record, { imageOverride = null } = {}) {
    const tpl = this.getTemplate(record.templateId);
    const context = this.buildRuntimeContext(record, tpl);
    const customEnv = this.decryptCustomEnv(record);
    const effectiveEnv = { ...resolveEnv(tpl.app.env, context), ...customEnv };
    const targetImage = imageOverride || record.image || tpl.app.image;

    try { await this.docker(['stop', '-t', '20', record.containerName], { timeout: 60000 }); } catch (e) {}
    try { await this.docker(['rm', '-f', record.containerName], { timeout: 30000 }); } catch (e) {}

    const extraPublishes = Object.entries(record.extraPorts || {}).map(([cPort, hPort]) => `127.0.0.1:${hPort}:${cPort}`);
    const containerId = await this.runContainer({
      containerName: record.containerName,
      image: targetImage,
      networkName: record.networkName,
      networkAlias: 'app',
      env: effectiveEnv,
      volumes: (tpl.app.volumes || []).map((v) => `${record.volumes[v.name]}:${v.path}`),
      files: this.materialiseFiles(record.id, 'app', tpl.app.files || []),
      memoryMb: record.memoryMb,
      cpus: record.cpus,
      shmSize: tpl.app.shmSize || null,
      command: tpl.app.command || null,
      publish: [`127.0.0.1:${record.hostPort}:${tpl.app.port}`, ...extraPublishes],
      labels: { 'culkibo.service': record.id, 'culkibo.role': 'app' }
    });
    record.containerId = containerId;
    record.image = targetImage;
    record.status = 'running';
    record.updatedAt = new Date().toISOString();
    this.save();
    return containerId;
  }

  /** Actualiza variables personalizadas del servicio y recrea app + auxiliares acoplados con rollback. */
  async updateEnv(id, overrides = {}) {
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio se está instalando ahora mismo');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const entries = validateEnvOverrides(overrides, { allowDelete: true });
    const prevCustom = { ...(record.customEnvEnc || {}) };
    /** @type {Record<string, string>} */
    const nextEnc = { ...prevCustom };
    for (const [k, val] of entries) {
      if (val === null) delete nextEnc[k];
      else nextEnc[k] = encryptSecret(val, this.cryptoKey);
    }
    record.customEnvEnc = nextEnc;
    this.save();

    if (await this.isDockerAvailable()) {
      const tpl = this.getTemplate(record.templateId);
      const coupledSpecs = (tpl.sidecars || []).filter((s) => s.coupledWithApp);
      try {
        await this.recreateAppContainer(record);
        for (const spec of coupledSpecs) {
          const stored = (record.sidecars || []).find((c) => c.name === spec.name);
          if (stored) await this.recreateSidecarContainer(record, spec, stored);
        }
      } catch (err) {
        record.customEnvEnc = prevCustom;
        this.save();
        try { await this.recreateAppContainer(record); } catch (e2) {}
        for (const spec of coupledSpecs) {
          const stored = (record.sidecars || []).find((c) => c.name === spec.name);
          if (stored) {
            try { await this.recreateSidecarContainer(record, spec, stored); } catch (e2) {}
          }
        }
        throw err;
      }
    }
    return { success: true, service: this.toPublic(record), customKeys: Object.keys(record.customEnvEnc || {}) };
  }

  /**
   * Actualiza la etiqueta fijada de imagen del contenedor principal y de todos
   * sus auxiliares acoplados (`coupledWithApp` / misma imagen), con validación
   * de repositorio y rollback automático completo si falla la sonda de salud.
   * @param {string} id
   * @param {string} newImage
   * @param {{ allowRepoChange?: boolean }} [opts]
   */
  async updateImage(id, newImage, { allowRepoChange = false } = {}) {
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio se está instalando ahora mismo');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const img = String(newImage || '').trim();
    if (!IMAGE_RE.test(img) || FLOATING_TAG_RE.test(img)) {
      throw new Error('La nueva imagen debe llevar una etiqueta de versión fija (no :latest ni etiquetas móviles)');
    }
    const prevImage = record.image;
    const prevRepo = parseImageRef(prevImage).repo;
    const nextRepo = parseImageRef(img).repo;
    if (!allowRepoChange && prevRepo && nextRepo && prevRepo !== nextRepo) {
      throw new Error(
        `La nueva imagen (${nextRepo}) pertenece a otro repositorio distinto de ${prevRepo}. ` +
        'Confirma explícitamente `allowRepoChange: true` si deseas cambiar de repositorio.'
      );
    }
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible');
    }
    const tpl = this.getTemplate(record.templateId);
    const { preApp, postApp } = orderSidecars(tpl.sidecars || []);
    const isCoupled = (spec, stored) => Boolean(spec.coupledWithApp || (stored && stored.image === prevImage));

    /** @type {Array<{ spec: any, stored: any, prevImage: string, nextImage: string, phase: 'pre' | 'post' }>} */
    const coupledTargets = [];
    for (const [phase, list] of /** @type {const} */ ([['pre', preApp], ['post', postApp]])) {
      for (const spec of list) {
        const stored = (record.sidecars || []).find((c) => c.name === spec.name);
        if (!stored || !isCoupled(spec, stored)) continue;
        const nextSidecarImage = resolveCoupledSidecarImage(spec, stored.image, img);
        if (!IMAGE_RE.test(nextSidecarImage) || FLOATING_TAG_RE.test(nextSidecarImage)) {
          throw new Error(`Imagen acoplada inválida para el auxiliar «${spec.name}»: ${nextSidecarImage}`);
        }
        coupledTargets.push({ spec, stored, prevImage: stored.image, nextImage: nextSidecarImage, phase });
      }
    }

    // Descargar todas las imágenes nuevas antes de detener ningún contenedor
    const imagesToPull = new Set([img, ...coupledTargets.map((t) => t.nextImage)]);
    for (const toPull of imagesToPull) {
      await this.pullImage(toPull);
    }

    const prevHealth = record.health;
    const prevStatus = record.status;
    /** @type {typeof coupledTargets} */
    const mutatedSidecars = [];
    try {
      for (const target of coupledTargets.filter((t) => t.phase === 'pre')) {
        await this.recreateSidecarContainer(record, target.spec, target.stored, { imageOverride: target.nextImage });
        mutatedSidecars.push(target);
        await this.waitSidecarReady(target.stored.containerName, target.spec.readiness || null);
      }

      await this.recreateAppContainer(record, { imageOverride: img });
      const probe = await this.waitUntilReady(record, {
        ...tpl.app.readiness,
        timeoutMs: Math.max(tpl.app.readiness.timeoutMs || 90000, 60000)
      });
      if (!probe.healthy) {
        throw new Error(`La nueva imagen no respondió en ${tpl.app.readiness.path} (${probe.detail})`);
      }

      for (const target of coupledTargets.filter((t) => t.phase === 'post')) {
        await this.recreateSidecarContainer(record, target.spec, target.stored, { imageOverride: target.nextImage });
        mutatedSidecars.push(target);
        await this.waitSidecarReady(target.stored.containerName, target.spec.readiness || null);
      }

      record.health = 'healthy';
      record.lastProbe = probe;
      record.lastError = null;
      this.save();
      return {
        success: true,
        previousImage: prevImage,
        image: img,
        updatedSidecars: mutatedSidecars.map((t) => ({ name: t.spec.name, previousImage: t.prevImage, image: t.nextImage })),
        service: this.toPublic(record)
      };
    } catch (err) {
      // Rollback automático completo: app + todos los auxiliares acoplados modificados
      record.image = prevImage;
      record.health = prevHealth;
      record.status = prevStatus;
      for (const target of mutatedSidecars) target.stored.image = target.prevImage;
      this.save();
      for (const target of mutatedSidecars.filter((t) => t.phase === 'pre')) {
        try { await this.recreateSidecarContainer(record, target.spec, target.stored, { imageOverride: target.prevImage }); } catch (e2) {}
      }
      try { await this.recreateAppContainer(record, { imageOverride: prevImage }); } catch (e2) {}
      for (const target of mutatedSidecars.filter((t) => t.phase === 'post')) {
        try { await this.recreateSidecarContainer(record, target.spec, target.stored, { imageOverride: target.prevImage }); } catch (e2) {}
      }
      record.health = prevHealth;
      record.status = prevStatus;
      this.save();
      throw new Error(`Actualización revertida a ${prevImage}: ${err.message}`);
    }
  }

  /**
   * Comprueba si una o todas las instalaciones están desfasadas respecto a la
   * versión fijada actual del catálogo (sin red, O(n) instantáneo).
   * @param {string | null} [id]
   */
  checkImageDrift(id = null) {
    const inspectOne = (record) => {
      const tpl = TEMPLATE_MAP.get(record.templateId);
      const catalogImage = tpl ? tpl.app.image : record.image;
      const appDrifted = Boolean(tpl && tpl.app.image !== record.image);
      const sidecarDrifts = [];
      for (const stored of record.sidecars || []) {
        const spec = tpl ? (tpl.sidecars || []).find((s) => s.name === stored.name) : null;
        if (spec && spec.image !== stored.image) {
          sidecarDrifts.push({
            name: stored.name,
            currentImage: stored.image,
            catalogImage: spec.image,
            coupledWithApp: Boolean(spec.coupledWithApp)
          });
        }
      }
      return {
        id: record.id,
        templateId: record.templateId,
        name: record.name,
        currentImage: record.image,
        catalogImage,
        hasUpdate: appDrifted || sidecarDrifts.length > 0,
        appDrifted,
        sidecarDrifts,
        totalDrifts: (appDrifted ? 1 : 0) + sidecarDrifts.length
      };
    };

    if (id) return inspectOne(this.mustGet(id));
    const services = this.state.installations.map(inspectOne);
    return {
      checkedAt: new Date().toISOString(),
      totalCount: services.length,
      outdatedCount: services.filter((s) => s.hasUpdate).length,
      services
    };
  }

  // -------------------------------------------------------------------------
  // Copias de seguridad de volúmenes Docker (0 shell, imagen fijada alpine)
  // -------------------------------------------------------------------------

  /** Lista todos los volúmenes nombrados de una instalación (app + sidecars). */
  collectNamedVolumes(record) {
    /** @type {Array<{ role: string, key: string, volumeName: string, archiveName: string }>} */
    const out = [];
    for (const [key, volumeName] of Object.entries(record.volumes || {})) {
      if (volumeName) out.push({ role: 'app', key, volumeName, archiveName: `app_${key}.tar.gz` });
    }
    for (const car of record.sidecars || []) {
      for (const [key, volumeName] of Object.entries(car.volumes || {})) {
        if (volumeName) out.push({ role: car.name, key, volumeName, archiveName: `${car.name}_${key}.tar.gz` });
      }
    }
    return out;
  }

  /**
   * Crea una copia de seguridad `.tar.gz` con resumen SHA-256 de todos los
   * volúmenes nombrados del servicio usando únicamente `docker(argv)` y una
   * imagen fijada (`alpine:3.21.3`).
   */
  async backupVolumes(id, { label = 'manual' } = {}) {
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio se está instalando ahora mismo');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const volumes = this.collectNamedVolumes(record);
    if (volumes.length === 0) {
      return {
        success: true,
        id: record.id,
        backupId: null,
        skipped: 'no_volumes',
        volumes: [],
        totalBytes: 0
      };
    }
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible');
    }
    const safeLabel = String(label || 'manual').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || 'manual';
    const stamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
    const backupId = `vbk_${stamp}_${crypto.randomBytes(3).toString('hex')}`;
    const destDir = path.resolve(this.backupsRoot, record.id, backupId);
    const rootResolved = path.resolve(this.backupsRoot);
    if (!destDir.startsWith(rootResolved + path.sep)) {
      throw new Error('Ruta de copia de seguridad fuera del directorio permitido');
    }
    fs.mkdirSync(destDir, { recursive: true, mode: 0o700 });
    const mountDest = destDir.split(path.sep).join('/');

    /** @type {Array<{ role: string, key: string, volumeName: string, archiveName: string, sizeBytes: number, sha256: string }>} */
    const backedUp = [];
    let totalBytes = 0;
    try {
      for (const vol of volumes) {
        await this.docker([
          'run', '--rm',
          '--security-opt', 'no-new-privileges',
          '-v', `${vol.volumeName}:/source:ro`,
          '--mount', `type=bind,source=${mountDest},target=/backup`,
          BACKUP_IMAGE,
          'tar', '-czf', `/backup/${vol.archiveName}`, '-C', '/source', '.'
        ], { timeout: 600000 });
        const archivePath = path.join(destDir, vol.archiveName);
        if (!fs.existsSync(archivePath)) {
          throw new Error(`El volcado del volumen «${vol.volumeName}» no generó el archivo esperado`);
        }
        const buf = fs.readFileSync(archivePath);
        const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
        totalBytes += buf.length;
        backedUp.push({ ...vol, sizeBytes: buf.length, sha256 });
      }
    } catch (err) {
      try { fs.rmSync(destDir, { recursive: true, force: true }); } catch (e) {}
      throw err;
    }

    const manifest = {
      version: 1,
      backupId,
      installId: record.id,
      templateId: record.templateId,
      image: record.image,
      label: safeLabel,
      createdAt: new Date().toISOString(),
      totalBytes,
      volumes: backedUp
    };
    atomicWriteJsonSync(path.join(destDir, 'manifest.json'), manifest, 0o600);
    return { success: true, id: record.id, ...manifest };
  }

  /** Lista copias de volúmenes existentes de una instalación (de más reciente a más antigua). */
  listVolumeBackups(id) {
    const record = this.mustGet(id);
    const serviceDir = path.resolve(this.backupsRoot, record.id);
    if (!fs.existsSync(serviceDir)) return [];
    const entries = fs.readdirSync(serviceDir, { withFileTypes: true }).filter((d) => d.isDirectory());
    /** @type {any[]} */
    const out = [];
    for (const entry of entries) {
      if (!BACKUP_ID_RE.test(entry.name)) continue;
      const manifestPath = path.join(serviceDir, entry.name, 'manifest.json');
      try {
        if (fs.existsSync(manifestPath)) {
          out.push(JSON.parse(fs.readFileSync(manifestPath, 'utf8')));
        }
      } catch (e) {}
    }
    return out.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  }

  /**
   * Restaura uno o todos los volúmenes de una copia de seguridad verificando
   * previamente el SHA-256 de cada archivo (fail-fast antes de tocar datos).
   */
  async restoreVolume(id, backupId, { volumeKey = null } = {}) {
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio se está instalando ahora mismo');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const bid = String(backupId || '').trim();
    if (!BACKUP_ID_RE.test(bid)) throw new Error('Identificador de copia de seguridad inválido');
    const backupDir = path.resolve(this.backupsRoot, record.id, bid);
    const rootResolved = path.resolve(this.backupsRoot);
    if (!backupDir.startsWith(rootResolved + path.sep) || !fs.existsSync(path.join(backupDir, 'manifest.json'))) {
      throw new Error(`La copia de seguridad ${bid} no existe para ${record.id}`);
    }
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible');
    }

    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, 'manifest.json'), 'utf8'));
    const targets = (manifest.volumes || []).filter((v) => !volumeKey || v.key === volumeKey || `${v.role}:${v.key}` === volumeKey);
    if (targets.length === 0) {
      throw new Error(`No hay volúmenes que coincidan con «${volumeKey || '*'}» en la copia ${bid}`);
    }

    // 1. Verificar integridad SHA-256 ANTES de detener o sobrescribir nada
    for (const v of targets) {
      if (!FILE_NAME_RE.test(String(v.archiveName || ''))) {
        throw new Error(`Nombre de archivo inválido en el manifiesto: ${v.archiveName}`);
      }
      const archivePath = path.join(backupDir, v.archiveName);
      if (!fs.existsSync(archivePath)) throw new Error(`Falta el archivo ${v.archiveName} en la copia ${bid}`);
      const actualHash = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
      if (v.sha256 && actualHash !== v.sha256) {
        throw new Error(`Integridad SHA-256 fallida en ${v.archiveName}: copia corrupta o manipulada`);
      }
    }

    const wasRunning = record.status === 'running' || record.status === 'degraded';
    if (wasRunning) {
      await this.stop(record.id);
    }

    const mountSrc = backupDir.split(path.sep).join('/');
    /** @type {string[]} */
    const restoredVolumes = [];
    try {
      for (const v of targets) {
        await this.docker([
          'run', '--rm',
          '--security-opt', 'no-new-privileges',
          '-v', `${v.volumeName}:/target`,
          '--mount', `type=bind,source=${mountSrc},target=/backup,readonly`,
          BACKUP_IMAGE,
          'tar', '-xzf', `/backup/${v.archiveName}`, '-C', '/target'
        ], { timeout: 600000 });
        restoredVolumes.push(v.volumeName);
      }
    } finally {
      if (wasRunning) {
        try { await this.start(record.id); } catch (e) {}
      }
    }
    return { success: true, id: record.id, backupId: bid, restoredVolumes };
  }

  /** Estadísticas en vivo (`docker stats --no-stream`) del contenedor principal y auxiliares. */
  async getStats(id) {
    const record = this.mustGet(id);
    if (!(await this.isDockerAvailable())) {
      return { id: record.id, available: false, containers: [] };
    }
    const names = this.allContainerNames(record);
    try {
      const { stdout } = await this.docker([
        'stats', '--no-stream', '--format',
        '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.PIDs}}',
        ...names
      ], { timeout: 15000 });
      const containers = (stdout || '').trim().split(/\r?\n/).filter(Boolean).map((line) => {
        const [name, cpu, memUsage, memPerc, netIo, pids] = line.split('|');
        return {
          name,
          containerName: name,
          role: name === record.containerName ? 'app' : (record.sidecars.find((c) => c.containerName === name)?.name || 'sidecar'),
          cpuPercent: parseFloat(String(cpu || '0').replace('%', '')) || 0,
          memoryUsage: memUsage || '',
          memoryPercent: parseFloat(String(memPerc || '0').replace('%', '')) || 0,
          netIo: netIo || '',
          pids: parseInt(String(pids || '0'), 10) || 0
        };
      });
      return { id: record.id, available: true, containers };
    } catch (e) {
      return { id: record.id, available: false, containers: [], error: e.message };
    }
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
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio todavía se está instalando');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const tpl = TEMPLATE_MAP.get(record.templateId);

    // 1. Base de datos gestionada + espera de salud
    if (record.databaseId) {
      await getDbManager().start(record.databaseId);
      await this.waitDbReady(record.databaseId, (tpl && tpl.database && tpl.database.readyTimeoutMs) || 90000);
    }

    const { preApp, postApp } = tpl
      ? orderSidecars(tpl.sidecars || [])
      : { preApp: record.sidecars.filter((c) => !c.startAfterApp), postApp: record.sidecars.filter((c) => c.startAfterApp) };

    // 2. Auxiliares previos en orden topológico, esperando su sonda uno a uno
    for (const spec of preApp) {
      const car = record.sidecars.find((c) => c.name === spec.name);
      if (!car) continue;
      await this.docker(['start', car.containerName], { timeout: 60000 });
      await this.waitSidecarReady(car.containerName, spec.readiness || null);
    }

    // 3. Contenedor principal
    await this.docker(['start', record.containerName], { timeout: 60000 });

    // 4. Auxiliares dependientes (workers) tras arranque de `app`
    if (postApp.length > 0) {
      if (tpl && tpl.app && tpl.app.readiness) {
        const probe = await this.waitUntilReady(record, {
          ...tpl.app.readiness,
          timeoutMs: Math.min(tpl.app.readiness.timeoutMs || 60000, 90000)
        });
        record.health = probe.healthy ? 'healthy' : 'unhealthy';
        record.lastProbe = probe;
      }
      for (const spec of postApp) {
        const car = record.sidecars.find((c) => c.name === spec.name);
        if (!car) continue;
        await this.docker(['start', car.containerName], { timeout: 60000 });
        await this.waitSidecarReady(car.containerName, spec.readiness || null);
      }
    }

    record.status = 'running';
    record.updatedAt = new Date().toISOString();
    this.save();
    if (record.domainId) {
      try { await getIngressManager().reconcile(); } catch (e) {}
    }
    return this.toPublic(record);
  }

  async stop(id) {
    if (this.inFlight.has(id)) {
      const err = new Error('No puedes detener un servicio mientras se está instalando');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const tpl = TEMPLATE_MAP.get(record.templateId);
    const { preApp, postApp } = tpl
      ? orderSidecars(tpl.sidecars || [])
      : { preApp: record.sidecars.filter((c) => !c.startAfterApp), postApp: record.sidecars.filter((c) => c.startAfterApp) };

    // Parada en orden inverso de dependencias: workers → app → auxiliares base
    for (const spec of [...postApp].reverse()) {
      const car = record.sidecars.find((c) => c.name === spec.name);
      if (!car) continue;
      try { await this.docker(['stop', car.containerName], { timeout: 90000 }); } catch (e) {}
    }
    await this.docker(['stop', record.containerName], { timeout: 90000 });
    for (const spec of [...preApp].reverse()) {
      const car = record.sidecars.find((c) => c.name === spec.name);
      if (!car) continue;
      try { await this.docker(['stop', car.containerName], { timeout: 90000 }); } catch (e) {}
    }
    record.status = 'stopped';
    record.health = 'unknown';
    record.updatedAt = new Date().toISOString();
    this.save();
    // Reconciliar Caddy DESPUÉS de marcar `stopped`: ingressManager omite servicios detenidos y limpia su ruta correctamente.
    if (record.domainId) {
      try { await getIngressManager().reconcile(); } catch (e) {}
    }
    return this.toPublic(record);
  }

  async restart(id) {
    await this.stop(id);
    return this.start(id);
  }

  /** Devuelve registros del contenedor principal o de un auxiliar (`role`), con secretos redactados. */
  async logs(id, { lines = 200, role = 'app' } = {}) {
    const record = this.mustGet(id);
    const count = Math.max(1, Math.min(2000, parseInt(String(lines), 10) || 200));
    let targetContainer = record.containerName;
    if (role && role !== 'app') {
      const sidecar = (record.sidecars || []).find((c) => c.name === role);
      if (!sidecar) throw new Error(`Auxiliar «${role}» no encontrado en esta instalación`);
      targetContainer = sidecar.containerName;
    }
    const { stdout, stderr } = await this.docker(
      ['logs', '--tail', String(count), targetContainer],
      { timeout: 20000 }
    );
    /** @type {Record<string, any>} */
    const secrets = { ...this.decryptSecrets(record), ...this.decryptCustomEnv(record) };
    if (record.databaseId) {
      try {
        const dbCreds = getDbManager().getCredentials(record.databaseId);
        if (dbCreds && dbCreds.password) secrets.__db_password = dbCreds.password;
      } catch (e) {}
    }
    return {
      id: record.id,
      role: role || 'app',
      containerName: targetContainer,
      output: this.redact(`${stdout}${stderr}`, secrets, null)
    };
  }

  /** Sincroniza el dominio/URL cuando un dominio vinculado se edita o elimina desde DomainManager. */
  syncDomainRemoved(domainId) {
    let changed = false;
    for (const inst of this.state.installations) {
      if (inst.domainId === domainId) {
        inst.domainId = null;
        inst.domain = null;
        inst.url = `http://127.0.0.1:${inst.hostPort}`;
        inst.updatedAt = new Date().toISOString();
        changed = true;
      }
    }
    if (changed) this.save();
  }

  /** Conecta o actualiza un dominio HTTPS sobre un servicio ya instalado (p. ej. WordPress). */
  async attachDomain(id, rawHostname) {
    const record = this.mustGet(id);
    const domain = String(rawHostname || '').trim().toLowerCase();
    if (!domain || !DOMAIN_RE.test(domain)) {
      throw new Error(`Dominio inválido: «${domain}». Usa un nombre completo, por ejemplo miweb.com`);
    }
    const domainManager = getDomainManager();
    const existing = domainManager.getByHostname(domain);
    if (existing && existing.serviceId !== record.id) {
      throw new Error(`El dominio ${domain} ya está en uso en Culkibo`);
    }
    if (record.domainId && record.domain !== domain) {
      try { await domainManager.deleteDomain(record.domainId); } catch (e) {}
    }
    const created = existing || await domainManager.addDomain({
      hostname: domain,
      targetPod: 'service',
      targetPort: record.hostPort,
      cloudflareProxied: false,
      routingMode: 'direct_dns'
    });
    await domainManager.updateDomain(created.id, {
      targetPod: 'service',
      targetPort: record.hostPort,
      serviceId: record.id,
      serviceName: record.name
    });
    record.domain = domain;
    record.domainId = created.id;
    record.url = `https://${domain}`;
    record.updatedAt = new Date().toISOString();
    this.save();
    // Recrear app y auxiliares acoplados o que consuman {{url}}/{{domain}}/{{host}} si está activo
    if (record.status === 'running' && (await this.isDockerAvailable())) {
      try { await this.recreateAppContainer(record); } catch (e) {}
      const tpl = TEMPLATE_MAP.get(record.templateId);
      for (const spec of (tpl && tpl.sidecars) || []) {
        const envStr = JSON.stringify(spec.env || {});
        const usesUrl = spec.coupledWithApp || /\{\{(url|domain|host|protocol|wsProtocol|isHttps)\}\}/.test(envStr);
        if (!usesUrl) continue;
        const stored = (record.sidecars || []).find((c) => c.name === spec.name);
        if (stored) {
          try { await this.recreateSidecarContainer(record, spec, stored); } catch (e) {}
        }
      }
    }
    const ingress = await getIngressManager().reconcile().catch((e) => ({ applied: false, reason: e.message }));
    record.ingress = {
      applied: Boolean(ingress && ingress.applied),
      reason: ingress && ingress.reason ? ingress.reason : null
    };
    this.save();
    return this.toPublic(record);
  }

  async remove(id, { deleteVolumes = false, deleteBackups = deleteVolumes } = {}) {
    if (this.inFlight.has(id)) {
      const err = new Error('El servicio se está instalando ahora mismo; espera a que termine antes de eliminarlo');
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    const record = this.mustGet(id);
    const removed = {
      containers: /** @type {string[]} */ ([]),
      volumes: /** @type {string[]} */ ([]),
      network: /** @type {string | null} */ (null),
      database: /** @type {string | null} */ (null),
      domain: /** @type {string | null} */ (null)
    };

    if (await this.isDockerAvailable()) {
      const rmFlag = deleteVolumes ? '-fv' : '-f';
      for (const name of this.allContainerNames(record)) {
        try {
          await this.docker(['rm', rmFlag, name], { timeout: 90000 });
          removed.containers.push(name);
        } catch (e) {}
      }
    }

    if (record.databaseId) {
      try {
        await getDbManager().remove(record.databaseId, { deleteVolume: deleteVolumes, deleteBackups });
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
    }
    // Los ficheros de configuración se regeneran desde la plantilla: limpiarlos siempre para no dejar huérfanos.
    try { fs.rmSync(path.join(this.filesRoot, record.id), { recursive: true, force: true }); } catch (e) {}
    if (deleteBackups) {
      try { fs.rmSync(path.join(this.backupsRoot, record.id), { recursive: true, force: true }); } catch (e) {}
    }

    if (await this.isDockerAvailable()) {
      try {
        await this.docker(['network', 'rm', record.networkName], { timeout: 20000 });
        removed.network = record.networkName;
      } catch (e) {}
    }

    if (record.domainId) {
      try {
        await getDomainManager().deleteDomain(record.domainId);
        removed.domain = record.domain;
      } catch (e) {}
      try { await getIngressManager().reconcile(); } catch (e) {}
    }

    // Liberar reservas de puertos principales y extraPorts en portRegistry
    portRegistry.releaseOwner(record.id);
    for (const [cPort, hPort] of Object.entries(record.extraPorts || {})) {
      this.pendingPorts.delete(Number(hPort));
      portRegistry.release(Number(hPort), `svc_ep_${record.id}_${cPort}`);
    }
    this.pendingPorts.delete(record.hostPort);

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
    const catalogImage = tpl ? tpl.app.image : record.image;
    return {
      id: record.id,
      templateId: record.templateId,
      templateName: record.templateName || (tpl ? tpl.name : record.templateId),
      name: record.name,
      category: record.category,
      categoryLabel: CATEGORY_MAP.get(record.category) || record.category,
      image: record.image,
      catalogImage,
      updateAvailable: Boolean(tpl && tpl.app.image !== record.image),
      domain: record.domain,
      url: record.url,
      hostPort: record.hostPort,
      appPort: record.appPort,
      extraPorts: record.extraPorts || {},
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
      try { out.database = getDbManager().getCredentials(record.databaseId); } catch (e) {}
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
  orderSidecars,
  parseImageRef,
  resolveCoupledSidecarImage,
  defaultTimezone,
  BACKUP_IMAGE,
  STEPS,
  PORT_RANGE: { start: PORT_RANGE_START, end: PORT_RANGE_END }
});

module.exports = catalogManager;
