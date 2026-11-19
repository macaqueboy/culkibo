const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const EventEmitter = require('events');
const { execFile, spawn } = require('child_process');
const util = require('util');
const execFilePromise = util.promisify(execFile);

const dbBackupManager = require('./dbBackupManager');
const { S3Client, redactKey } = require('./s3Uploader');

/**
 * Bases de datos gestionadas: aprovisionamiento en un clic, copias programadas,
 * subida a S3/R2, restauración y retención.
 *
 * El modelo de amenaza que guía todo este fichero es concreto, no teórico:
 *
 *  1. Dokploy publicó durante meses la MISMA contraseña de Postgres en todas
 *     las instalaciones del mundo, sobre una red overlay plana compartida
 *     (Dokploy/dokploy#3449). Aquí cada base de datos genera su propia
 *     contraseña con `crypto.randomBytes` y vive en la red del proyecto, no en
 *     una red común.
 *  2. Publicar el puerto es la otra mitad del desastre: en Linux, `-p 5432:5432`
 *     escribe en la cadena DOCKER de iptables, que se evalúa ANTES que UFW, así
 *     que el "firewall activo" del usuario no protege nada. Exponer es aquí una
 *     decisión explícita, con aviso, y por defecto sólo a 127.0.0.1.
 *  3. Los secretos no aparecen en `ps`. Ni al crear el contenedor (`--env-file`
 *     temporal con permisos 0600, nunca `-e CLAVE=valor`) ni al volcar
 *     (`docker exec` sin `-e`, apoyándonos en variables ya presentes DENTRO del
 *     contenedor). Ver `provision()` y `runBackup()`.
 *  4. Nunca se construye una cadena de shell. Todo va por `execFile`/`spawn`
 *     con argv, igual que `dbBackupManager.buildDbDumpSpec`.
 */

const DATA_FILE = path.join(__dirname, '..', '..', 'data', 'databases.json');
const KEY_FILE = path.join(__dirname, '..', '..', 'data', '.databases.key');
const BACKUPS_ROOT = path.join(__dirname, '..', '..', 'data', 'backups', 'databases');
const TMP_DIR = path.join(__dirname, '..', '..', 'data', '.tmp');

/** Cada cuánto despierta el planificador a mirar si toca alguna copia. */
const SCHEDULER_TICK_MS = 30000;
/** Una copia perdida por un daemon apagado se recupera si no ha caducado del todo. */
const MAX_CATCH_UP_MS = 7 * 24 * 3600 * 1000;

// ---------------------------------------------------------------------------
// Catálogo de motores
// ---------------------------------------------------------------------------

/**
 * Catálogo verificado contra la API del registro de Docker Hub y los
 * Dockerfile de docker-library el 15 de septiembre de 2026. Está aislado aquí
 * arriba a propósito: subir de major es cambiar una línea, no buscar por el
 * fichero.
 *
 * Decisiones que no son obvias:
 *
 *  - PostgreSQL 18 es la rama estable (19 sólo existe como beta3). Y OJO: 18
 *    movió PGDATA a `/var/lib/postgresql`; en 17 y anteriores era
 *    `/var/lib/postgresql/data`. Montar el volumen en el sitio de la versión
 *    anterior da un contenedor que arranca, parece sano y pierde los datos en
 *    el primer reinicio. De ahí `dataDirFor`.
 *  - MySQL 8.0 llegó a fin de vida el 30/04/2026. La LTS viva es la 9.7
 *    (`mysql:9`); `latest` apunta a la rama de innovación 26.x, que sólo tiene
 *    tres meses de soporte. No hay variante Alpine oficial.
 *  - MariaDB movió `lts` a 12.3. Es la única imagen de las cinco que trae su
 *    propio script de sonda (`healthcheck.sh`).
 *  - Valkey es el motor clave-valor por defecto y Redis queda como alternativa
 *    explícita. Redis 8 es AGPLv3 (o RSALv2, o SSPLv1); ejecutar un contenedor
 *    no crea obra derivada, así que no es una trampa legal para un
 *    orquestador, pero Valkey es BSD-3, está bajo la Linux Foundation, habla el
 *    mismo protocolo y ocupa la mitad. Elegir lo permisivo por defecto y dejar
 *    lo otro a un clic es lo correcto en un producto Apache-2.0.
 *  - MongoDB se fija en 8.0 y no en 8.3: las dos caducan el 31/10/2029, pero
 *    8.0 lleva dos años en producción. Sigue bajo SSPL, que no es OSI; mismo
 *    razonamiento que con Redis, y por eso se muestra la licencia en la
 *    interfaz.
 *  - NINGUNA de estas imágenes trae instrucción HEALTHCHECK propia: si no la
 *    inyectamos nosotros, `docker ps` dice "Up" de un motor que aún no acepta
 *    conexiones. Por eso `health` es obligatorio en cada entrada.
 *
 * `clientEnv` es la pieza no evidente: además de la variable que el entrypoint
 * usa para inicializar el motor, inyectamos la variable que la herramienta de
 * volcado lee (PGPASSWORD, MYSQL_PWD, REDISCLI_AUTH). Así el backup se ejecuta
 * con `docker exec` SIN pasar `-e CLAVE=valor`, que dejaría el secreto en la
 * línea de comandos del proceso `docker` del host, visible en `ps` para
 * cualquier usuario de la máquina.
 */
/**
 * Envoltorio para la familia MySQL. Traduce `CULKIBO_MYSQL_PWD` a `MYSQL_PWD`
 * justo en el momento de ejecutar la herramienta.
 *
 * Por qué hace falta el rodeo, en vez de poner `MYSQL_PWD` directamente en el
 * entorno del contenedor como hacemos con `PGPASSWORD`: la prueba contra Docker
 * real lo destapó. Durante la inicialización, el entrypoint de MySQL levanta un
 * servidor temporal cuyo root AÚN NO tiene contraseña y ejecuta su propio SQL
 * con el cliente `mysql`; ese cliente hereda `MYSQL_PWD` del entorno, envía una
 * contraseña que el servidor recién nacido no espera y falla con «Access denied
 * ... (using password: YES)». El entrypoint se traga el error, el contenedor
 * llega a "healthy" y queda una base de datos SIN el usuario ni la contraseña
 * que pediste. Exactamente la clase de fallo silencioso que hay que evitar.
 *
 * La cadena es CONSTANTE. El programa y sus argumentos llegan como parámetros
 * posicionales detrás del nombre del script y se expanden con `"$@"`, así que
 * ningún dato del usuario entra en el texto del shell: no hay nada que inyectar.
 */
const MYSQL_PWD_WRAPPER = 'MYSQL_PWD="$CULKIBO_MYSQL_PWD" exec "$@"';

const ENGINES = {
  postgres: {
    label: 'PostgreSQL',
    family: 'postgresql',
    image: 'postgres:18-alpine',
    port: 5432,
    scheme: 'postgresql',
    dataDir: '/var/lib/postgresql',
    // PG 18 movió PGDATA. Si alguien fija una imagen anterior, el volumen tiene
    // que ir al sitio que esa versión espera.
    dataDirFor: (image) => {
      const m = /:(\d+)/.exec(String(image || ''));
      const major = m ? parseInt(m[1], 10) : 18;
      return major >= 18 ? '/var/lib/postgresql' : '/var/lib/postgresql/data';
    },
    licence: 'PostgreSQL License (permisiva)',
    initEnv: ({ username, password, dbName }) => ({
      POSTGRES_USER: username,
      POSTGRES_PASSWORD: password,
      POSTGRES_DB: dbName
    }),
    clientEnv: ({ password }) => ({ PGPASSWORD: password }),
    // `-h 127.0.0.1` a propósito: durante la inicialización el entrypoint
    // levanta un servidor temporal que sólo escucha en el socket local, y un
    // `pg_isready` sin host lo daría por sano antes de que el servidor de
    // verdad acepte TCP.
    health: ({ username, dbName }) => `pg_isready -h 127.0.0.1 -U ${username} -d ${dbName}`,
    dumpExt: '.dump',
    restore: ({ username, dbName, inFile }) => ({
      program: 'pg_restore',
      args: ['-U', username, '-d', dbName, '--clean', '--if-exists', '--no-owner', inFile]
    })
  },

  mysql: {
    label: 'MySQL',
    family: 'mysql',
    image: 'mysql:9',
    port: 3306,
    scheme: 'mysql',
    dataDir: '/var/lib/mysql',
    licence: 'GPLv2',
    initEnv: ({ username, password, dbName }) => ({
      MYSQL_ROOT_PASSWORD: password,
      MYSQL_DATABASE: dbName,
      MYSQL_USER: username,
      MYSQL_PASSWORD: password
    }),
    clientEnv: ({ password }) => ({ CULKIBO_MYSQL_PWD: password }),
    dumpWrapper: MYSQL_PWD_WRAPPER,
    dumpUser: 'root',
    // MySQL 9 trae GTID activado, así que mysqldump escribe en la cabecera un
    // `SET @@GLOBAL.GTID_PURGED=...`. Al restaurar sobre el mismo servidor eso
    // falla con «GTID_PURGED cannot be changed: the added gtid set must not
    // overlap with GTID_EXECUTED» y la restauración muere a mitad, con la base
    // de datos ya parcialmente borrada por el `--clean`. mariadb-dump no
    // reconoce esta opción, por eso está aquí y no en el catálogo común.
    dumpExtraArgs: ['--set-gtid-purged=OFF'],
    // Sin credenciales: `mysqladmin ping` sale con 0 incluso si el acceso es
    // denegado, porque el servidor ha respondido, que es justo la semántica de
    // "está vivo". Pasarle `-p<clave>` metería el secreto en `ps`.
    health: () => 'mysqladmin ping -h 127.0.0.1 --silent',
    dumpExt: '.sql',
    restore: ({ dbName, inFile }) => ({
      program: 'mysql',
      args: ['-u', 'root', dbName],
      stdinFile: inFile
    })
  },

  mariadb: {
    label: 'MariaDB',
    family: 'mariadb',
    image: 'mariadb:12.3',
    port: 3306,
    scheme: 'mysql',
    dataDir: '/var/lib/mysql',
    licence: 'GPLv2',
    initEnv: ({ username, password, dbName }) => ({
      MARIADB_ROOT_PASSWORD: password,
      MARIADB_DATABASE: dbName,
      MARIADB_USER: username,
      MARIADB_PASSWORD: password
    }),
    clientEnv: ({ password }) => ({ CULKIBO_MYSQL_PWD: password }),
    dumpWrapper: MYSQL_PWD_WRAPPER,
    dumpUser: 'root',
    health: () => 'healthcheck.sh --su-mysql --connect --innodb_initialized',
    // MariaDB 12 ya no instala los enlaces de compatibilidad `mysqldump` y
    // `mysql`: sólo existen `mariadb-dump` y `mariadb`. Verificado dentro de la
    // imagen mariadb:12.3 (`command -v mysqldump` -> no existe).
    dumpProgram: 'mariadb-dump',
    dumpExt: '.sql',
    restore: ({ dbName, inFile }) => ({
      program: 'mariadb',
      args: ['-u', 'root', dbName],
      stdinFile: inFile
    })
  },

  valkey: {
    label: 'Valkey',
    family: 'redis',
    image: 'valkey/valkey:9-alpine',
    port: 6379,
    scheme: 'redis',
    dataDir: '/data',
    licence: 'BSD-3-Clause',
    noDatabaseName: true,
    initEnv: ({ password }) => ({ VALKEY_PASSWORD: password, REDISCLI_AUTH: password, VALKEYCLI_AUTH: password }),
    clientEnv: ({ password }) => ({ REDISCLI_AUTH: password, VALKEYCLI_AUTH: password }),
    command: () => REDIS_FAMILY_COMMAND('valkey-server', 'VALKEY_PASSWORD'),
    health: () => 'valkey-cli ping',
    // buildDbDumpSpec habla de `redis-cli`; en la imagen de Valkey el binario
    // se llama `valkey-cli` y el enlace de compatibilidad no está garantizado.
    dumpProgram: 'valkey-cli',
    dumpExt: '.rdb'
  },

  redis: {
    label: 'Redis',
    family: 'redis',
    image: 'redis:8-alpine',
    port: 6379,
    scheme: 'redis',
    dataDir: '/data',
    licence: 'AGPLv3 / RSALv2 / SSPLv1 (desde Redis 8)',
    noDatabaseName: true,
    initEnv: ({ password }) => ({ REDIS_PASSWORD: password, REDISCLI_AUTH: password }),
    clientEnv: ({ password }) => ({ REDISCLI_AUTH: password }),
    command: () => REDIS_FAMILY_COMMAND('redis-server', 'REDIS_PASSWORD'),
    health: () => 'redis-cli ping',
    dumpExt: '.rdb'
  },

  mongodb: {
    label: 'MongoDB',
    family: 'mongodb',
    image: 'mongo:8.0',
    port: 27017,
    scheme: 'mongodb',
    dataDir: '/data/db',
    licence: 'SSPL (no aprobada por la OSI)',
    initEnv: ({ username, password, dbName }) => ({
      MONGO_INITDB_ROOT_USERNAME: username,
      MONGO_INITDB_ROOT_PASSWORD: password,
      MONGO_INITDB_DATABASE: dbName
    }),
    // mongodump no lee ninguna variable de entorno para la contraseña. En vez
    // de pasarla por argv la escribimos en un fichero YAML que copiamos al
    // contenedor y borramos al terminar. Ver `runBackup()`.
    clientEnv: () => ({}),
    usesConfigFile: true,
    // Sin esto mongodump se autentica contra la base de datos que va a volcar,
    // pero el usuario raíz que crea el entrypoint vive en `admin`, así que la
    // copia falla con «Authentication failed» pese a tener la contraseña bien.
    dumpExtraArgs: ['--authenticationDatabase=admin'],
    // `ping` se puede ejecutar antes de autenticarse, así que la sonda no
    // necesita credenciales ni siquiera con auth activada.
    health: () => "mongosh --quiet --eval \"db.adminCommand('ping').ok\"",
    dumpExt: '.archive.gz'
  }
};

/**
 * Redis y Valkey son las únicas imágenes sin variable de entorno para la
 * contraseña: sólo aceptan `--requirepass <secreto>` en la línea de comandos.
 * Escribirlo en el `docker run` dejaría el secreto en el argv del proceso
 * `docker` del HOST, que es exactamente lo que este módulo evita.
 *
 * La salida es una cadena de shell — pero CONSTANTE y sin una sola
 * interpolación: el secreto entra por el `--env-file` y lo expande la shell de
 * dentro del contenedor, entrecomillado, así que ni siquiera una contraseña
 * con metacaracteres podría hacer nada. No hay ningún dato del usuario en esta
 * cadena; si lo hubiera, esto sería un fallo de inyección y no un comentario.
 *
 * Persistencia por RDB con puntos de guardado explícitos, y NO por AOF.
 * No es pereza, es una restricción real que descubrió la prueba contra Docker:
 * con `--appendonly yes` el servidor carga el registro de escrituras y no el
 * `dump.rdb`, así que restaurar sustituyendo el fichero no restaura nada. Y
 * borrar el `appendonlydir` tampoco vale: Valkey 9 no cae entonces al RDB, crea
 * un AOF base VACÍO ("Creating AOF base file ... on server start" con la base
 * de datos a cero). El procedimiento oficial para volver a un RDB con AOF
 * activo exige arrancar con AOF desactivado y reactivarlo después, es decir dos
 * recreaciones del contenedor por restauración. Para un producto cuyo modelo de
 * durabilidad son las copias externas programadas, RDB + esas copias es lo
 * coherente: una restauración que funciona de verdad vale más que un segundo
 * extra de durabilidad ante un corte eléctrico.
 */
function REDIS_FAMILY_COMMAND(server, envVar) {
  return [
    'sh', '-c',
    `exec ${server} --save 900 1 --save 300 10 --save 60 10000 --requirepass "$${envVar}"`
  ];
}

// ---------------------------------------------------------------------------
// Validación
// ---------------------------------------------------------------------------

/**
 * Los identificadores que acaban dentro de un nombre de contenedor, de volumen
 * o del `--health-cmd` (que Docker ejecuta con `CMD-SHELL` DENTRO del
 * contenedor) pasan por aquí. Lista blanca estricta: si no encaja, se rechaza.
 * No se escapa nada, no se sanea nada, se rechaza.
 */
const IDENTIFIER_RE = /^[a-z][a-z0-9_]{0,62}$/;
const RESOURCE_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

function assertIdentifier(value, field) {
  if (!IDENTIFIER_RE.test(String(value || ''))) {
    throw new Error(
      `${field} inválido: sólo minúsculas, dígitos y guion bajo, empezando por letra (máx. 63 caracteres)`
    );
  }
  return String(value);
}

function assertResourceId(value, field) {
  if (!RESOURCE_ID_RE.test(String(value || ''))) {
    throw new Error(`${field} inválido`);
  }
  return String(value);
}

// ---------------------------------------------------------------------------
// Cifrado en reposo
// ---------------------------------------------------------------------------

/**
 * Las contraseñas no se guardan en claro en `databases.json`.
 *
 * Esto no protege contra alguien con root en el host —nada lo hace, la clave
 * está al lado— pero sí contra el fallo real y frecuente: `databases.json`
 * acaba en un `tar` de soporte, en un repositorio o en una captura de pantalla.
 * Coolify guarda las credenciales en claro en su base de datos y es
 * exactamente así como se filtran.
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
  if (parts.length !== 4 || parts[0] !== 'v1') {
    // Compatibilidad hacia atrás con registros escritos antes del cifrado.
    return String(blob || '');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[1], 'base64'));
  decipher.setAuthTag(Buffer.from(parts[2], 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
}

/**
 * Contraseña de 32 caracteres del alfabeto base64url.
 *
 * base64url (`A-Za-z0-9-_`) y no base64 a secas: `+`, `/` y `=` obligan a
 * codificar la contraseña al meterla en una URI de conexión, y la mitad de las
 * bibliotecas cliente del mundo se equivocan al hacerlo. Con este alfabeto la
 * cadena `postgresql://u:PASS@host/db` es correcta sin escapar nada.
 * 24 bytes de `randomBytes` = 192 bits de entropía.
 */
function generatePassword() {
  return crypto.randomBytes(24).toString('base64url');
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

const CRON_ALIASES = {
  '@hourly': '0 * * * *',
  '@daily': '0 3 * * *',
  '@midnight': '0 0 * * *',
  '@weekly': '0 4 * * 0',
  '@monthly': '0 5 1 * *'
};

const CRON_FIELDS = [
  { name: 'minuto', min: 0, max: 59 },
  { name: 'hora', min: 0, max: 23 },
  { name: 'día del mes', min: 1, max: 31 },
  { name: 'mes', min: 1, max: 12 },
  { name: 'día de la semana', min: 0, max: 7 }
];

// ---------------------------------------------------------------------------

class DatabaseManager extends EventEmitter {
  constructor() {
    super();
    /** @type {{ version: number, databases: any[], s3: any }} */
    this.state = { version: 1, databases: [], s3: null };
    /** @type {Buffer | null} */
    this.key = null;
    /** @type {ReturnType<typeof setInterval> | null} */
    this.schedulerTimer = null;
    /** @type {Set<string>} */
    this.runningBackups = new Set();
    /** @type {any} */
    this.dockerChecked = null;
    this.ensureDirs();
    this.load();
  }

  ensureDirs() {
    for (const dir of [path.dirname(DATA_FILE), BACKUPS_ROOT, TMP_DIR]) {
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
        if (parsed && Array.isArray(parsed.databases)) {
          // Normalizamos al cargar: un registro escrito por una versión
          // anterior no puede hacer que `toPublic()` o el planificador revienten
          // al leer una propiedad que entonces no existía.
          this.state = {
            version: 1,
            s3: parsed.s3 || null,
            databases: parsed.databases.map((d) => ({
              backups: [],
              exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
              retention: { daily: 7, weekly: 4 },
              ...d,
              schedule: {
                enabled: false, cron: '0 3 * * *', nextRunAt: null, lastRunAt: null, lastStatus: null,
                ...(d.schedule || {})
              }
            }))
          };
        }
      }
    } catch (err) {
      console.error('[Databases] No se pudo leer databases.json:', err.message);
    }
  }

  save() {
    try {
      const tmp = `${DATA_FILE}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmp, DATA_FILE);
      try { fs.chmodSync(DATA_FILE, 0o600); } catch (e) {}
    } catch (err) {
      console.error('[Databases] No se pudo guardar databases.json:', err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Catálogo
  // -------------------------------------------------------------------------

  listEngines() {
    return Object.entries(ENGINES).map(([key, e]) => ({
      engine: key,
      label: e.label,
      image: e.image,
      port: e.port,
      licence: e.licence,
      requiresDatabaseName: !e.noDatabaseName
    }));
  }

  // -------------------------------------------------------------------------
  // Docker (siempre argv, nunca cadena de shell)
  // -------------------------------------------------------------------------

  /**
   * @param {string[]} args
   * @param {{ env?: Record<string, string> | null, timeout?: number, input?: any, inputFile?: string | null }} [opts]
   */
  async docker(args, { env = null, timeout = 60000, input = null, inputFile = null } = {}) {
    if (!Array.isArray(args)) throw new Error('Los argumentos de docker deben ser un array');

    if (!input && !inputFile) {
      const { stdout, stderr } = await execFilePromise('docker', args, {
        timeout,
        maxBuffer: 32 * 1024 * 1024,
        env: env ? { ...process.env, ...env } : process.env,
        windowsHide: true
      });
      return { stdout: stdout || '', stderr: stderr || '' };
    }

    // Con stdin hace falta spawn. Se usa para restaurar volcados SQL sin
    // redirección de shell: el fichero se canaliza al proceso hijo desde Node.
    return new Promise((resolve, reject) => {
      const child = spawn('docker', args, {
        env: env ? { ...process.env, ...env } : process.env,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += d.toString(); });
      child.stderr.on('data', (d) => { stderr += d.toString(); });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code === 0) resolve({ stdout, stderr });
        else reject(new Error(`docker ${args[0]} salió con código ${code}: ${stderr.slice(0, 500)}`));
      });
      if (inputFile) {
        fs.createReadStream(inputFile).pipe(child.stdin).on('error', reject);
      } else {
        child.stdin.end(input);
      }
    });
  }

  async isDockerAvailable(force = false) {
    if (!force && this.dockerChecked && Date.now() - this.dockerChecked.at < 15000) {
      return this.dockerChecked.ok;
    }
    let ok = false;
    let reason = '';
    try {
      await execFilePromise('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 5000, windowsHide: true });
      ok = true;
    } catch (err) {
      reason = err.message;
    }
    this.dockerChecked = { at: Date.now(), ok, reason };
    return ok;
  }

  async dockerStatus() {
    const ok = await this.isDockerAvailable(true);
    return {
      available: ok,
      reason: ok ? null : 'El daemon de Docker no responde. Las bases de datos gestionadas lo necesitan.'
    };
  }

  // -------------------------------------------------------------------------
  // Aprovisionamiento
  // -------------------------------------------------------------------------

  containerName(id) { return `culkibo_db_${id}`; }
  volumeName(id) { return `culkibo_dbdata_${id}`; }
  networkName(projectId) { return `culkibo_net_${projectId}`; }

  /** El directorio de datos puede depender de la versión (ver PostgreSQL 18). */
  resolveDataDir(engine, image) {
    return engine.dataDirFor ? engine.dataDirFor(image) : engine.dataDir;
  }

  /**
   * Una red bridge por proyecto.
   *
   * Es la diferencia concreta con el fallo de Dokploy: allí todos los servicios
   * de todos los proyectos compartían una overlay plana, así que cualquier
   * contenedor comprometido veía todas las bases de datos del host. Una red por
   * proyecto significa que un contenedor sólo alcanza lo que hay en su propio
   * proyecto, y que la resolución por nombre no filtra nombres ajenos.
   */
  async ensureNetwork(projectId) {
    assertResourceId(projectId, 'projectId');
    const name = this.networkName(projectId);
    try {
      await this.docker(['network', 'inspect', name], { timeout: 10000 });
      return { name, created: false };
    } catch (e) {
      await this.docker(['network', 'create', '--driver', 'bridge', '--label', 'culkibo.managed=true',
        '--label', `culkibo.project=${projectId}`, name], { timeout: 20000 });
      return { name, created: true };
    }
  }

  /**
   * Crea una base de datos gestionada.
   *
   * @param {{
   *   projectId?: string,
   *   engine?: string,
   *   name?: string,
   *   dbName?: string,
   *   username?: string,
   *   image?: string,
   *   memoryMb?: number | string,
   *   cpus?: number | string
   * }} [opts]
   */
  async provision(opts = {}) {
    const engineKey = String(opts.engine || '').toLowerCase();
    const engine = ENGINES[engineKey];
    if (!engine) {
      throw new Error(`Motor no soportado: ${opts.engine}. Disponibles: ${Object.keys(ENGINES).join(', ')}`);
    }

    const projectId = assertResourceId(opts.projectId, 'projectId');
    const username = assertIdentifier(opts.username || 'culkibo', 'Usuario');
    const dbName = engine.noDatabaseName ? null : assertIdentifier(opts.dbName || 'app', 'Nombre de la base de datos');

    if (opts.image !== undefined && opts.image !== null && opts.image !== '') {
      // Referencia de imagen: registro/espacio/nombre:etiqueta. Lista blanca.
      if (!/^[a-z0-9][a-z0-9._\-/]{0,190}(:[a-zA-Z0-9._-]{1,128})?$/.test(String(opts.image))) {
        throw new Error('Referencia de imagen inválida');
      }
    }

    const id = `db_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const password = generatePassword();
    const memoryMb = Math.max(128, Math.min(65536, parseInt(String(opts.memoryMb ?? ''), 10) || 512));
    const cpus = Math.max(0.1, Math.min(32, Number(opts.cpus) || 1));

    const record = {
      id,
      projectId,
      engine: engineKey,
      family: engine.family,
      name: String(opts.name || `${engine.label} ${engineKey}`).slice(0, 80),
      image: opts.image || engine.image,
      username,
      dbName,
      passwordEnc: encryptSecret(password, this.cryptoKey),
      port: engine.port,
      containerName: this.containerName(id),
      volumeName: this.volumeName(id),
      networkName: this.networkName(projectId),
      // Se congela al crear: si mañana cambiamos el resolutor, un contenedor ya
      // existente debe seguir montando su volumen donde ya tiene los datos.
      dataDir: this.resolveDataDir(engine, opts.image || engine.image),
      memoryMb,
      cpus,
      // Nunca expuesto al arrancar. Exponer es una decisión posterior y explícita.
      exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
      status: 'provisioning',
      health: 'unknown',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      schedule: { enabled: false, cron: '0 3 * * *', nextRunAt: null, lastRunAt: null, lastStatus: null },
      retention: { daily: 7, weekly: 4 },
      backups: []
    };

    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible: no se puede aprovisionar una base de datos gestionada');
    }

    await this.ensureNetwork(projectId);

    // -- Secretos: fichero de entorno temporal 0600, nunca `-e CLAVE=valor` ---
    //
    // `docker run -e POSTGRES_PASSWORD=<secreto>` deja el secreto en el argv
    // del proceso `docker` del host, y cualquier usuario local lo lee con `ps`.
    // La alternativa `-e POSTGRES_PASSWORD` (sólo el nombre, heredando del
    // entorno del cliente) tiene un modo de fallo intolerable: si la variable
    // no está definida, algunas versiones del CLI pasan el valor vacío en vez
    // de fallar, y el resultado es una base de datos SIN contraseña. Con
    // --env-file el valor o está o docker aborta.
    const envVars = {
      ...engine.initEnv({ username, password, dbName }),
      ...engine.clientEnv({ password })
    };
    const envFile = path.join(TMP_DIR, `env_${id}_${crypto.randomBytes(6).toString('hex')}`);

    const args = [
      'run', '-d',
      '--name', record.containerName,
      '--restart', 'unless-stopped',
      '--network', record.networkName,
      // Alias corto para que las apps del proyecto se conecten por nombre.
      '--network-alias', engineKey,
      '-v', `${record.volumeName}:${record.dataDir}`,
      '--env-file', envFile,
      // Límites: una base de datos que se come el host tumba el orquestador.
      '--memory', `${memoryMb}m`,
      // memory-swap igual a memory desactiva el swap: sin esto el límite de
      // memoria no limita nada, sólo empuja al contenedor al disco.
      '--memory-swap', `${memoryMb}m`,
      '--cpus', String(cpus),
      '--pids-limit', '512',
      '--security-opt', 'no-new-privileges',
      '--health-cmd', engine.health({ username, dbName }),
      '--health-interval', '10s',
      '--health-timeout', '5s',
      '--health-retries', '5',
      '--health-start-period', '40s',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${projectId}`,
      '--label', `culkibo.database=${id}`,
      '--label', `culkibo.engine=${engineKey}`,
      record.image,
      // Redis/Valkey necesitan argumentos de arranque; el resto usa el CMD de
      // la imagen. Ver REDIS_FAMILY_COMMAND.
      ...(engine.command ? engine.command() : [])
    ];

    try {
      fs.writeFileSync(
        envFile,
        Object.entries(envVars).map(([k, v]) => `${k}=${v}`).join('\n') + '\n',
        { encoding: 'utf8', mode: 0o600 }
      );
      const { stdout } = await this.docker(args, { timeout: 180000 });
      record.containerId = stdout.trim().slice(0, 64);
      record.status = 'running';
    } catch (err) {
      record.status = 'error';
      record.lastError = this.redactMessage(err.message, password);
      throw new Error(`No se pudo crear el contenedor: ${record.lastError}`);
    } finally {
      // El fichero con el secreto vive lo que tarda docker en leerlo.
      try { fs.unlinkSync(envFile); } catch (e) {}
    }

    this.state.databases.push(record);
    this.save();
    this.emit('database_created', this.toPublic(record));

    return {
      ...this.toPublic(record),
      // La cadena de conexión se devuelve UNA vez, al crear. Después hay que
      // pedirla explícitamente en /credentials, que sí queda auditado.
      connectionString: this.buildConnectionString(record, password)
    };
  }

  // -------------------------------------------------------------------------
  // Exposición de puerto
  // -------------------------------------------------------------------------

  /**
   * Publicar el puerto en el host. Opt-in deliberado.
   *
   * `docker run -p` inserta reglas en la cadena DOCKER de iptables, que se
   * evalúa antes que INPUT y por tanto antes que UFW o firewalld. Un usuario
   * con "ufw deny 5432" activo y el puerto publicado en 0.0.0.0 tiene la base
   * de datos abierta a Internet y su firewall dice que no. Por eso el enlace
   * por defecto es 127.0.0.1 y abrir a 0.0.0.0 exige `acknowledgeRisk: true`.
   *
   * Docker no permite cambiar el mapeo de puertos de un contenedor existente,
   * así que se recrea conservando el volumen (los datos no se tocan).
   */
  /** @param {string} id @param {{ enabled?: boolean, hostPort?: number | null, bindAddress?: string, acknowledgeRisk?: boolean }} [opts] */
  async setExposure(id, { enabled = false, hostPort = null, bindAddress = '127.0.0.1', acknowledgeRisk = false } = {}) {
    const record = this.mustGet(id);
    const engine = ENGINES[record.engine];

    if (!enabled) {
      record.exposure = { enabled: false, bindAddress: '127.0.0.1', hostPort: null };
      await this.recreateContainer(record);
      this.save();
      return { ...this.toPublic(record), warning: null };
    }

    const bind = String(bindAddress || '127.0.0.1');
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(bind)) {
      throw new Error('Dirección de enlace inválida: use una IPv4 (127.0.0.1 para sólo local)');
    }
    const port = parseInt(String(hostPort ?? ''), 10) || engine.port;
    if (!(port > 0 && port < 65536)) throw new Error('Puerto de host inválido');

    const publicBind = bind === '0.0.0.0';
    if (publicBind && acknowledgeRisk !== true) {
      throw new Error(
        'Publicar en 0.0.0.0 expone la base de datos a toda la red y las reglas de Docker se ' +
        'saltan UFW/firewalld. Repita la operación con acknowledgeRisk: true si es lo que quiere.'
      );
    }

    const taken = this.state.databases.find(
      (d) => d.id !== id && d.exposure && d.exposure.enabled && d.exposure.hostPort === port
    );
    if (taken) throw new Error(`El puerto ${port} ya lo usa otra base de datos gestionada`);

    record.exposure = { enabled: true, bindAddress: bind, hostPort: port };
    await this.recreateContainer(record);
    this.save();

    return {
      ...this.toPublic(record),
      warning: publicBind
        ? `La base de datos ${record.name} está accesible en ${bind}:${port} desde cualquier origen que ` +
          'alcance este host. Docker publica el puerto por debajo de UFW: su cortafuegos NO la protege. ' +
          'Restrinja el acceso en el proveedor de red o vuelva a 127.0.0.1.'
        : `Accesible sólo desde este host en 127.0.0.1:${port}. Para acceso remoto use un túnel SSH.`
    };
  }

  /**
   * Recrea el contenedor conservando volumen y contraseña. Se usa al cambiar
   * la exposición o los límites, que Docker no deja modificar en caliente.
   */
  async recreateContainer(record) {
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible');
    }
    const engine = ENGINES[record.engine];
    const password = this.decryptPassword(record);

    try { await this.docker(['rm', '-f', record.containerName], { timeout: 60000 }); } catch (e) {}

    const envVars = {
      ...engine.initEnv({ username: record.username, password, dbName: record.dbName }),
      ...engine.clientEnv({ password })
    };
    const envFile = path.join(TMP_DIR, `env_${record.id}_${crypto.randomBytes(6).toString('hex')}`);

    const args = [
      'run', '-d',
      '--name', record.containerName,
      '--restart', 'unless-stopped',
      '--network', record.networkName,
      '--network-alias', record.engine,
      '-v', `${record.volumeName}:${record.dataDir || this.resolveDataDir(engine, record.image)}`,
      '--env-file', envFile,
      '--memory', `${record.memoryMb}m`,
      '--memory-swap', `${record.memoryMb}m`,
      '--cpus', String(record.cpus),
      '--pids-limit', '512',
      '--security-opt', 'no-new-privileges',
      '--health-cmd', engine.health({ username: record.username, dbName: record.dbName }),
      '--health-interval', '10s',
      '--health-timeout', '5s',
      '--health-retries', '5',
      '--health-start-period', '40s',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${record.projectId}`,
      '--label', `culkibo.database=${record.id}`
    ];

    if (record.exposure && record.exposure.enabled) {
      args.push('-p', `${record.exposure.bindAddress}:${record.exposure.hostPort}:${engine.port}`);
    }
    args.push(record.image, ...(engine.command ? engine.command() : []));

    try {
      fs.writeFileSync(
        envFile,
        Object.entries(envVars).map(([k, v]) => `${k}=${v}`).join('\n') + '\n',
        { encoding: 'utf8', mode: 0o600 }
      );
      const { stdout } = await this.docker(args, { timeout: 180000 });
      record.containerId = stdout.trim().slice(0, 64);
      record.status = 'running';
      record.updatedAt = new Date().toISOString();
    } finally {
      try { fs.unlinkSync(envFile); } catch (e) {}
    }
    return record;
  }

  // -------------------------------------------------------------------------
  // Ciclo de vida
  // -------------------------------------------------------------------------

  mustGet(id) {
    const record = this.state.databases.find((d) => d.id === id);
    if (!record) throw new Error(`Base de datos ${id} no encontrada`);
    return record;
  }

  decryptPassword(record) {
    return decryptSecret(record.passwordEnc, this.cryptoKey);
  }

  async start(id) {
    const record = this.mustGet(id);
    await this.docker(['start', record.containerName], { timeout: 60000 });
    record.status = 'running';
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  async stop(id) {
    const record = this.mustGet(id);
    await this.docker(['stop', record.containerName], { timeout: 90000 });
    record.status = 'stopped';
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  async restart(id) {
    const record = this.mustGet(id);
    await this.docker(['restart', record.containerName], { timeout: 120000 });
    record.status = 'running';
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  /**
   * Elimina el contenedor. El volumen sólo se borra si se pide explícitamente:
   * un clic de más no puede destruir los datos de producción de nadie.
   */
  async remove(id, { deleteVolume = false, deleteBackups = false } = {}) {
    const record = this.mustGet(id);
    if (await this.isDockerAvailable()) {
      try { await this.docker(['rm', '-f', record.containerName], { timeout: 90000 }); } catch (e) {}
      if (deleteVolume) {
        try { await this.docker(['volume', 'rm', record.volumeName], { timeout: 30000 }); } catch (e) {}
      }
    }
    if (deleteBackups) {
      try { fs.rmSync(path.join(BACKUPS_ROOT, record.id), { recursive: true, force: true }); } catch (e) {}
    }
    this.state.databases = this.state.databases.filter((d) => d.id !== id);
    this.save();
    this.emit('database_deleted', { id, volumeDeleted: deleteVolume });
    return { success: true, id, volumeDeleted: deleteVolume, backupsDeleted: deleteBackups };
  }

  async refreshHealth(id) {
    const record = this.mustGet(id);
    if (!(await this.isDockerAvailable())) {
      record.health = 'unknown';
      return this.toPublic(record);
    }
    try {
      const { stdout } = await this.docker(
        ['inspect', '--format', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', record.containerName],
        { timeout: 10000 }
      );
      const [status, health] = stdout.trim().split('|');
      record.status = status === 'running' ? 'running' : status;
      record.health = health === 'none' ? 'unknown' : health;
    } catch (err) {
      record.status = 'missing';
      record.health = 'unknown';
    }
    record.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublic(record);
  }

  // -------------------------------------------------------------------------
  // Vistas
  // -------------------------------------------------------------------------

  /**
   * Proyección pública. NUNCA incluye contraseña, cadena de conexión ni las
   * claves S3. Es lo que devuelven todos los endpoints de listado.
   */
  toPublic(record) {
    return {
      id: record.id,
      projectId: record.projectId,
      engine: record.engine,
      engineLabel: (ENGINES[record.engine] || {}).label || record.engine,
      name: record.name,
      image: record.image,
      username: record.username,
      dbName: record.dbName,
      port: record.port,
      containerName: record.containerName,
      volumeName: record.volumeName,
      networkName: record.networkName,
      memoryMb: record.memoryMb,
      cpus: record.cpus,
      exposure: record.exposure,
      status: record.status,
      health: record.health,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      schedule: {
        enabled: record.schedule.enabled,
        cron: record.schedule.cron,
        nextRunAt: record.schedule.nextRunAt,
        lastRunAt: record.schedule.lastRunAt,
        lastStatus: record.schedule.lastStatus
      },
      retention: record.retention,
      backupsCount: (record.backups || []).length,
      // Plantilla sin secreto: útil en la interfaz sin filtrar nada.
      connectionTemplate: this.buildConnectionString(record, '********'),
      hasPassword: Boolean(record.passwordEnc)
    };
  }

  /** @param {{ projectId?: string | null }} [opts] */
  list({ projectId = null } = {}) {
    return this.state.databases
      .filter((d) => !projectId || d.projectId === projectId)
      .map((d) => this.toPublic(d));
  }

  get(id) {
    return this.toPublic(this.mustGet(id));
  }

  /**
   * Único punto del sistema que devuelve el secreto. Endpoint aparte,
   * deliberadamente incómodo de llamar por accidente.
   */
  getCredentials(id) {
    const record = this.mustGet(id);
    const password = this.decryptPassword(record);
    return {
      id: record.id,
      username: record.username,
      password,
      dbName: record.dbName,
      host: record.containerName,
      port: record.port,
      internalConnectionString: this.buildConnectionString(record, password),
      hostConnectionString:
        record.exposure && record.exposure.enabled
          ? this.buildConnectionString(record, password, {
              host: record.exposure.bindAddress,
              port: record.exposure.hostPort
            })
          : null
    };
  }

  buildConnectionString(record, password, override = {}) {
    const engine = ENGINES[record.engine] || {};
    const host = override.host || record.containerName;
    const port = override.port || record.port;
    // `generatePassword()` usa el alfabeto base64url, que ya es seguro en la
    // parte de credenciales de una URI. Codificamos igualmente por si alguien
    // restaura un registro antiguo con una contraseña puesta a mano.
    const pass = encodeURIComponent(password);

    switch (engine.family) {
      case 'redis':
        return `redis://:${pass}@${host}:${port}`;
      case 'mongodb':
        return `mongodb://${record.username}:${pass}@${host}:${port}/${record.dbName}?authSource=admin`;
      case 'mysql':
      case 'mariadb':
        return `mysql://${record.username}:${pass}@${host}:${port}/${record.dbName}`;
      case 'postgresql':
      default:
        return `postgresql://${record.username}:${pass}@${host}:${port}/${record.dbName}`;
    }
  }

  /** Quita del texto cualquier aparición literal del secreto antes de logear. */
  redactMessage(message, ...secrets) {
    let out = String(message || '');
    for (const s of secrets) {
      if (s && String(s).length >= 6) out = out.split(String(s)).join('********');
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Copias de seguridad
  // -------------------------------------------------------------------------

  backupDir(id) {
    const dir = path.join(BACKUPS_ROOT, id);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  /**
   * Argumentos de ejecución dentro del contenedor, con el envoltorio del motor
   * si lo necesita. El programa y sus argumentos van siempre como elementos
   * separados de argv, nunca concatenados en el texto del script.
   */
  wrapInContainer(engine, program, args) {
    if (!engine.dumpWrapper) return [program, ...args];
    // `sh -c <script> <$0> <$1...>`: el primer positional es el nombre del
    // script (convención) y el resto se expande con "$@" sin reinterpretarse.
    return ['sh', '-c', engine.dumpWrapper, 'culkibo', program, ...args];
  }

  /**
   * Ejecuta un volcado completo.
   *
   * Invariante central: el secreto no viaja en ningún argv del host.
   *  - Postgres/MySQL/MariaDB/Redis: la variable que lee la herramienta
   *    (PGPASSWORD, MYSQL_PWD, REDISCLI_AUTH) ya está DENTRO del contenedor
   *    desde que se creó, así que `docker exec` no necesita `-e` ninguno.
   *  - MongoDB: `mongodump` no lee ninguna variable, así que se le pasa un
   *    fichero de configuración YAML copiado al contenedor con `docker cp` y
   *    borrado justo después. Sigue sin haber secretos en `ps`.
   *
   * El `spec` de argumentos lo produce `dbBackupManager.buildDbDumpSpec`, que
   * ya devuelve argv + entorno y nunca una cadena de shell.
   */
  async runBackup(id, { trigger = 'manual' } = {}) {
    const record = this.mustGet(id);
    if (this.runningBackups.has(id)) {
      throw new Error('Ya hay una copia en curso para esta base de datos');
    }
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible: no se puede ejecutar la copia');
    }

    this.runningBackups.add(id);
    const startedAt = Date.now();
    const engine = ENGINES[record.engine];
    const password = this.decryptPassword(record);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseName = `${record.engine}_${record.id}_${stamp}${engine.dumpExt}`;
    const containerPath = `/tmp/${baseName}`;
    const localPath = path.join(this.backupDir(id), baseName);
    /** @type {string | null} */
    let configInContainer = null;

    try {
      const spec = dbBackupManager.buildDbDumpSpec(engine.family, {
        host: '127.0.0.1',
        port: engine.port,
        // La familia MySQL vuelca como root: el usuario de la aplicación sólo
        // tiene permisos sobre su propia base y `mysqldump` necesita además
        // RELOAD/FLUSH_TABLES, así que un volcado con el usuario normal falla a
        // mitad y deja un fichero incompleto. En PostgreSQL el usuario que crea
        // el entrypoint ya es superusuario, así que no hace falta distinguir.
        user: engine.dumpUser || record.username,
        password,
        dbName: record.dbName || 'app',
        outputFile: containerPath
      });

      let args = [...spec.args];

      // Las opciones extra van ANTES del último argumento: en la familia MySQL
      // el nombre de la base de datos es posicional y todo lo que va detrás se
      // interpreta como una lista de tablas.
      if (engine.dumpExtraArgs && engine.dumpExtraArgs.length) {
        args.splice(Math.max(0, args.length - 1), 0, ...engine.dumpExtraArgs);
      }

      if (engine.usesConfigFile) {
        // Quitamos el --password=... que buildDbDumpSpec marca como
        // `secretInArgs: true` y lo sustituimos por un fichero de configuración.
        args = args.filter((a) => !String(a).startsWith('--password='));
        const cfgLocal = path.join(TMP_DIR, `mongo_${record.id}_${crypto.randomBytes(6).toString('hex')}.yml`);
        configInContainer = `/tmp/.culkibo_${crypto.randomBytes(6).toString('hex')}.yml`;
        fs.writeFileSync(cfgLocal, `password: ${JSON.stringify(password)}\n`, { encoding: 'utf8', mode: 0o600 });
        try {
          await this.docker(['cp', cfgLocal, `${record.containerName}:${configInContainer}`], { timeout: 30000 });
        } finally {
          try { fs.unlinkSync(cfgLocal); } catch (e) {}
        }
        args = [`--config=${configInContainer}`, ...args];
      }

      // Sin `-e`: el entorno necesario ya está dentro del contenedor.
      const program = engine.dumpProgram || spec.program;
      await this.docker(
        ['exec', record.containerName, ...this.wrapInContainer(engine, program, args)],
        { timeout: 6 * 3600 * 1000 }
      );

      await this.docker(['cp', `${record.containerName}:${containerPath}`, localPath], { timeout: 3600 * 1000 });
      try {
        await this.docker(['exec', record.containerName, 'rm', '-f', containerPath], { timeout: 30000 });
      } catch (e) {}

      // mongodump ya sale comprimido con --gzip; el resto no.
      let finalPath = localPath;
      if (!baseName.endsWith('.gz')) {
        finalPath = `${localPath}.gz`;
        await this.gzipFile(localPath, finalPath);
        fs.unlinkSync(localPath);
      }

      const stat = fs.statSync(finalPath);
      /** @type {any} */
      const entry = {
        id: `bk_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
        fileName: path.basename(finalPath),
        sizeBytes: stat.size,
        sha256: await this.sha256File(finalPath),
        createdAt: new Date().toISOString(),
        trigger,
        durationMs: Date.now() - startedAt,
        remote: null
      };

      const s3 = this.s3ClientFor();
      if (s3) {
        const key = `${this.s3Prefix()}${record.projectId}/${record.id}/${entry.fileName}`;
        const uploaded = await s3.uploadFile(key, finalPath, { contentType: 'application/gzip' });
        entry.remote = { key, etag: uploaded.etag || null, multipart: Boolean(uploaded.multipart), uploadedAt: new Date().toISOString() };
      }

      record.backups.unshift(entry);
      record.schedule.lastRunAt = entry.createdAt;
      record.schedule.lastStatus = 'ok';
      this.save();

      const pruned = await this.applyRetention(id);
      this.emit('backup_completed', { databaseId: id, backupId: entry.id, trigger });

      return { success: true, backup: entry, pruned, remote: entry.remote ? entry.remote.key : null };
    } catch (err) {
      record.schedule.lastRunAt = new Date().toISOString();
      record.schedule.lastStatus = 'error';
      record.lastError = this.redactMessage(err.message, password);
      this.save();
      this.emit('backup_failed', { databaseId: id, error: record.lastError });
      throw new Error(`Copia fallida: ${record.lastError}`);
    } finally {
      if (configInContainer) {
        try {
          await this.docker(['exec', record.containerName, 'rm', '-f', configInContainer], { timeout: 15000 });
        } catch (e) {}
      }
      this.runningBackups.delete(id);
    }
  }

  gzipFile(src, dest) {
    return new Promise((resolve, reject) => {
      const rs = fs.createReadStream(src);
      const ws = fs.createWriteStream(dest);
      rs.on('error', reject);
      ws.on('error', reject);
      ws.on('finish', resolve);
      rs.pipe(zlib.createGzip({ level: 6 })).pipe(ws);
    });
  }

  gunzipFile(src, dest) {
    return new Promise((resolve, reject) => {
      const rs = fs.createReadStream(src);
      const ws = fs.createWriteStream(dest);
      rs.on('error', reject);
      ws.on('error', reject);
      ws.on('finish', resolve);
      rs.pipe(zlib.createGunzip()).pipe(ws);
    });
  }

  sha256File(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const rs = fs.createReadStream(filePath);
      rs.on('error', reject);
      rs.on('data', (d) => hash.update(d));
      rs.on('end', () => resolve(hash.digest('hex')));
    });
  }

  listBackups(id) {
    const record = this.mustGet(id);
    const dir = this.backupDir(id);
    return (record.backups || []).map((b) => ({
      ...b,
      localAvailable: fs.existsSync(path.join(dir, b.fileName)),
      remoteAvailable: Boolean(b.remote && b.remote.key)
    }));
  }

  // -------------------------------------------------------------------------
  // Restauración
  // -------------------------------------------------------------------------

  /**
   * Restaura desde una copia local o, si ya no está en disco, descargándola
   * primero del bucket. `backupId` identifica la entrada del historial;
   * `remoteKey` permite restaurar algo que no está en el historial (por
   * ejemplo, tras reinstalar el orquestador).
   */
  /** @param {string} id @param {{ backupId?: string | null, remoteKey?: string | null }} [opts] */
  async restore(id, { backupId = null, remoteKey = null } = {}) {
    const record = this.mustGet(id);
    const engine = ENGINES[record.engine];
    if (!(await this.isDockerAvailable())) throw new Error('Docker no está disponible');

    const dir = this.backupDir(id);
    /** @type {string | null} */
    let archivePath = null;
    let downloaded = false;

    if (backupId) {
      const entry = (record.backups || []).find((b) => b.id === backupId);
      if (!entry) throw new Error(`Copia ${backupId} no encontrada en el historial`);
      const candidate = path.join(dir, entry.fileName);
      if (fs.existsSync(candidate)) {
        archivePath = candidate;
        const actual = await this.sha256File(candidate);
        if (entry.sha256 && actual !== entry.sha256) {
          throw new Error('La copia local no coincide con su sha256: fichero corrupto, no se restaura');
        }
      } else if (entry.remote && entry.remote.key) {
        const s3 = this.s3ClientFor();
        if (!s3) throw new Error('La copia sólo existe en remoto y no hay S3 configurado');
        archivePath = path.join(dir, entry.fileName);
        await s3.downloadFile(entry.remote.key, archivePath);
        downloaded = true;
      } else {
        throw new Error('La copia no está ni en disco ni en el bucket');
      }
    } else if (remoteKey) {
      const s3 = this.s3ClientFor();
      if (!s3) throw new Error('No hay almacenamiento S3 configurado');
      archivePath = path.join(dir, `remote_${path.basename(String(remoteKey))}`);
      await s3.downloadFile(String(remoteKey), archivePath);
      downloaded = true;
    } else {
      throw new Error('Indique backupId o remoteKey');
    }

    // Descomprimir a un fichero plano que la herramienta sepa leer.
    /** @type {string} */
    let plainPath = archivePath;
    let madeTemp = false;
    if (archivePath.endsWith('.gz') && !archivePath.endsWith('.archive.gz')) {
      plainPath = path.join(TMP_DIR, `restore_${record.id}_${crypto.randomBytes(5).toString('hex')}`);
      await this.gunzipFile(archivePath, plainPath);
      madeTemp = true;
    }

    const inContainer = `/tmp/culkibo_restore_${crypto.randomBytes(6).toString('hex')}`;

    try {
      // Redis/Valkey no se restauran "en caliente": hay que parar el servidor,
      // sustituir el RDB y arrancar.
      //
      // El orden importa. Al recibir SIGTERM el servidor guarda una última
      // instantánea en `dump.rdb` ("Saving the final RDB snapshot before
      // exiting"), así que la copia TIENE que escribirse después del `stop`; al
      // revés, el propio motor sobreescribiría lo que acabamos de restaurar con
      // los datos que queríamos descartar.
      //
      // Se borra además cualquier `appendonlydir` que pudiera quedar de una
      // versión anterior de Culkibo que sí activaba AOF: si existe, el servidor
      // lo carga y descarta el RDB. Ver REDIS_FAMILY_COMMAND.
      if (engine.family === 'redis') {
        const dataDir = record.dataDir || this.resolveDataDir(engine, record.image);
        await this.docker(['stop', record.containerName], { timeout: 90000 });
        // Contenedor efímero sobre el MISMO volumen: `docker exec` no funciona
        // contra un contenedor parado.
        try {
          await this.docker(
            ['run', '--rm', '-v', `${record.volumeName}:${dataDir}`, '--entrypoint', 'rm',
             record.image, '-rf', `${dataDir}/appendonlydir`, `${dataDir}/appendonly.aof`],
            { timeout: 120000 }
          );
        } catch (e) {}
        await this.docker(['cp', plainPath, `${record.containerName}:${dataDir}/dump.rdb`], { timeout: 3600 * 1000 });
        await this.docker(['start', record.containerName], { timeout: 90000 });
        record.status = 'running';
        this.save();
        return { success: true, databaseId: id, method: 'rdb-replace', downloaded };
      }

      // Los motores que leen el volcado de la entrada estándar no necesitan
      // copia previa: sería duplicar en disco un fichero que puede pesar giga.
      const usesStdin = Boolean(engine.restore && engine.restore({ dbName: 'x', inFile: 'x', username: 'x' }).stdinFile);
      if (!usesStdin) {
        await this.docker(['cp', plainPath, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
      }

      if (engine.family === 'mongodb') {
        const cfgLocal = path.join(TMP_DIR, `mongo_r_${record.id}_${crypto.randomBytes(5).toString('hex')}.yml`);
        const cfgRemote = `/tmp/.culkibo_r_${crypto.randomBytes(5).toString('hex')}.yml`;
        fs.writeFileSync(cfgLocal, `password: ${JSON.stringify(this.decryptPassword(record))}\n`, { encoding: 'utf8', mode: 0o600 });
        try {
          await this.docker(['cp', cfgLocal, `${record.containerName}:${cfgRemote}`], { timeout: 30000 });
          await this.docker([
            'exec', record.containerName, 'mongorestore',
            `--config=${cfgRemote}`,
            `--username=${record.username}`,
            '--authenticationDatabase=admin',
            `--archive=${inContainer}`, '--gzip', '--drop'
          ], { timeout: 6 * 3600 * 1000 });
        } finally {
          try { fs.unlinkSync(cfgLocal); } catch (e) {}
          try { await this.docker(['exec', record.containerName, 'rm', '-f', cfgRemote], { timeout: 15000 }); } catch (e) {}
        }
      } else {
        const plan = engine.restore({ username: record.username, dbName: record.dbName, inFile: inContainer });
        const argv = this.wrapInContainer(engine, plan.program, plan.args);
        if (plan.stdinFile) {
          // `mysql < dump.sql` sin redirección de shell: el fichero se canaliza
          // a la entrada estándar del `docker exec -i` desde Node.
          await this.docker(['exec', '-i', record.containerName, ...argv], {
            timeout: 6 * 3600 * 1000,
            inputFile: plainPath
          });
        } else {
          await this.docker(['exec', record.containerName, ...argv], { timeout: 6 * 3600 * 1000 });
        }
      }

      this.emit('restore_completed', { databaseId: id });
      return { success: true, databaseId: id, method: engine.family, downloaded };
    } finally {
      try { await this.docker(['exec', record.containerName, 'rm', '-f', inContainer], { timeout: 15000 }); } catch (e) {}
      if (madeTemp) { try { fs.unlinkSync(plainPath); } catch (e) {} }
    }
  }

  // -------------------------------------------------------------------------
  // Retención
  // -------------------------------------------------------------------------

  /**
   * Plan de retención abuelo-padre-hijo, función pura para poder probarla.
   *
   * Se conserva la copia MÁS RECIENTE de cada uno de los últimos N días
   * naturales y la más reciente de cada una de las últimas M semanas ISO. La
   * última copia siempre sobrevive, pase lo que pase con los contadores: una
   * política mal configurada no puede dejar a nadie sin ninguna copia.
   *
   * @param {Array<{id:string, createdAt:string}>} backups
   * @param {{daily?:number | string, weekly?:number | string}} [policy]
   * @returns {{keep:string[], prune:string[], reasons:Object}}
   */
  planRetention(backups, policy = {}) {
    const daily = Math.max(0, parseInt(String(policy.daily ?? 0), 10) || 0);
    const weekly = Math.max(0, parseInt(String(policy.weekly ?? 0), 10) || 0);

    const sorted = (backups || [])
      .filter((b) => b && b.id && b.createdAt)
      .slice()
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const keep = new Set();
    const reasons = {};

    if (sorted.length) {
      keep.add(sorted[0].id);
      reasons[sorted[0].id] = 'última copia';
    }

    const dayKey = (d) => {
      const x = new Date(d);
      return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`;
    };
    // Semana ISO: jueves de la misma semana identifica el año-semana sin
    // ambigüedad en los cambios de año.
    const weekKey = (d) => {
      const x = new Date(d);
      x.setHours(0, 0, 0, 0);
      x.setDate(x.getDate() + 3 - ((x.getDay() + 6) % 7));
      const jan4 = new Date(x.getFullYear(), 0, 4);
      const week = 1 + Math.round(((x.getTime() - jan4.getTime()) / 86400000 - 3 + ((jan4.getDay() + 6) % 7)) / 7);
      return `${x.getFullYear()}-W${String(week).padStart(2, '0')}`;
    };

    const pickNewestPerBucket = (keyFn, limit, label) => {
      const seen = new Map();
      for (const b of sorted) {
        const k = keyFn(b.createdAt);
        if (!seen.has(k)) seen.set(k, b);
      }
      let n = 0;
      for (const [k, b] of seen) {
        if (n >= limit) break;
        if (!keep.has(b.id)) reasons[b.id] = `${label} ${k}`;
        keep.add(b.id);
        n++;
      }
    };

    pickNewestPerBucket(dayKey, daily, 'diaria');
    pickNewestPerBucket(weekKey, weekly, 'semanal');

    return {
      keep: sorted.filter((b) => keep.has(b.id)).map((b) => b.id),
      prune: sorted.filter((b) => !keep.has(b.id)).map((b) => b.id),
      reasons
    };
  }

  /** Aplica el plan: borra el fichero local y el objeto remoto. */
  async applyRetention(id) {
    const record = this.mustGet(id);
    const plan = this.planRetention(record.backups, record.retention);
    if (!plan.prune.length) return { pruned: 0, kept: plan.keep.length };

    const dir = this.backupDir(id);
    const s3 = this.s3ClientFor();
    let pruned = 0;

    for (const backupId of plan.prune) {
      const entry = record.backups.find((b) => b.id === backupId);
      if (!entry) continue;
      try { fs.unlinkSync(path.join(dir, entry.fileName)); } catch (e) {}
      if (s3 && entry.remote && entry.remote.key) {
        try { await s3.deleteObject(entry.remote.key); } catch (e) {
          console.warn(`[Databases] No se pudo borrar el objeto remoto: ${e.message}`);
        }
      }
      pruned++;
    }

    record.backups = record.backups.filter((b) => plan.keep.includes(b.id));
    this.save();
    return { pruned, kept: record.backups.length };
  }

  /** @param {string} id @param {{ daily?: number | string, weekly?: number | string }} [opts] */
  setRetention(id, { daily = 0, weekly = 0 } = {}) {
    const record = this.mustGet(id);
    record.retention = {
      daily: Math.max(0, Math.min(365, parseInt(String(daily), 10) || 0)),
      weekly: Math.max(0, Math.min(260, parseInt(String(weekly), 10) || 0))
    };
    if (record.retention.daily === 0 && record.retention.weekly === 0) {
      throw new Error('La retención no puede ser 0 diarias y 0 semanales');
    }
    this.save();
    return this.toPublic(record);
  }

  // -------------------------------------------------------------------------
  // Planificador
  // -------------------------------------------------------------------------

  /**
   * Analiza una expresión cron de 5 campos.
   *
   * Soporta `*`, `n`, `a-b`, `*​/n`, `a-b/n` y listas separadas por coma, que es
   * lo que cubre el 100% de los horarios de copia reales. No soporta `L`, `W`
   * ni `#`: nadie programa una copia el último viernes laborable del mes, y un
   * parser que acepta sintaxis que luego no respeta es peor que uno que la
   * rechaza.
   */
  parseCron(expression) {
    const expr = CRON_ALIASES[String(expression || '').trim()] || String(expression || '').trim();
    const parts = expr.split(/\s+/).filter(Boolean);
    if (parts.length !== 5) {
      throw new Error(`Expresión cron inválida: se esperan 5 campos, hay ${parts.length}`);
    }

    return parts.map((field, i) => {
      const { name, min, max } = CRON_FIELDS[i];
      const allowed = new Set();

      for (const token of field.split(',')) {
        const [rangePart, stepPart] = token.split('/');
        const step = stepPart === undefined ? 1 : parseInt(stepPart, 10);
        if (!Number.isInteger(step) || step < 1) {
          throw new Error(`Paso inválido en el campo ${name}: ${token}`);
        }

        let lo;
        let hi;
        if (rangePart === '*') {
          lo = min; hi = max;
        } else if (rangePart.includes('-')) {
          const [a, b] = rangePart.split('-').map((n) => parseInt(n, 10));
          lo = a; hi = b;
        } else {
          lo = parseInt(rangePart, 10);
          hi = stepPart === undefined ? lo : max;
        }

        if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < min || hi > max || lo > hi) {
          throw new Error(`Valor fuera de rango en el campo ${name}: ${token} (permitido ${min}-${max})`);
        }
        for (let v = lo; v <= hi; v += step) {
          // Domingo se escribe 0 o 7; normalizamos a 0.
          allowed.add(i === 4 && v === 7 ? 0 : v);
        }
      }
      return allowed;
    });
  }

  /**
   * Siguiente ejecución en hora local del servidor, estrictamente posterior a
   * `from`. Devuelve null si no hay ninguna en 366 días (cron imposible, p. ej.
   * el 30 de febrero).
   */
  nextCronRun(expression, from = new Date()) {
    const [minutes, hours, doms, months, dows] = this.parseCron(expression);

    const cursor = new Date(from.getTime());
    cursor.setSeconds(0, 0);
    cursor.setMinutes(cursor.getMinutes() + 1);

    const limit = new Date(from.getTime() + 366 * 24 * 3600 * 1000);

    while (cursor <= limit) {
      if (!months.has(cursor.getMonth() + 1)) {
        cursor.setMonth(cursor.getMonth() + 1, 1);
        cursor.setHours(0, 0, 0, 0);
        continue;
      }
      // Cron estándar: si ambos campos de día están restringidos, se cumple
      // con que coincida CUALQUIERA de los dos (no los dos a la vez).
      const domRestricted = doms.size !== 31;
      const dowRestricted = dows.size !== 7;
      const domOk = doms.has(cursor.getDate());
      const dowOk = dows.has(cursor.getDay());
      const dayOk = domRestricted && dowRestricted ? domOk || dowOk : domOk && dowOk;

      if (!dayOk) {
        cursor.setDate(cursor.getDate() + 1);
        cursor.setHours(0, 0, 0, 0);
        continue;
      }
      if (!hours.has(cursor.getHours())) {
        cursor.setHours(cursor.getHours() + 1, 0, 0, 0);
        continue;
      }
      if (!minutes.has(cursor.getMinutes())) {
        cursor.setMinutes(cursor.getMinutes() + 1, 0, 0);
        continue;
      }
      return cursor;
    }
    return null;
  }

  /** @param {string} id @param {{ enabled?: boolean, cron?: string }} [opts] */
  setSchedule(id, { enabled = false, cron = '' } = {}) {
    const record = this.mustGet(id);
    const expr = cron || record.schedule.cron || '0 3 * * *';
    this.parseCron(expr); // valida o lanza antes de guardar nada

    record.schedule.cron = expr;
    record.schedule.enabled = Boolean(enabled);
    const next = record.schedule.enabled ? this.nextCronRun(expr) : null;
    record.schedule.nextRunAt = next ? next.toISOString() : null;
    this.save();
    return this.toPublic(record);
  }

  /**
   * Por qué NO node-cron (ni croner, ni node-schedule).
   *
   * 1. El estado. node-cron vive en memoria: si el daemon está parado a las
   *    03:00 —una actualización, un reinicio del host, un portátil suspendido—
   *    esa copia no se ejecuta y nadie se entera. Persistiendo `nextRunAt`
   *    detectamos al arrancar que la ventana pasó y la recuperamos. Para un
   *    producto cuyo argumento de venta es "tus copias están hechas", esa es la
   *    diferencia entre funcionar y aparentarlo.
   * 2. El coste. Un tick de `setInterval` cada 30 s comparando marcas de tiempo
   *    es exacto al minuto, que es la resolución de cron. Toda la maquinaria de
   *    un `setTimeout` por trabajo sobra, y `setTimeout` además se desincroniza
   *    con el reloj cuando la máquina suspende.
   * 3. La dependencia. Culkibo tiene siete dependencias en total; añadir una
   *    más para ~60 líneas de parser no sale a cuenta en un producto que la
   *    gente audita antes de confiarle sus datos.
   *
   * El temporizador va con `unref()`: el planificador jamás mantiene vivo el
   * proceso, ni en las pruebas ni en un `culkibo` de un solo comando.
   */
  startScheduler({ intervalMs = SCHEDULER_TICK_MS, catchUp = true } = {}) {
    if (this.schedulerTimer) return this.schedulerTimer;

    if (catchUp) {
      // Recuperación de ventanas perdidas mientras el daemon estaba parado.
      for (const record of this.state.databases) {
        if (!record.schedule || !record.schedule.enabled || !record.schedule.nextRunAt) continue;
        const due = new Date(record.schedule.nextRunAt).getTime();
        const age = Date.now() - due;
        if (age > 0 && age < MAX_CATCH_UP_MS) {
          console.log(`[Databases] Copia perdida de ${record.name} (${record.schedule.nextRunAt}); recuperando`);
          this.runBackup(record.id, { trigger: 'catch-up' }).catch((e) =>
            console.error(`[Databases] Recuperación fallida: ${e.message}`)
          );
        }
      }
    }

    this.schedulerTimer = setInterval(() => this.tick().catch(() => {}), intervalMs);
    if (this.schedulerTimer.unref) this.schedulerTimer.unref();
    return this.schedulerTimer;
  }

  stopScheduler() {
    if (this.schedulerTimer) {
      clearInterval(this.schedulerTimer);
      this.schedulerTimer = null;
    }
  }

  /**
   * Un paso del planificador. Público para poder dispararlo desde las pruebas
   * sin esperar 30 segundos.
   */
  async tick(now = new Date()) {
    const fired = [];
    for (const record of this.state.databases) {
      const s = record.schedule;
      if (!s || !s.enabled || !s.cron) continue;

      // Una expresión cron corrupta en UN registro no puede dejar sin copia a
      // todos los demás: se aísla el fallo y se desactiva esa programación.
      try {
        this.parseCron(s.cron);
      } catch (err) {
        console.error(`[Databases] Horario inválido en ${record.name}: ${err.message}. Se desactiva.`);
        s.enabled = false;
        s.lastStatus = 'horario-invalido';
        this.save();
        continue;
      }

      if (!s.nextRunAt) {
        const next = this.nextCronRun(s.cron, now);
        s.nextRunAt = next ? next.toISOString() : null;
        this.save();
        continue;
      }
      if (new Date(s.nextRunAt).getTime() > now.getTime()) continue;
      if (this.runningBackups.has(record.id)) continue;

      // Se recalcula ANTES de ejecutar: si el volcado tarda dos horas no debe
      // volver a dispararse en el siguiente tick, y si falla tampoco debe
      // reintentarse en bucle cada 30 segundos.
      const next = this.nextCronRun(s.cron, now);
      s.nextRunAt = next ? next.toISOString() : null;
      this.save();

      fired.push(record.id);
      this.runBackup(record.id, { trigger: 'scheduled' }).catch((e) =>
        console.error(`[Databases] Copia programada fallida (${record.name}): ${e.message}`)
      );
    }
    return { firedAt: now.toISOString(), fired };
  }

  // -------------------------------------------------------------------------
  // Configuración S3 / R2
  // -------------------------------------------------------------------------

  /**
   * Guarda la configuración del bucket. La clave secreta se cifra igual que
   * las contraseñas y no vuelve a salir nunca por la API.
   */
  setS3Config(config = {}) {
    if (config === null || config.enabled === false) {
      this.state.s3 = null;
      this.save();
      return { configured: false };
    }
    // Validamos construyendo el cliente: si la configuración es inválida,
    // falla aquí y no seis horas después en mitad de la copia nocturna.
    const probe = new S3Client(config);
    this.state.s3 = {
      endpoint: probe.origin,
      region: probe.region,
      bucket: probe.bucket,
      forcePathStyle: probe.forcePathStyle,
      prefix: String(config.prefix || 'culkibo/').replace(/^\/+/, ''),
      accessKeyId: config.accessKeyId,
      secretAccessKeyEnc: encryptSecret(config.secretAccessKey, this.cryptoKey)
    };
    this.save();
    return this.getS3Config();
  }

  /** Vista pública: sin la clave secreta, con el identificador enmascarado. */
  getS3Config() {
    if (!this.state.s3) return { configured: false };
    const s = this.state.s3;
    return {
      configured: true,
      endpoint: s.endpoint,
      region: s.region,
      bucket: s.bucket,
      prefix: s.prefix,
      pathStyle: s.forcePathStyle,
      accessKeyId: redactKey(s.accessKeyId),
      secretAccessKey: '********'
    };
  }

  s3Prefix() {
    const p = (this.state.s3 && this.state.s3.prefix) || 'culkibo/';
    return p.endsWith('/') ? p : `${p}/`;
  }

  s3ClientFor() {
    if (!this.state.s3) return null;
    const s = this.state.s3;
    return new S3Client({
      endpoint: s.endpoint,
      region: s.region,
      bucket: s.bucket,
      forcePathStyle: s.forcePathStyle,
      accessKeyId: s.accessKeyId,
      secretAccessKey: decryptSecret(s.secretAccessKeyEnc, this.cryptoKey)
    });
  }

  /** Prueba de extremo a extremo del bucket: escribe, lee y borra un objeto. */
  async testS3() {
    const s3 = this.s3ClientFor();
    if (!s3) throw new Error('No hay almacenamiento S3 configurado');
    const key = `${this.s3Prefix()}.culkibo-test-${crypto.randomBytes(6).toString('hex')}`;
    const payload = Buffer.from(`culkibo ${new Date().toISOString()}\n`, 'utf8');
    await s3.putObject(key, payload, 'text/plain');
    const head = await s3.headObject(key);
    await s3.deleteObject(key);
    return { success: true, endpoint: s3.origin, bucket: s3.bucket, verifiedBytes: head ? head.sizeBytes : payload.length };
  }
}

const instance = Object.assign(new DatabaseManager(), {
  ENGINES,
  generatePassword,
  encryptSecret,
  decryptSecret
});

module.exports = instance;
