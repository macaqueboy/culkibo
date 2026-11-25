const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const zlib = require('zlib');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const EventEmitter = require('events');
const { execFile, spawn } = require('child_process');
const util = require('util');
const execFilePromise = util.promisify(execFile);

const dbBackupManager = require('./dbBackupManager');
const { S3Client, redactKey } = require('./s3Uploader');
const { atomicWriteJsonSync, assertContainedPath, formatDockerEnvFile } = require('./ssrfGuard');
const portRegistry = require('./portRegistry');
const { isSubDailyCron } = require('./cronParser');

const MAX_CONCURRENT_BACKUPS = 2;

/** @type {any} */
let _notificationService = null;
function getNotificationService() {
  if (!_notificationService) {
    try { _notificationService = require('./notificationService'); } catch (e) {}
  }
  return _notificationService;
}

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

function resolveDefaultDataRoot() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.join(__dirname, '..', '..', 'data');
}

const DEFAULT_DATA_ROOT = resolveDefaultDataRoot();
const DATA_FILE = path.join(DEFAULT_DATA_ROOT, 'databases.json');
const KEY_FILE = path.join(DEFAULT_DATA_ROOT, '.databases.key');
const BACKUPS_ROOT = path.join(DEFAULT_DATA_ROOT, 'backups', 'databases');
const TMP_DIR = path.join(DEFAULT_DATA_ROOT, '.tmp');

/** Cada cuánto despierta el planificador a mirar si toca alguna copia. */
const SCHEDULER_TICK_MS = 30000;
/** Una copia perdida por un daemon apagado se recupera si no ha caducado del todo. */
const MAX_CATCH_UP_MS = 7 * 24 * 3600 * 1000;
/** Imagen fijada para el pooler PgBouncer co-localizado (PostgreSQL/pgvector/TimescaleDB). */
const PGBOUNCER_IMAGE = 'edoburu/pgbouncer:v1.23.1-p3';
const VALID_POOL_MODES = new Set(['transaction', 'session', 'statement']);
const VALID_TUNING_PRESETS = new Set(['oltp', 'analytics', 'low-memory', 'cache', 'none']);
const VALID_REDIS_EVICTION_POLICIES = new Set([
  'noeviction', 'allkeys-lru', 'volatile-lru', 'allkeys-lfu', 'volatile-lfu', 'volatile-ttl'
]);
const MAX_AUDIT_HISTORY = 50;

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

/** Resuelve el PGDATA correcto según la major de PostgreSQL (PG18 movió PGDATA a /var/lib/postgresql). */
function resolvePostgresDataDir(image) {
  const tagSeg = String(image || '').split('/').pop() || '';
  const m = /:(?:[\d.]+-)?(?:pg)?(\d+)/.exec(tagSeg) || /-pg(\d+)/.exec(tagSeg);
  const major = m ? parseInt(m[1], 10) : 18;
  return major >= 18 ? '/var/lib/postgresql' : '/var/lib/postgresql/data';
}

const ENGINES = {
  postgres: {
    label: 'PostgreSQL',
    family: 'postgresql',
    image: 'postgres:18-alpine',
    port: 5432,
    scheme: 'postgresql',
    dataDir: '/var/lib/postgresql',
    supportsPooler: true,
    // PG 18 movió PGDATA. Si alguien fija una imagen anterior, el volumen tiene
    // que ir al sitio que esa versión espera.
    dataDirFor: resolvePostgresDataDir,
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
      args: ['-U', username, '-d', dbName, '--clean', '--if-exists', '--no-owner', '--no-privileges', '-e', inFile]
    })
  },

  pgvector: {
    label: 'PostgreSQL + pgvector',
    family: 'postgresql',
    image: 'pgvector/pgvector:0.8.0-pg17',
    port: 5432,
    scheme: 'postgresql',
    dataDir: '/var/lib/postgresql/data',
    dataDirFor: resolvePostgresDataDir,
    supportsPooler: true,
    extensions: ['vector'],
    licence: 'PostgreSQL License (permisiva)',
    initEnv: ({ username, password, dbName }) => ({
      POSTGRES_USER: username,
      POSTGRES_PASSWORD: password,
      POSTGRES_DB: dbName
    }),
    clientEnv: ({ password }) => ({ PGPASSWORD: password }),
    health: ({ username, dbName }) => `pg_isready -h 127.0.0.1 -U ${username} -d ${dbName}`,
    dumpExt: '.dump',
    restore: ({ username, dbName, inFile }) => ({
      program: 'pg_restore',
      args: ['-U', username, '-d', dbName, '--clean', '--if-exists', '--no-owner', '--no-privileges', '-e', inFile]
    })
  },

  timescaledb: {
    label: 'TimescaleDB',
    family: 'postgresql',
    image: 'timescale/timescaledb:2.19.3-pg17',
    port: 5432,
    scheme: 'postgresql',
    dataDir: '/var/lib/postgresql/data',
    dataDirFor: resolvePostgresDataDir,
    supportsPooler: true,
    extensions: ['timescaledb'],
    licence: 'Apache-2.0 / Timescale License',
    initEnv: ({ username, password, dbName }) => ({
      POSTGRES_USER: username,
      POSTGRES_PASSWORD: password,
      POSTGRES_DB: dbName
    }),
    clientEnv: ({ password }) => ({ PGPASSWORD: password }),
    health: ({ username, dbName }) => `pg_isready -h 127.0.0.1 -U ${username} -d ${dbName}`,
    dumpExt: '.dump',
    restore: ({ username, dbName, inFile }) => ({
      program: 'pg_restore',
      args: ['-U', username, '-d', dbName, '--clean', '--if-exists', '--no-owner', '--no-privileges', '-e', inFile]
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
      args: ['--sandbox', '-u', 'root', dbName],
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
    command: (opts) => REDIS_FAMILY_COMMAND('valkey-server', 'VALKEY_PASSWORD', opts),
    health: () => 'valkey-cli -e ping',
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
    command: (opts) => REDIS_FAMILY_COMMAND('redis-server', 'REDIS_PASSWORD', opts),
    health: () => 'redis-cli -e ping',
    dumpExt: '.rdb'
  },

  dragonfly: {
    label: 'Dragonfly',
    family: 'redis',
    image: 'docker.dragonflydb.io/dragonflydb/dragonfly:v1.34.1',
    port: 6379,
    scheme: 'redis',
    dataDir: '/data',
    licence: 'BSL 1.1 (source-available)',
    noDatabaseName: true,
    // Dragonfly lee variables `DFLY_<flag>` nativamente del entorno (--env-file 0600),
    // evitando pasar --requirepass por argv o depender de una shell interna.
    initEnv: ({ password }) => ({ DFLY_requirepass: password, REDISCLI_AUTH: password }),
    clientEnv: ({ password }) => ({ REDISCLI_AUTH: password }),
    command: (/** @type {{ tuning?: any }} */ opts = {}) => [
      '--dir', '/data',
      '--dbfilename', 'dump.rdb',
      ...(opts && opts.tuning && Array.isArray(opts.tuning.commandArgs) ? opts.tuning.commandArgs : [])
    ],
    health: () => 'redis-cli -e ping',
    dumpProgram: 'redis-cli',
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
    configFormat: 'mongo-yaml',
    // Sin esto mongodump se autentica contra la base de datos que va a volcar,
    // pero el usuario raíz que crea el entrypoint vive en `admin`, así que la
    // copia falla con «Authentication failed» pese a tener la contraseña bien.
    dumpExtraArgs: ['--authenticationDatabase=admin'],
    // `ping` se puede ejecutar antes de autenticarse, así que la sonda no
    // necesita credenciales ni siquiera con auth activada.
    health: () => "mongosh --quiet --eval \"db.adminCommand('ping').ok\"",
    dumpExt: '.archive.gz'
  },

  clickhouse: {
    label: 'ClickHouse',
    family: 'clickhouse',
    image: 'clickhouse/clickhouse-server:25.8-alpine',
    port: 8123,
    nativePort: 9000,
    scheme: 'http',
    dataDir: '/var/lib/clickhouse',
    licence: 'Apache-2.0',
    initEnv: ({ username, password, dbName }) => ({
      CLICKHOUSE_USER: username,
      CLICKHOUSE_PASSWORD: password,
      CLICKHOUSE_DB: dbName,
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: '1'
    }),
    clientEnv: ({ password }) => ({ CLICKHOUSE_PASSWORD: password }),
    usesConfigFile: true,
    configFormat: 'clickhouse-xml',
    health: () => 'wget -qO- http://127.0.0.1:8123/ping',
    dumpExt: '.chbackup.zip'
  },

  qdrant: {
    label: 'Qdrant',
    family: 'qdrant',
    image: 'qdrant/qdrant:v1.15.5',
    port: 6333,
    grpcPort: 6334,
    scheme: 'http',
    dataDir: '/qdrant/storage',
    licence: 'Apache-2.0',
    noDatabaseName: true,
    initEnv: ({ password }) => ({ QDRANT__SERVICE__API_KEY: password }),
    clientEnv: () => ({}),
    usesConfigFile: true,
    configFormat: 'curl-qdrant',
    health: () => 'wget -qO- http://127.0.0.1:6333/readyz',
    dumpExt: '.snapshot'
  },

  meilisearch: {
    label: 'Meilisearch',
    family: 'meilisearch',
    image: 'getmeili/meilisearch:v1.15.2',
    port: 7700,
    scheme: 'http',
    dataDir: '/meili_data',
    licence: 'MIT',
    noDatabaseName: true,
    initEnv: ({ password }) => ({
      MEILI_MASTER_KEY: password,
      MEILI_ENV: 'production',
      MEILI_NO_ANALYTICS: 'true'
    }),
    clientEnv: () => ({}),
    usesConfigFile: true,
    configFormat: 'curl-meilisearch',
    health: () => 'wget -qO- http://127.0.0.1:7700/health',
    dumpExt: '.dump'
  }
};

/**
 * Calcula los parámetros óptimos de afinado de memoria/CPU por motor sin construir
 * comandos de shell (solo flags en argv o variables de entorno para `--env-file`).
 * @param {string} engineKey
 * @param {{ memoryMb?: number, cpus?: number, preset?: string }} [opts]
 * @returns {{ preset: string, params: Record<string, any>, commandArgs: string[], env: Record<string, string> }}
 */
function computeTuningConfig(engineKey, { memoryMb = 512, cpus = 1, preset = 'oltp' } = {}) {
  const key = String(engineKey || '').toLowerCase();
  const engine = ENGINES[key];
  if (!engine) throw new Error(`Motor no soportado para tuning: ${engineKey}`);
  const cleanPreset = String(preset || 'oltp').toLowerCase();
  if (!VALID_TUNING_PRESETS.has(cleanPreset)) {
    throw new Error(`Preset de tuning inválido: ${preset}. Disponibles: ${Array.from(VALID_TUNING_PRESETS).join(', ')}`);
  }
  const mem = Math.max(128, Math.min(65536, parseInt(String(memoryMb), 10) || 512));
  const cpu = Math.max(0.1, Math.min(32, Number(cpus) || 1));

  if (cleanPreset === 'none') {
    return { preset: 'none', params: {}, commandArgs: [], env: {} };
  }

  if (engine.family === 'postgresql') {
    const sharedBuffersMb = Math.max(32, Math.floor(mem * (cleanPreset === 'low-memory' ? 0.15 : 0.25)));
    const effectiveCacheMb = Math.max(64, Math.floor(mem * (cleanPreset === 'low-memory' ? 0.4 : 0.65)));
    const workMemMb = cleanPreset === 'analytics'
      ? Math.max(8, Math.min(256, Math.floor(mem * 0.05)))
      : Math.max(4, Math.min(64, Math.floor(mem * 0.015)));
    const maintenanceWorkMemMb = Math.max(32, Math.min(512, Math.floor(mem * 0.08)));
    const maxConnections = cleanPreset === 'low-memory'
      ? 50
      : Math.max(50, Math.min(500, Math.floor(mem / 8)));
    return {
      preset: cleanPreset,
      params: { sharedBuffersMb, effectiveCacheMb, workMemMb, maintenanceWorkMemMb, maxConnections, walCompression: 'on' },
      commandArgs: [
        '-c', `shared_buffers=${sharedBuffersMb}MB`,
        '-c', `effective_cache_size=${effectiveCacheMb}MB`,
        '-c', `work_mem=${workMemMb}MB`,
        '-c', `maintenance_work_mem=${maintenanceWorkMemMb}MB`,
        '-c', `max_connections=${maxConnections}`,
        '-c', 'wal_compression=on'
      ],
      env: {}
    };
  }

  if (engine.family === 'mysql' || engine.family === 'mariadb') {
    const innodbBufferPoolMb = Math.max(64, Math.floor(mem * (cleanPreset === 'low-memory' ? 0.35 : 0.55)));
    const maxConnections = cleanPreset === 'low-memory'
      ? 60
      : Math.max(60, Math.min(400, Math.floor(mem / 10)));
    return {
      preset: cleanPreset,
      params: { innodbBufferPoolMb, maxConnections },
      commandArgs: [
        `--innodb-buffer-pool-size=${innodbBufferPoolMb}M`,
        `--max-connections=${maxConnections}`
      ],
      env: {}
    };
  }

  if (key === 'dragonfly') {
    const maxMemoryMb = Math.max(128, Math.floor(mem * 0.8));
    const proactorThreads = Math.max(1, Math.min(8, Math.ceil(cpu)));
    const cacheMode = cleanPreset === 'cache';
    return {
      preset: cleanPreset,
      params: { maxMemoryMb, proactorThreads, cacheMode },
      commandArgs: [
        `--maxmemory=${maxMemoryMb}mb`,
        `--proactor_threads=${proactorThreads}`,
        ...(cacheMode ? ['--cache_mode=true'] : [])
      ],
      env: {}
    };
  }

  if (engine.family === 'redis') {
    // 78% del cgroup deja margen para el fork() de BGSAVE sin disparar OOM-killer
    const maxMemoryMb = Math.max(64, Math.floor(mem * 0.78));
    const evictionPolicy = cleanPreset === 'cache'
      ? 'allkeys-lru'
      : cleanPreset === 'low-memory'
        ? 'volatile-lru'
        : 'noeviction';
    return {
      preset: cleanPreset,
      params: { maxMemoryMb, evictionPolicy },
      commandArgs: ['--maxmemory', `${maxMemoryMb}mb`, '--maxmemory-policy', evictionPolicy],
      env: {}
    };
  }

  if (engine.family === 'mongodb') {
    const wiredTigerCacheGb = Math.max(0.25, Number(((mem * 0.5) / 1024).toFixed(2)));
    return {
      preset: cleanPreset,
      params: { wiredTigerCacheGb },
      commandArgs: ['--wiredTigerCacheSizeGB', String(wiredTigerCacheGb)],
      env: {}
    };
  }

  if (engine.family === 'meilisearch') {
    const maxIndexingMemoryMb = Math.max(64, Math.floor(mem * 0.65));
    const maxIndexingThreads = Math.max(1, Math.min(8, Math.ceil(cpu)));
    return {
      preset: cleanPreset,
      params: { maxIndexingMemoryMb, maxIndexingThreads },
      commandArgs: [],
      env: {
        MEILI_MAX_INDEXING_MEMORY: `${maxIndexingMemoryMb}MiB`,
        MEILI_MAX_INDEXING_THREADS: String(maxIndexingThreads)
      }
    };
  }

  if (engine.family === 'qdrant') {
    const searchThreads = Math.max(1, Math.min(16, Math.ceil(cpu)));
    return {
      preset: cleanPreset,
      params: { searchThreads },
      commandArgs: [],
      env: {
        QDRANT__STORAGE__PERFORMANCE__MAX_SEARCH_THREADS: String(searchThreads)
      }
    };
  }

  if (engine.family === 'clickhouse') {
    const maxServerMemoryRatio = cleanPreset === 'low-memory' ? 0.7 : 0.85;
    return {
      preset: cleanPreset,
      params: { maxServerMemoryRatio },
      commandArgs: [],
      env: {}
    };
  }

  return { preset: cleanPreset, params: {}, commandArgs: [], env: {} };
}

/**
 * Redis y Valkey son las únicas imágenes sin variable de entorno para la
 * contraseña: sólo aceptan `--requirepass <secreto>` en la línea de comandos.
 * Escribirlo en el `docker run` dejaría el secreto en el argv del proceso
 * `docker` del HOST, que es exactamente lo que este módulo evita.
 *
 * La salida es una cadena de shell — pero CONSTANTE y sin una sola
 * interpolación de datos del usuario: el secreto entra por el `--env-file` y
 * los parámetros de tuning (`maxMemoryMb`, `evictionPolicy`) pasan por entero
 * estricto y lista blanca cerrada antes de construirse.
 */
/** @param {string} server @param {string} envVar @param {{ tuning?: any }} [opts] */
function REDIS_FAMILY_COMMAND(server, envVar, { tuning = null } = {}) {
  let extra = '';
  if (tuning && tuning.params && Number.isInteger(tuning.params.maxMemoryMb) && tuning.params.maxMemoryMb >= 64) {
    const policy = VALID_REDIS_EVICTION_POLICIES.has(tuning.params.evictionPolicy)
      ? tuning.params.evictionPolicy
      : 'noeviction';
    extra = ` --maxmemory ${tuning.params.maxMemoryMb}mb --maxmemory-policy ${policy}`;
  }
  return [
    'sh', '-c',
    `exec ${server} --save 900 1 --save 300 10 --save 60 10000${extra} --requirepass "$${envVar}"`
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
function loadOrCreateKey(keyFile = KEY_FILE, dataFile = DATA_FILE) {
  // P0: si KEY_FILE ya existe, JAMÁS regenerarlo ante un error transitorio de lectura (EBUSY/EACCES),
  // porque sobrescribirlo destruiría el descifrado de todas las contraseñas en databases.json.
  if (fs.existsSync(keyFile)) {
    const raw = fs.readFileSync(keyFile, 'utf8').trim();
    const key = Buffer.from(raw, 'hex');
    if (key.length !== 32) {
      throw new Error(`Clave de cifrado corrupta en ${keyFile} (esperados 32 bytes). No se regenerará automáticamente para proteger tus contraseñas.`);
    }
    return key;
  }

  // Protección anti pérdida de clave: si ya hay registros cifrados v1: en databases.json, no inventar clave nueva
  if (fs.existsSync(dataFile)) {
    try {
      const existingData = fs.readFileSync(dataFile, 'utf8');
      if (existingData.includes('"v1:')) {
        throw new Error(`Falta el archivo de clave ${keyFile} pero ${dataFile} contiene secretos cifrados. Restaura .databases.key desde tu copia segura.`);
      }
    } catch (e) {
      if (String(e.message || '').includes('Falta el archivo de clave')) throw e;
    }
  }

  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(keyFile, key.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    try { fs.chmodSync(keyFile, 0o600); } catch (e) {}
    return key;
  } catch (err) {
    if (err && err.code === 'EEXIST') {
      const raced = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
      if (raced.length === 32) return raced;
    }
    throw err;
  }
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

// ---------------------------------------------------------------------------
// Cifrado autenticado en streaming para copias S3/R2 (formato CKB1 AEAD)
// ---------------------------------------------------------------------------
// Cabecera fija de 32 bytes:
//   [0..3]   Magic 'CKB1'
//   [4]      Versión (0x01)
//   [5]      Suite (0x01 = AES-256-GCM en bloques)
//   [6..7]   Reservado (0x0000)
//   [8..15]  Key-ID (primeros 8 bytes de SHA-256(key), permite rotación sin re-cifrar)
//   [16..27] Base-Nonce aleatorio de 12 bytes
//   [28..31] Tamaño de bloque uint32 BE (por defecto 65536 B)
// Cada bloque:
//   [flags(1B: 0x00 intermedio, 0x01 final) | len(4B BE) | ciphertext(len) | authTag(16B)]
// El AAD vincula (CKB1, ver, keyId, chunkIndex, flags): impide reordenar,
// duplicar, truncar o añadir basura tras el bloque final.
const CKB1_MAGIC = Buffer.from('CKB1', 'ascii');
const CKB1_VERSION = 1;
const CKB1_CIPHER_SUITE = 1;
const CKB1_HEADER_LEN = 32;
const CKB1_DEFAULT_CHUNK_SIZE = 65536;
const CKB1_MIN_CHUNK_SIZE = 1024;
const CKB1_MAX_CHUNK_SIZE = 1024 * 1024;
const CKB1_AUTH_TAG_LEN = 16;

/** Identificador público de clave de 16 caracteres hex (8 bytes SHA-256) para rotación. */
function computeKeyId(keyBuf) {
  if (!Buffer.isBuffer(keyBuf) || keyBuf.length !== 32) {
    throw new Error('La clave de cifrado CKB1 debe ser un Buffer de exactamente 32 bytes');
  }
  return crypto.createHash('sha256').update(keyBuf).digest().subarray(0, 8).toString('hex');
}

/** Deriva una clave AES-256 (32 bytes) a partir de una passphrase con scrypt. */
function deriveBackupKeyFromPassphrase(passphrase, salt = null) {
  const pwd = String(passphrase || '').trim();
  if (pwd.length < 12) {
    throw new Error('La frase de paso de cifrado de copias debe tener al menos 12 caracteres');
  }
  const saltBuf = salt
    ? (Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt), 'hex'))
    : crypto.randomBytes(16);
  if (saltBuf.length < 16) throw new Error('Salt inválido (mínimo 16 bytes)');
  const key = crypto.scryptSync(pwd, saltBuf, 32, { N: 16384, r: 8, p: 1 });
  return { key, saltHex: saltBuf.toString('hex'), keyId: computeKeyId(key) };
}

function deriveChunkNonce(baseNonce, chunkIndex, flags) {
  const nonce = Buffer.from(baseNonce);
  const idxBuf = Buffer.alloc(4);
  idxBuf.writeUInt32BE(chunkIndex >>> 0, 0);
  nonce[7] ^= flags & 0xff;
  nonce[8] ^= idxBuf[0];
  nonce[9] ^= idxBuf[1];
  nonce[10] ^= idxBuf[2];
  nonce[11] ^= idxBuf[3];
  return nonce;
}

function buildChunkAad(keyIdBuf, chunkIndex, flags) {
  const aad = Buffer.alloc(18);
  CKB1_MAGIC.copy(aad, 0);
  aad[4] = CKB1_VERSION;
  keyIdBuf.copy(aad, 5, 0, 8);
  aad.writeUInt32BE(chunkIndex >>> 0, 13);
  aad[17] = flags & 0xff;
  return aad;
}

/** Comprueba si un fichero en disco comienza por la cabecera mágica `CKB1`. */
function hasCkb1Magic(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(4);
    const n = fs.readSync(fd, buf, 0, 4, 0);
    return n === 4 && buf.equals(CKB1_MAGIC);
  } finally {
    fs.closeSync(fd);
  }
}

/** Inspecciona la cabecera pública de un archivo cifrado `CKB1` sin requerir clave. */
function inspectCkb1Header(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const hdr = Buffer.alloc(CKB1_HEADER_LEN);
    const n = fs.readSync(fd, hdr, 0, CKB1_HEADER_LEN, 0);
    if (n < CKB1_HEADER_LEN || !hdr.subarray(0, 4).equals(CKB1_MAGIC)) {
      return { valid: false, reason: 'Cabecera CKB1 ausente o truncada' };
    }
    const version = hdr[4];
    const cipherSuite = hdr[5];
    const keyId = hdr.subarray(8, 16).toString('hex');
    const chunkSize = hdr.readUInt32BE(28);
    if (version !== CKB1_VERSION || cipherSuite !== CKB1_CIPHER_SUITE) {
      return { valid: false, reason: `Versión/suite CKB1 no soportada (${version}/${cipherSuite})` };
    }
    if (chunkSize < CKB1_MIN_CHUNK_SIZE || chunkSize > CKB1_MAX_CHUNK_SIZE) {
      return { valid: false, reason: `Tamaño de bloque CKB1 fuera de rango (${chunkSize})` };
    }
    return { valid: true, version, cipherSuite, keyId, chunkSize };
  } finally {
    fs.closeSync(fd);
  }
}

async function readExact(handle, buf, length, position) {
  let total = 0;
  while (total < length) {
    const { bytesRead } = await handle.read(buf, total, length - total, position + total);
    if (bytesRead <= 0) break;
    total += bytesRead;
  }
  return total;
}

/**
 * Cifra un fichero de volcado en streaming con AES-256-GCM en bloques (`CKB1`) con memoria O(1).
 * @param {string} srcPath
 * @param {string} destPath
 * @param {Buffer} keyBuf
 * @param {{ chunkSize?: number }} [opts]
 */
async function encryptBackupFile(srcPath, destPath, keyBuf, { chunkSize = CKB1_DEFAULT_CHUNK_SIZE } = {}) {
  if (!Buffer.isBuffer(keyBuf) || keyBuf.length !== 32) {
    throw new Error('La clave AES-256-GCM debe medir exactamente 32 bytes');
  }
  const safeChunkSize = Math.max(CKB1_MIN_CHUNK_SIZE, Math.min(CKB1_MAX_CHUNK_SIZE, parseInt(String(chunkSize), 10) || CKB1_DEFAULT_CHUNK_SIZE));
  const keyIdHex = computeKeyId(keyBuf);
  const keyIdBuf = Buffer.from(keyIdHex, 'hex');
  const baseNonce = crypto.randomBytes(12);

  const stat = await fs.promises.stat(srcPath);
  const totalPlain = stat.size;

  const header = Buffer.alloc(CKB1_HEADER_LEN);
  CKB1_MAGIC.copy(header, 0);
  header[4] = CKB1_VERSION;
  header[5] = CKB1_CIPHER_SUITE;
  keyIdBuf.copy(header, 8, 0, 8);
  baseNonce.copy(header, 16, 0, 12);
  header.writeUInt32BE(safeChunkSize, 28);

  const inHandle = await fs.promises.open(srcPath, 'r');
  const outHandle = await fs.promises.open(destPath, 'w', 0o600);
  const readBuf = Buffer.alloc(safeChunkSize);
  let encryptedBytes = 0;
  let chunks = 0;

  try {
    await outHandle.write(header, 0, header.length);
    encryptedBytes += header.length;

    let offset = 0;
    const totalChunks = Math.max(1, Math.ceil(totalPlain / safeChunkSize));
    for (let idx = 0; idx < totalChunks; idx++) {
      const toRead = Math.min(safeChunkSize, totalPlain - offset);
      const bytesRead = toRead > 0 ? await readExact(inHandle, readBuf, toRead, offset) : 0;
      offset += bytesRead;
      const isFinal = idx === totalChunks - 1 ? 1 : 0;
      const plainSlice = readBuf.subarray(0, bytesRead);

      const nonce = deriveChunkNonce(baseNonce, idx, isFinal);
      const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, nonce, { authTagLength: CKB1_AUTH_TAG_LEN });
      cipher.setAAD(buildChunkAad(keyIdBuf, idx, isFinal));
      const ct = Buffer.concat([cipher.update(plainSlice), cipher.final()]);
      const tag = cipher.getAuthTag();

      const frameMeta = Buffer.alloc(5);
      frameMeta[0] = isFinal;
      frameMeta.writeUInt32BE(ct.length, 1);

      const frame = Buffer.concat([frameMeta, ct, tag]);
      await outHandle.write(frame, 0, frame.length);
      encryptedBytes += frame.length;
      chunks++;
    }
    return {
      format: 'CKB1',
      cipher: 'aes-256-gcm',
      keyId: keyIdHex,
      chunks,
      plainBytes: totalPlain,
      encryptedBytes
    };
  } catch (err) {
    try { await outHandle.close(); } catch (e) {}
    try { fs.unlinkSync(destPath); } catch (e) {}
    throw err;
  } finally {
    try { await inHandle.close(); } catch (e) {}
    try { await outHandle.close(); } catch (e) {}
  }
}

/**
 * Descifra y verifica criptográficamente un archivo `CKB1` bloque a bloque.
 * Si falla cualquier authTag, el orden, la clave o hay truncamiento/basura al final,
 * elimina `destPath` antes de lanzar error para que NUNCA llegue texto no autenticado a restore().
 *
 * @param {string} srcPath
 * @param {string} destPath
 * @param {Buffer | Map<string, Buffer> | Array<{ keyId?: string, key: Buffer }>} keyOrRing
 */
async function decryptBackupFile(srcPath, destPath, keyOrRing) {
  /** @type {Map<string, Buffer>} */
  const ring = new Map();
  if (Buffer.isBuffer(keyOrRing)) {
    ring.set(computeKeyId(keyOrRing), keyOrRing);
  } else if (keyOrRing instanceof Map) {
    for (const [k, v] of keyOrRing.entries()) ring.set(k, v);
  } else if (Array.isArray(keyOrRing)) {
    for (const item of keyOrRing) {
      if (item && Buffer.isBuffer(item.key) && item.key.length === 32) {
        ring.set(item.keyId || computeKeyId(item.key), item.key);
      }
    }
  }

  const stat = await fs.promises.stat(srcPath);
  if (stat.size < CKB1_HEADER_LEN + 5 + CKB1_AUTH_TAG_LEN) {
    throw new Error('Archivo cifrado CKB1 truncado o corrupto');
  }

  const inHandle = await fs.promises.open(srcPath, 'r');
  const outHandle = await fs.promises.open(destPath, 'w', 0o600);
  let closedOut = false;

  try {
    const hdr = Buffer.alloc(CKB1_HEADER_LEN);
    const hdrRead = await readExact(inHandle, hdr, CKB1_HEADER_LEN, 0);
    if (hdrRead !== CKB1_HEADER_LEN || !hdr.subarray(0, 4).equals(CKB1_MAGIC)) {
      throw new Error('Cabecera CKB1 inválida: el archivo no es un volcado cifrado Culkibo');
    }
    const version = hdr[4];
    const suite = hdr[5];
    if (version !== CKB1_VERSION || suite !== CKB1_CIPHER_SUITE) {
      throw new Error(`Versión o suite CKB1 no soportada (${version}/${suite})`);
    }
    const keyIdBuf = hdr.subarray(8, 16);
    const keyIdHex = keyIdBuf.toString('hex');
    const baseNonce = hdr.subarray(16, 28);
    const chunkSize = hdr.readUInt32BE(28);
    if (chunkSize < CKB1_MIN_CHUNK_SIZE || chunkSize > CKB1_MAX_CHUNK_SIZE) {
      throw new Error(`Tamaño de bloque CKB1 inválido (${chunkSize})`);
    }

    const keyBuf = ring.get(keyIdHex);
    if (!keyBuf || keyBuf.length !== 32) {
      throw new Error(`Clave de descifrado CKB1 no encontrada para keyId ${keyIdHex}`);
    }

    let pos = CKB1_HEADER_LEN;
    let chunkIndex = 0;
    let sawFinal = false;
    let plainBytes = 0;
    const metaBuf = Buffer.alloc(5);

    while (pos < stat.size) {
      if (sawFinal) {
        throw new Error('Archivo cifrado CKB1 alterado: existen bytes sobrantes después del bloque final');
      }
      const metaRead = await readExact(inHandle, metaBuf, 5, pos);
      if (metaRead !== 5) {
        throw new Error('Archivo cifrado CKB1 truncado en cabecera de bloque');
      }
      pos += 5;
      const flags = metaBuf[0];
      if (flags !== 0 && flags !== 1) {
        throw new Error(`Flag de bloque CKB1 inválido: ${flags}`);
      }
      const ctLen = metaBuf.readUInt32BE(1);
      if (ctLen > chunkSize) {
        throw new Error(`Longitud de bloque CKB1 (${ctLen}) supera chunkSize (${chunkSize})`);
      }
      if (pos + ctLen + CKB1_AUTH_TAG_LEN > stat.size) {
        throw new Error('Archivo cifrado CKB1 truncado dentro del bloque de datos/authTag');
      }
      const bodyAndTag = Buffer.alloc(ctLen + CKB1_AUTH_TAG_LEN);
      const got = await readExact(inHandle, bodyAndTag, bodyAndTag.length, pos);
      if (got !== bodyAndTag.length) {
        throw new Error('Lectura incompleta de bloque CKB1');
      }
      pos += got;

      const ct = bodyAndTag.subarray(0, ctLen);
      const tag = bodyAndTag.subarray(ctLen);
      const nonce = deriveChunkNonce(baseNonce, chunkIndex, flags);
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, nonce, { authTagLength: CKB1_AUTH_TAG_LEN });
      decipher.setAAD(buildChunkAad(keyIdBuf, chunkIndex, flags));
      decipher.setAuthTag(tag);

      let plainChunk;
      try {
        plainChunk = Buffer.concat([decipher.update(ct), decipher.final()]);
      } catch (authErr) {
        throw new Error(`Fallo de autenticación AES-256-GCM en bloque #${chunkIndex} (archivo alterado o clave errónea)`);
      }

      if (plainChunk.length > 0) {
        await outHandle.write(plainChunk, 0, plainChunk.length);
        plainBytes += plainChunk.length;
      }
      chunkIndex++;
      if (flags === 1) sawFinal = true;
    }

    if (!sawFinal) {
      throw new Error('Archivo cifrado CKB1 truncado: falta el bloque final autenticado');
    }

    await outHandle.close();
    closedOut = true;
    return { format: 'CKB1', keyId: keyIdHex, chunks: chunkIndex, plainBytes };
  } catch (err) {
    if (!closedOut) {
      try { await outHandle.close(); } catch (e) {}
      closedOut = true;
    }
    try { if (fs.existsSync(destPath)) fs.unlinkSync(destPath); } catch (e) {}
    throw err;
  } finally {
    try { await inHandle.close(); } catch (e) {}
    if (!closedOut) {
      try { await outHandle.close(); } catch (e) {}
    }
  }
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
  /** @param {{ dataDir?: string | null, registerPortProvider?: boolean }} [opts] */
  constructor({ dataDir = null, registerPortProvider = true } = {}) {
    super();
    const dataRoot = dataDir ? path.join(path.resolve(dataDir), 'data') : resolveDefaultDataRoot();
    this.dataFile = path.join(dataRoot, 'databases.json');
    this.keyFile = path.join(dataRoot, '.databases.key');
    this.backupsRoot = path.join(dataRoot, 'backups', 'databases');
    this.tmpDir = path.join(dataRoot, '.tmp');
    /** @type {{ version: number, databases: any[], s3: any, backupEncryption: any }} */
    this.state = { version: 1, databases: [], s3: null, backupEncryption: null };
    /** @type {Buffer | null} */
    this.key = null;
    /** @type {ReturnType<typeof setInterval> | null} */
    this.schedulerTimer = null;
    /** @type {Set<string>} */
    this.runningBackups = new Set();
    /** Operaciones exclusivas activas por BD (`backup` | `restore` | `drill`) para rechazar conflictos al instante con 409. */
    /** @type {Map<string, { kind: string, startedAt: number | string }>} */
    this._activeOps = new Map();
    /** @type {Map<string, Promise<any>>} Mutex por ID de BD para serializar operaciones destructivas */
    this._opLocks = new Map();
    /** Marca si el archivo databases.json falló al parsearse en arranque (protege contra borrado accidental). */
    this._corruptedOnLoad = false;
    /** @type {any} */
    this.dockerChecked = null;
    this._lastWatchdogAt = 0;
    this.ensureDirs();
    this.load();
    if (registerPortProvider) {
      portRegistry.registerProvider('databaseManager', () =>
        this.state.databases
          .filter((d) => d && d.exposure && d.exposure.enabled && d.exposure.hostPort)
          .map((d) => Number(d.exposure.hostPort))
      );
    }
  }

  /**
   * Serializa operaciones de ciclo de vida/exposición/restauración sobre la misma BD.
   * @template T
   * @param {string} id
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async withLock(id, fn) {
    while (this._opLocks.has(id)) {
      try { await this._opLocks.get(id); } catch (e) {}
    }
    const task = Promise.resolve().then(fn).finally(() => {
      if (this._opLocks.get(id) === task) this._opLocks.delete(id);
    });
    this._opLocks.set(id, task);
    return task;
  }

  /** Comprueba que no exista una copia o restauración en curso antes de mutar la BD. */
  assertNoActiveLongOp(id, requestedKind = 'operación') {
    const active = this._activeOps.get(id);
    if (active) {
      const err = new Error(`No se puede ejecutar ${requestedKind}: hay un proceso de "${active.kind}" en curso para esta base de datos`);
      /** @type {any} */ (err).status = 409;
      throw err;
    }
  }

  ensureDirs() {
    for (const dir of [path.dirname(this.dataFile), this.backupsRoot, this.tmpDir]) {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    }
  }

  get cryptoKey() {
    if (!this.key) this.key = loadOrCreateKey(this.keyFile, this.dataFile);
    return this.key;
  }

  load() {
    const bakFile = `${this.dataFile}.bak`;
    let loadedOk = false;
    let hadFile = fs.existsSync(this.dataFile);
    for (const candidate of [this.dataFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && Array.isArray(parsed.databases)) {
          this.state = {
            version: 1,
            s3: parsed.s3 || null,
            backupEncryption: parsed.backupEncryption || null,
            databases: parsed.databases.map((d) => ({
              backups: [],
              restoreHistory: [],
              verificationHistory: [],
              pooler: null,
              tuning: null,
              clonedFrom: null,
              exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
              retention: { daily: 7, weekly: 4, hourly: 0 },
              ...d,
              schedule: {
                enabled: false, cron: '0 3 * * *', nextRunAt: null, lastRunAt: null, lastStatus: null,
                ...(d.schedule || {})
              }
            }))
          };
          loadedOk = true;
          this._corruptedOnLoad = false;
          break;
        }
      } catch (err) {
        console.error(`[Databases] No se pudo leer ${path.basename(candidate)}:`, err.message);
      }
    }
    if (hadFile && !loadedOk) {
      this._corruptedOnLoad = true;
      console.error('[Databases] ADVERTENCIA: databases.json corrupto y sin .bak válido; escritura bloqueada para evitar pérdida de datos.');
    }
  }

  save({ strict = false } = {}) {
    if (this._corruptedOnLoad) {
      const err = new Error('databases.json estaba corrupto al arrancar; repáralo antes de guardar cambios');
      if (strict) throw err;
      console.error('[Databases]', err.message);
      return;
    }
    try {
      if (fs.existsSync(this.dataFile)) {
        try { fs.copyFileSync(this.dataFile, `${this.dataFile}.bak`); } catch (e) {}
      }
      atomicWriteJsonSync(this.dataFile, this.state, 0o600);
    } catch (err) {
      console.error('[Databases] No se pudo guardar databases.json:', err.message);
      if (strict) throw err;
    }
  }

  // -------------------------------------------------------------------------
  // Catálogo
  // -------------------------------------------------------------------------

  listEngines() {
    if (!this._cachedEngines) {
      this._cachedEngines = Object.entries(ENGINES).map(([key, e]) => ({
        engine: key,
        label: e.label,
        family: e.family,
        image: e.image,
        port: e.port,
        licence: e.licence,
        requiresDatabaseName: !e.noDatabaseName,
        supportsPooler: Boolean(e.supportsPooler),
        extensions: e.extensions || []
      }));
    }
    return this._cachedEngines;
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
      const MAX_CAPTURE_BYTES = 1024 * 1024;
      const child = spawn('docker', args, {
        env: env ? { ...process.env, ...env } : process.env,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      let stdout = '';
      let stderr = '';
      let settled = false;
      let timedOut = false;

      const finish = (err, val) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(val);
      };

      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGKILL'); } catch (e) {}
        finish(new Error(`docker ${args[0]} agotó el tiempo de espera (${timeout} ms)`));
      }, timeout);
      if (timer.unref) timer.unref();

      child.stdout.on('data', (d) => {
        if (stdout.length < MAX_CAPTURE_BYTES) stdout += d.toString().slice(0, MAX_CAPTURE_BYTES - stdout.length);
      });
      child.stderr.on('data', (d) => {
        if (stderr.length < MAX_CAPTURE_BYTES) stderr += d.toString().slice(0, MAX_CAPTURE_BYTES - stderr.length);
      });
      child.stdin.on('error', () => {});
      child.on('error', (err) => finish(err));
      child.on('close', (code) => {
        if (timedOut) return;
        if (code === 0) finish(null, { stdout, stderr });
        else finish(new Error(`docker ${args[0]} salió con código ${code}: ${stderr.slice(0, 500)}`));
      });
      if (inputFile) {
        const rs = fs.createReadStream(inputFile);
        rs.on('error', (err) => {
          try { child.kill('SIGKILL'); } catch (e) {}
          finish(err);
        });
        rs.pipe(child.stdin);
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
  /**
   * Asigna una subred `/24` libre en `10.128..254.x.0/24` evitando el límite clásico
   * de ~31 redes bridge por defecto de Docker (`Pool overlaps` — Runtipi #2126/#2140).
   */
  async pickAvailableBridgeSubnet() {
    const usedPrefixes = new Set();
    try {
      const { stdout: idsOut } = await this.docker(['network', 'ls', '-q'], { timeout: 10000 });
      const ids = idsOut.trim().split(/\r?\n/).filter(Boolean).slice(0, 128);
      if (ids.length > 0) {
        const { stdout: insp } = await this.docker(['network', 'inspect', ...ids, '--format', '{{range .IPAM.Config}}{{.Subnet}} {{end}}'], { timeout: 15000 });
        for (const m of insp.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\/\d{1,2}\b/g)) {
          usedPrefixes.add(m[1]);
        }
      }
    } catch (e) {}
    for (let oct2 = 128; oct2 <= 254; oct2++) {
      for (let oct3 = 10; oct3 <= 250; oct3++) {
        const prefix = `10.${oct2}.${oct3}`;
        if (!usedPrefixes.has(prefix)) {
          return `${prefix}.0/24`;
        }
      }
    }
    return null;
  }

  async ensureNetwork(projectId) {
    assertResourceId(projectId, 'projectId');
    const name = this.networkName(projectId);
    try {
      await this.docker(['network', 'inspect', name], { timeout: 10000 });
      return { name, created: false };
    } catch (e) {
      const subnet = await this.pickAvailableBridgeSubnet();
      const createArgs = [
        'network', 'create', '--driver', 'bridge',
        ...(subnet ? ['--subnet', subnet] : []),
        '--label', 'culkibo.managed=true',
        '--label', `culkibo.project=${projectId}`,
        name
      ];
      try {
        await this.docker(createArgs, { timeout: 20000 });
        return { name, created: true };
      } catch (createErr) {
        const msg = String(createErr && createErr.message || '');
        if (/already exists/i.test(msg)) {
          return { name, created: false };
        }
        // Si hubo carrera en la subred elegida, reintentar sin `--subnet` como fallback
        if (subnet && /overlaps|Pool/i.test(msg)) {
          await this.docker(['network', 'create', '--driver', 'bridge', '--label', 'culkibo.managed=true',
            '--label', `culkibo.project=${projectId}`, name], { timeout: 20000 });
          return { name, created: true };
        }
        throw createErr;
      }
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
   *   cpus?: number | string,
   *   tuningPreset?: string
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
    const defaultPreset = engine.family === 'redis' ? 'cache' : 'oltp';
    const tuning = computeTuningConfig(engineKey, {
      memoryMb,
      cpus,
      preset: opts.tuningPreset || defaultPreset
    });

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
      tuning: { preset: tuning.preset, params: tuning.params },
      pooler: null,
      clonedFrom: null,
      // Nunca expuesto al arrancar. Exponer es una decisión posterior y explícita.
      exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
      status: 'provisioning',
      health: 'unknown',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      schedule: { enabled: false, cron: '0 3 * * *', nextRunAt: null, lastRunAt: null, lastStatus: null },
      retention: { daily: 7, weekly: 4 },
      backups: [],
      restoreHistory: [],
      verificationHistory: []
    };

    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible: no se puede aprovisionar una base de datos gestionada');
    }

    await this.ensureNetwork(projectId);

    const envVars = {
      ...engine.initEnv({ username, password, dbName }),
      ...engine.clientEnv({ password }),
      ...(tuning.env || {})
    };
    const envFile = path.join(this.tmpDir, `env_${id}_${crypto.randomBytes(6).toString('hex')}`);

    const hasSameEngineInProject = this.state.databases.some(
      (d) => d.projectId === projectId && d.engine === engineKey
    );
    const engineCmd = engine.command
      ? engine.command({ tuning })
      : (tuning.commandArgs || []);
    const args = [
      'run', '-d',
      '--name', record.containerName,
      '--restart', 'unless-stopped',
      '--network', record.networkName,
      // Solo asignar alias corto del motor si es la primera BD de ese motor en el proyecto (evita DNS round-robin)
      ...(!hasSameEngineInProject ? ['--network-alias', engineKey] : []),
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
      '--log-driver', 'json-file',
      '--log-opt', 'max-size=10m',
      '--log-opt', 'max-file=3',
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
      ...engineCmd
    ];

    try {
      fs.writeFileSync(
        envFile,
        formatDockerEnvFile(envVars),
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
    this.save({ strict: true });
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
    return this.withLock(id, async () => {
      this.assertNoActiveLongOp(id, 'cambio de exposición');
      const record = this.mustGet(id);
      const engine = ENGINES[record.engine];
      const prevExposure = record.exposure ? { ...record.exposure } : { enabled: false, bindAddress: '127.0.0.1', hostPort: null };
      const prevStatus = record.status;

      if (!enabled) {
        record.exposure = { enabled: false, bindAddress: '127.0.0.1', hostPort: null };
        try {
          await this.recreateContainer(record);
          this.save({ strict: true });
        } catch (err) {
          record.exposure = prevExposure;
          record.status = 'error';
          record.lastError = err.message;
          try { await this.recreateContainer(record); record.status = prevStatus || 'running'; } catch (e2) {}
          this.save();
          throw err;
        }
        return { ...this.toPublic(record), warning: null };
      }

      const bind = String(bindAddress || '127.0.0.1').trim();
      if (!net.isIPv4(bind)) {
        throw new Error('Dirección de enlace inválida: usa una IPv4 válida (127.0.0.1 para sólo local)');
      }

      const publicBind = !bind.startsWith('127.');
      if (publicBind && acknowledgeRisk !== true) {
        throw new Error(
          `Publicar en ${bind} expone la base de datos fuera de loopback y las reglas de Docker se ` +
          'saltan UFW/firewalld. Repite la operación con acknowledgeRisk: true si es lo que quieres.'
        );
      }

      let port = parseInt(String(hostPort ?? ''), 10) || engine.port;
      if (!(port > 0 && port < 65536)) throw new Error('Puerto de host inválido');

      const checkPortAvailable = async (candidatePort) => {
        const takenByOther = this.state.databases.some(
          (d) => d.id !== id && d.exposure && d.exposure.enabled && d.exposure.hostPort === candidatePort
        );
        if (takenByOther || portRegistry.isProtectedPort(candidatePort, 'databaseManager')) return false;
        const isSame = prevExposure.enabled && prevExposure.hostPort === candidatePort && prevExposure.bindAddress === bind;
        if (isSame) return true;
        return new Promise((resolve) => {
          const probe = net.createServer()
            .once('error', () => resolve(false))
            .once('listening', () => probe.once('close', () => resolve(true)).close())
            .listen(candidatePort, bind);
        });
      };

      const leaseOwner = `db_${id}`;
      /** @type {number | null} */
      let leasedPort = null;
      const preferredFree = await checkPortAvailable(port);
      if (!preferredFree) {
        // Si el usuario NO fijó puerto explícito, asignar un puerto libre automáticamente (evita colisión en 2ª BD del mismo motor)
        if (hostPort == null || String(hostPort).trim() === '') {
          port = await portRegistry.allocate({ kind: 'database', owner: leaseOwner, preferred: engine.port + 100, host: bind });
          leasedPort = port;
        } else {
          throw new Error(`El puerto ${bind}:${port} ya está ocupado en el host o reservado por otro servicio`);
        }
      }

      record.exposure = { enabled: true, bindAddress: bind, hostPort: port };
      try {
        await this.recreateContainer(record);
        this.save({ strict: true });
      } catch (err) {
        record.exposure = prevExposure;
        record.status = 'error';
        record.lastError = err.message;
        try {
          await this.recreateContainer(record);
          record.status = prevStatus || 'running';
        } catch (e2) {}
        this.save();
        throw err;
      } finally {
        if (leasedPort !== null) {
          portRegistry.release(leasedPort, leaseOwner);
        }
      }

      return {
        ...this.toPublic(record),
        warning: publicBind
          ? `La base de datos ${record.name} está accesible en ${bind}:${port} desde cualquier origen que ` +
            'alcance este host. Docker publica el puerto por debajo de UFW: su cortafuegos NO la protege. ' +
            'Restrinja el acceso en el proveedor de red o vuelva a 127.0.0.1.'
          : `Accesible sólo desde este host en 127.0.0.1:${port}. Para acceso remoto use un túnel SSH.`
      };
    });
  }

  /**
   * Recrea el contenedor conservando volumen y contraseña con parada ordenada (`docker stop -t 30`)
   * para que Redis/Valkey/PostgreSQL/MySQL vuelquen sus datos antes de sustituir el contenedor.
   */
  async recreateContainer(record) {
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible');
    }
    const engine = ENGINES[record.engine];
    const password = this.decryptPassword(record);

    await this.ensureNetwork(record.projectId);
    // P0: parada ordenada antes de eliminar (jamás SIGKILL inmediato con `rm -f`)
    try { await this.docker(['stop', '-t', '30', record.containerName], { timeout: 45000 }); } catch (e) {}
    try { await this.docker(['rm', record.containerName], { timeout: 30000 }); } catch (e) {
      try { await this.docker(['rm', '-f', record.containerName], { timeout: 30000 }); } catch (e2) {}
    }

    const preset = (record.tuning && record.tuning.preset) || (engine.family === 'redis' ? 'cache' : 'oltp');
    const tuning = computeTuningConfig(record.engine, { memoryMb: record.memoryMb, cpus: record.cpus, preset });
    record.tuning = { preset: tuning.preset, params: tuning.params };

    const envVars = {
      ...engine.initEnv({ username: record.username, password, dbName: record.dbName }),
      ...engine.clientEnv({ password }),
      ...(tuning.env || {})
    };
    const envFile = path.join(this.tmpDir, `env_${record.id}_${crypto.randomBytes(6).toString('hex')}`);

    const sameEngineEarlier = this.state.databases.some(
      (d) => d.id !== record.id && d.projectId === record.projectId && d.engine === record.engine
    );

    const args = [
      'run', '-d',
      '--name', record.containerName,
      '--restart', 'unless-stopped',
      '--network', record.networkName,
      ...(!sameEngineEarlier ? ['--network-alias', record.engine] : []),
      '-v', `${record.volumeName}:${record.dataDir || this.resolveDataDir(engine, record.image)}`,
      '--env-file', envFile,
      '--memory', `${record.memoryMb}m`,
      '--memory-swap', `${record.memoryMb}m`,
      '--cpus', String(record.cpus),
      '--pids-limit', '512',
      '--security-opt', 'no-new-privileges',
      '--log-driver', 'json-file',
      '--log-opt', 'max-size=10m',
      '--log-opt', 'max-file=3',
      '--health-cmd', engine.health({ username: record.username, dbName: record.dbName }),
      '--health-interval', '10s',
      '--health-timeout', '5s',
      '--health-retries', '5',
      '--health-start-period', '40s',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${record.projectId}`,
      '--label', `culkibo.database=${record.id}`,
      '--label', `culkibo.engine=${record.engine}`
    ];

    if (record.exposure && record.exposure.enabled) {
      args.push('-p', `${record.exposure.bindAddress}:${record.exposure.hostPort}:${engine.port}`);
    }
    const engineCmd = engine.command
      ? engine.command({ tuning })
      : (tuning.commandArgs || []);
    args.push(record.image, ...engineCmd);

    try {
      fs.writeFileSync(
        envFile,
        formatDockerEnvFile(envVars),
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

  /** Actualiza el preset de afinado y/o recursos RAM/CPU y recrea el contenedor sin perder el volumen. */
  async setTuning(id, { preset = 'oltp', memoryMb = undefined, cpus = undefined } = {}) {
    return this.withLock(id, async () => {
      this.assertNoActiveLongOp(id, 'cambio de tuning');
      const record = this.mustGet(id);
      const nextMem = memoryMb !== undefined
        ? Math.max(128, Math.min(65536, parseInt(String(memoryMb), 10) || record.memoryMb))
        : record.memoryMb;
      const nextCpus = cpus !== undefined
        ? Math.max(0.1, Math.min(32, Number(cpus) || record.cpus))
        : record.cpus;
      const tuning = computeTuningConfig(record.engine, { memoryMb: nextMem, cpus: nextCpus, preset });
      record.memoryMb = nextMem;
      record.cpus = nextCpus;
      record.tuning = { preset: tuning.preset, params: tuning.params };
      await this.recreateContainer(record);
      this.save({ strict: true });
      return this.toPublic(record);
    });
  }

  /**
   * Construye la especificación argv + `--env-file` (0 secretos en argv) de un
   * sidecar PgBouncer co-localizado en la red del proyecto (puerto 6432).
   */
  buildPoolerSpec(record, password, { poolMode = 'transaction', maxClientConn = 500, defaultPoolSize = 20, port = 6432 } = {}) {
    const engine = ENGINES[record.engine];
    if (!engine || !engine.supportsPooler) {
      throw new Error(`El motor ${record.engine} no soporta pooler PgBouncer (sólo PostgreSQL, pgvector y TimescaleDB)`);
    }
    const mode = String(poolMode || 'transaction').toLowerCase();
    if (!VALID_POOL_MODES.has(mode)) {
      throw new Error(`poolMode inválido: ${poolMode}. Usa: transaction, session o statement`);
    }
    const safeMaxClient = Math.max(10, Math.min(10000, parseInt(String(maxClientConn), 10) || 500));
    const safePoolSize = Math.max(2, Math.min(500, parseInt(String(defaultPoolSize), 10) || 20));
    const safePort = Math.max(1024, Math.min(65535, parseInt(String(port), 10) || 6432));
    const containerName = `culkibo_pooler_${record.id}`;
    const envVars = {
      DB_HOST: record.containerName,
      DB_PORT: String(record.port),
      DB_USER: record.username,
      DB_PASSWORD: password,
      DB_NAME: record.dbName,
      LISTEN_PORT: String(safePort),
      POOL_MODE: mode,
      MAX_CLIENT_CONN: String(safeMaxClient),
      DEFAULT_POOL_SIZE: String(safePoolSize),
      AUTH_TYPE: 'scram-sha-256',
      IGNORE_STARTUP_PARAMETERS: 'extra_float_digits'
    };
    const argsForEnvFile = (envFilePath) => [
      'run', '-d',
      '--name', containerName,
      '--restart', 'unless-stopped',
      '--network', record.networkName,
      '--env-file', envFilePath,
      '--memory', '128m',
      '--memory-swap', '128m',
      '--cpus', '0.5',
      '--pids-limit', '256',
      '--security-opt', 'no-new-privileges',
      '--log-driver', 'json-file',
      '--log-opt', 'max-size=5m',
      '--log-opt', 'max-file=2',
      '--health-cmd', `pg_isready -h 127.0.0.1 -p ${safePort}`,
      '--health-interval', '10s',
      '--health-timeout', '5s',
      '--health-retries', '5',
      '--label', 'culkibo.managed=true',
      '--label', `culkibo.project=${record.projectId}`,
      '--label', `culkibo.database=${record.id}`,
      '--label', 'culkibo.role=pgbouncer',
      PGBOUNCER_IMAGE
    ];
    return {
      image: PGBOUNCER_IMAGE,
      containerName,
      port: safePort,
      poolMode: mode,
      maxClientConn: safeMaxClient,
      defaultPoolSize: safePoolSize,
      envVars,
      argsForEnvFile
    };
  }

  /** Activa, actualiza o desactiva el pooler PgBouncer co-localizado para una BD PostgreSQL. */
  async configurePooler(id, { enabled = true, poolMode = 'transaction', maxClientConn = 500, defaultPoolSize = 20, port = 6432 } = {}) {
    return this.withLock(id, async () => {
      this.assertNoActiveLongOp(id, 'configuración de pooler');
      const record = this.mustGet(id);
      const engine = ENGINES[record.engine];
      if (!engine || !engine.supportsPooler) {
        throw new Error(`El motor ${record.engine} no soporta pooler PgBouncer (sólo PostgreSQL, pgvector y TimescaleDB)`);
      }
      if (!(await this.isDockerAvailable())) {
        throw new Error('Docker no está disponible');
      }

      const poolerContainer = `culkibo_pooler_${record.id}`;
      try { await this.docker(['stop', '-t', '15', poolerContainer], { timeout: 30000 }); } catch (e) {}
      try { await this.docker(['rm', '-f', poolerContainer], { timeout: 20000 }); } catch (e) {}

      if (!enabled) {
        record.pooler = { enabled: false, containerName: poolerContainer, port: 6432, poolMode: 'transaction', maxClientConn: 500, defaultPoolSize: 20, image: PGBOUNCER_IMAGE };
        record.updatedAt = new Date().toISOString();
        this.save({ strict: true });
        return this.toPublic(record);
      }

      const password = this.decryptPassword(record);
      const spec = this.buildPoolerSpec(record, password, { poolMode, maxClientConn, defaultPoolSize, port });
      await this.ensureNetwork(record.projectId);
      const envFile = path.join(this.tmpDir, `env_pooler_${record.id}_${crypto.randomBytes(6).toString('hex')}`);
      try {
        fs.writeFileSync(envFile, formatDockerEnvFile(spec.envVars), { encoding: 'utf8', mode: 0o600 });
        await this.docker(spec.argsForEnvFile(envFile), { timeout: 120000 });
      } finally {
        try { fs.unlinkSync(envFile); } catch (e) {}
      }

      record.pooler = {
        enabled: true,
        containerName: spec.containerName,
        port: spec.port,
        poolMode: spec.poolMode,
        maxClientConn: spec.maxClientConn,
        defaultPoolSize: spec.defaultPoolSize,
        image: spec.image
      };
      record.updatedAt = new Date().toISOString();
      this.save({ strict: true });
      return this.toPublic(record);
    });
  }

  /** Recupera un contenedor desaparecido conservando intacto su volumen y contraseña. */
  async recoverContainer(id) {
    return this.withLock(id, async () => {
      this.assertNoActiveLongOp(id, 'recuperación de contenedor');
      const record = this.mustGet(id);
      await this.recreateContainer(record);
      this.save({ strict: true });
      return this.toPublic(record);
    });
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
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      await this.docker(['start', record.containerName], { timeout: 60000 });
      record.status = 'running';
      record.updatedAt = new Date().toISOString();
      this.save();
      return this.toPublic(record);
    });
  }

  async stop(id) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      await this.docker(['stop', record.containerName], { timeout: 90000 });
      record.status = 'stopped';
      record.updatedAt = new Date().toISOString();
      this.save();
      return this.toPublic(record);
    });
  }

  async restart(id) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      await this.docker(['restart', record.containerName], { timeout: 120000 });
      record.status = 'running';
      record.updatedAt = new Date().toISOString();
      this.save();
      return this.toPublic(record);
    });
  }

  /**
   * Elimina el contenedor. El volumen sólo se borra si se pide explícitamente:
   * un clic de más no puede destruir los datos de producción de nadie.
   */
  async remove(id, { deleteVolume = false, deleteBackups = false } = {}) {
    return this.withLock(id, async () => {
      this.assertNoActiveLongOp(id, 'eliminación');
      const record = this.mustGet(id);
      if (await this.isDockerAvailable()) {
        if (record.pooler && record.pooler.containerName) {
          try { await this.docker(['stop', '-t', '15', record.pooler.containerName], { timeout: 30000 }); } catch (e) {}
          try { await this.docker(['rm', '-f', record.pooler.containerName], { timeout: 20000 }); } catch (e) {}
        }
        // Parada ordenada antes de eliminar para no corromper un volumen conservado
        try { await this.docker(['stop', '-t', '30', record.containerName], { timeout: 45000 }); } catch (e) {}
        try { await this.docker(['rm', record.containerName], { timeout: 30000 }); } catch (e) {
          try { await this.docker(['rm', '-f', record.containerName], { timeout: 30000 }); } catch (e2) {}
        }
        if (deleteVolume) {
          try { await this.docker(['volume', 'rm', record.volumeName], { timeout: 30000 }); } catch (e) {}
        }
      }
      if (deleteBackups) {
        try { fs.rmSync(path.join(this.backupsRoot, record.id), { recursive: true, force: true }); } catch (e) {}
      }
      this.state.databases = this.state.databases.filter((d) => d.id !== id);
      this.save({ strict: true });

      // Si era la última BD del proyecto y la red dedicada está vacía, liberarla para no agotar subredes
      if (record.networkName && !this.state.databases.some((d) => d.networkName === record.networkName)) {
        try { await this.docker(['network', 'rm', record.networkName], { timeout: 10000 }); } catch (e) {}
      }

      // Limpiar referencias obsoletas en linkedDatabaseIds de los proyectos
      try {
        const pm = require('./projectManager');
        for (const p of pm.getAll()) {
          if (Array.isArray(p.linkedDatabaseIds) && p.linkedDatabaseIds.includes(id)) {
            pm.update(p.id, { linkedDatabaseIds: p.linkedDatabaseIds.filter((x) => x !== id) });
          }
        }
      } catch (e) {}

      this.emit('database_deleted', { id, volumeDeleted: deleteVolume });
      return { success: true, id, volumeDeleted: deleteVolume, backupsDeleted: deleteBackups };
    });
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
    const newestVerified = (record.backups || []).find((b) => b && b.lastVerification && b.lastVerification.ok);
    const poolerActive = Boolean(record.pooler && record.pooler.enabled);
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
      tuning: record.tuning || null,
      pooler: record.pooler || null,
      clonedFrom: record.clonedFrom || null,
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
      restoreHistoryCount: (record.restoreHistory || []).length,
      lastVerifiedAt: newestVerified ? newestVerified.lastVerification.verifiedAt : null,
      activeOperation: this._activeOps.get(record.id) || null,
      // Plantilla sin secreto: útil en la interfaz sin filtrar nada.
      connectionTemplate: this.buildConnectionString(record, '********'),
      pooledConnectionTemplate: poolerActive
        ? this.buildConnectionString(record, '********', { host: record.pooler.containerName, port: record.pooler.port })
        : null,
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
    const poolerActive = Boolean(record.pooler && record.pooler.enabled);
    return {
      id: record.id,
      username: record.username,
      password,
      dbName: record.dbName,
      host: record.containerName,
      port: record.port,
      internalConnectionString: this.buildConnectionString(record, password),
      pooledConnectionString: poolerActive
        ? this.buildConnectionString(record, password, { host: record.pooler.containerName, port: record.pooler.port })
        : null,
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
      case 'clickhouse':
        return `http://${record.username}:${pass}@${host}:${port}/${record.dbName}`;
      case 'qdrant':
      case 'meilisearch':
        return `http://${host}:${port}`;
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
    const dir = path.join(this.backupsRoot, id);
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
   * Escribe un fichero efímero 0600 de credenciales para motores cuyos clientes
   * CLI no leen la clave desde variables de entorno (MongoDB, ClickHouse, Qdrant, Meilisearch).
   */
  _writeEngineAuthConfig(engine, password, tag = 'auth') {
    const format = engine.configFormat || 'mongo-yaml';
    const rand = crypto.randomBytes(6).toString('hex');
    let ext = '.yml';
    let content = `password: ${JSON.stringify(password)}\n`;
    if (format === 'clickhouse-xml') {
      ext = '.xml';
      const escaped = String(password).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      content = `<config><password>${escaped}</password></config>\n`;
    } else if (format === 'curl-qdrant') {
      ext = '.cfg';
      const clean = String(password).replace(/["\r\n\\]/g, '');
      content = `header = "api-key: ${clean}"\n`;
    } else if (format === 'curl-meilisearch') {
      ext = '.cfg';
      const clean = String(password).replace(/["\r\n\\]/g, '');
      content = `header = "Authorization: Bearer ${clean}"\n`;
    }
    const localPath = path.join(this.tmpDir, `${tag}_${rand}${ext}`);
    const containerPath = `/tmp/.culkibo_${tag}_${rand}${ext}`;
    fs.writeFileSync(localPath, content, { encoding: 'utf8', mode: 0o600 });
    return { localPath, containerPath, format };
  }

  /**
   * Ejecuta un volcado completo con cifrado cliente AEAD (`CKB1`) opcional antes de subir a S3/R2.
   * @param {string} id
   * @param {{ trigger?: string, skipS3?: boolean, skipRetention?: boolean, pinned?: boolean, bypassOpGuard?: boolean, encrypt?: boolean }} [opts]
   */
  async runBackup(id, { trigger = 'manual', skipS3 = false, skipRetention = false, pinned = false, bypassOpGuard = false, encrypt = undefined } = {}) {
    const record = this.mustGet(id);
    if (this.runningBackups.has(id)) {
      throw new Error('Ya hay una copia en curso para esta base de datos');
    }
    if (!bypassOpGuard) {
      this.assertNoActiveLongOp(id);
    }
    // Reservar slot ANTES del primer await (isDockerAvailable) para que MAX_CONCURRENT_BACKUPS se cumpla en tick()
    this.runningBackups.add(id);
    const startedAt = Date.now();
    if (!bypassOpGuard) {
      this._activeOps.set(id, { kind: 'backup', startedAt });
    }
    if (!(await this.isDockerAvailable())) {
      this.runningBackups.delete(id);
      if (!bypassOpGuard) this._activeOps.delete(id);
      throw new Error('Docker no está disponible: no se puede ejecutar la copia');
    }
    const engine = ENGINES[record.engine];
    const password = this.decryptPassword(record);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseName = `${record.engine}_${record.id}_${stamp}${engine.dumpExt}`;
    const containerPath = `/tmp/${baseName}`;
    const localPath = path.join(this.backupDir(id), baseName);
    /** @type {string | null} */
    let finalPath = null;
    /** @type {string | null} */
    let encryptedPath = null;
    let savedLocally = false;
    /** @type {string | null} */
    let configInContainer = null;

    try {
      const specEngine = engine.family === 'postgresql' ? 'postgresql' : record.engine;
      const spec = dbBackupManager.buildDbDumpSpec(specEngine, {
        host: '127.0.0.1',
        port: engine.nativePort || engine.port,
        user: engine.dumpUser || record.username,
        password,
        dbName: record.dbName || 'app',
        outputFile: containerPath
      });

      let args = [...spec.args];

      // Las opciones extra van ANTES del último argumento (deduplicadas)
      if (engine.dumpExtraArgs && engine.dumpExtraArgs.length) {
        const extraToAdd = engine.dumpExtraArgs.filter((flag) => !args.includes(flag));
        if (extraToAdd.length) {
          args.splice(Math.max(0, args.length - 1), 0, ...extraToAdd);
        }
      }

      if (engine.usesConfigFile) {
        // Quitamos cualquier --password=... y pasamos credenciales mediante archivo 0600 efímero
        args = args.filter((a) => !String(a).startsWith('--password='));
        const authCfg = this._writeEngineAuthConfig(engine, password, `auth_${record.id}`);
        configInContainer = authCfg.containerPath;
        try {
          await this.docker(['cp', authCfg.localPath, `${record.containerName}:${configInContainer}`], { timeout: 30000 });
        } finally {
          try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
        }
        if (authCfg.format === 'clickhouse-xml') {
          args = ['--config-file', configInContainer, ...args];
        } else if (authCfg.format === 'curl-qdrant' || authCfg.format === 'curl-meilisearch') {
          args = ['-K', configInContainer, ...args];
        } else {
          args = [`--config=${configInContainer}`, ...args];
        }
      }

      // Sin `-e`: el entorno necesario ya está dentro del contenedor.
      const program = engine.dumpProgram || spec.program;
      await this.docker(
        ['exec', record.containerName, ...this.wrapInContainer(engine, program, args)],
        { timeout: 6 * 3600 * 1000 }
      );

      await this.docker(['cp', `${record.containerName}:${containerPath}`, localPath], { timeout: 3600 * 1000 });

      // Comprobar tamaño ANTES de gzip (gzip de 0 bytes produce 20 bytes de cabecera y ocultaba volcados vacíos)
      const rawStat = fs.statSync(localPath);
      if (rawStat.size <= 0) {
        throw new Error('El volcado generado está vacío (0 bytes antes de comprimir)');
      }

      // mongodump (.archive.gz) y clickhouse (.zip) ya salen comprimidos; el resto pasa por gzip.
      finalPath = localPath;
      if (!baseName.endsWith('.gz') && !baseName.endsWith('.zip')) {
        finalPath = `${localPath}.gz`;
        await this.gzipFile(localPath, finalPath);
        try { fs.unlinkSync(localPath); } catch (e) {}
      }

      // Cifrado autenticado AES-256-GCM en streaming (`CKB1`) ANTES de subir a S3/R2
      const shouldEncrypt = encrypt === true || (encrypt !== false && Boolean(this.state.backupEncryption && this.state.backupEncryption.enabled));
      /** @type {any} */
      let encryptionMeta = null;
      if (shouldEncrypt) {
        const activeKey = this._getActiveBackupKey();
        if (!activeKey) {
          throw new Error('El cifrado de copias está activado pero no hay ninguna clave activa configurada');
        }
        encryptedPath = `${finalPath}.ckb1`;
        const encInfo = await encryptBackupFile(finalPath, encryptedPath, activeKey.key);
        try { fs.unlinkSync(finalPath); } catch (e) {}
        finalPath = encryptedPath;
        encryptionMeta = {
          format: encInfo.format,
          cipher: encInfo.cipher,
          keyId: encInfo.keyId,
          chunks: encInfo.chunks,
          plainBytes: encInfo.plainBytes
        };
      }

      const stat = fs.statSync(finalPath);
      if (stat.size <= 0) {
        throw new Error('El volcado generado está vacío (0 bytes)');
      }

      /** @type {any} */
      const entry = {
        id: `bk_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
        fileName: path.basename(finalPath),
        sizeBytes: stat.size,
        sha256: await this.sha256File(finalPath),
        createdAt: new Date().toISOString(),
        trigger,
        durationMs: Date.now() - startedAt,
        pinned: Boolean(pinned),
        encrypted: Boolean(encryptionMeta),
        encryption: encryptionMeta,
        lastVerification: null,
        lastDrill: null,
        remote: null,
        remoteError: null
      };

      // Si S3 falla, conservamos la copia local en historial en lugar de descartarla y filtrar el fichero en disco.
      const s3 = skipS3 ? null : this.s3ClientFor();
      if (s3) {
        const key = `${this.s3Prefix()}${record.projectId}/${record.id}/${entry.fileName}`;
        try {
          const uploaded = await s3.uploadFile(key, finalPath, {
            contentType: entry.encrypted ? 'application/octet-stream' : 'application/gzip',
            checksumSha256: true,
            metadata: {
              'culkibo-db-id': record.id,
              'culkibo-engine': record.engine,
              'culkibo-encrypted': entry.encrypted ? 'true' : 'false',
              'culkibo-sha256': entry.sha256,
              ...(entry.encryption ? { 'culkibo-key-id': entry.encryption.keyId } : {})
            }
          });
          entry.remote = {
            key,
            etag: uploaded.etag || null,
            checksumSha256: uploaded.checksumSha256 || null,
            multipart: Boolean(uploaded.multipart),
            uploadedAt: new Date().toISOString()
          };
        } catch (s3Err) {
          entry.remote = null;
          let msg = this.redactMessage(s3Err.message, password);
          if (s3.accessKeyId) msg = this.redactMessage(msg, s3.accessKeyId);
          if (s3.secretAccessKey) msg = this.redactMessage(msg, s3.secretAccessKey);
          entry.remoteError = msg;
          console.warn(`[Databases] Copia local guardada pero falló la subida S3 (${record.name}): ${entry.remoteError}`);
        }
      }

      record.backups.unshift(entry);
      savedLocally = true;
      if (trigger !== 'pre-restore') {
        record.schedule.lastRunAt = entry.createdAt;
        record.schedule.lastStatus = entry.remoteError ? 'local-only' : 'ok';
      }
      record.lastError = entry.remoteError ? `S3: ${entry.remoteError}` : null;
      this.save();

      const pruned = skipRetention ? { pruned: 0, kept: record.backups.length } : await this.applyRetention(id);
      this.emit('backup_completed', { databaseId: id, backupId: entry.id, trigger, remoteError: entry.remoteError });
      try {
        const telOk = require('./telemetryService');
        telOk.recordFeatureUsage(`db_backup:${record.engine}`, !entry.remoteError);
        if (entry.remoteError) {
          telOk.captureOperationFailure({
            operation: 'database_backup',
            stage: 's3_upload',
            kind: record.engine,
            message: entry.remoteError,
            durationMs: entry.durationMs
          });
        }
      } catch (e) {}

      if (trigger !== 'pre-restore') {
        const ns = getNotificationService();
        if (ns && typeof ns.notify === 'function') {
          if (entry.remoteError) {
            Promise.resolve(ns.notify({
              event: 'backup_failed',
              level: 'warning',
              title: `Copia local OK, subida S3 fallida: ${record.name}`,
              message: `La copia ${entry.fileName} se guardó en local, pero falló la subida a S3: ${entry.remoteError}`,
              projectId: record.projectId
            })).catch(() => {});
          } else {
            Promise.resolve(ns.notify({
              event: 'backup_succeeded',
              level: 'info',
              title: `Copia completada: ${record.name}`,
              message: `Copia (${trigger}) de ${record.name} (${record.engine}) completada (${(entry.sizeBytes / 1024).toFixed(1)} KB)${entry.remote ? ' y replicada a S3' : ''}.`,
              projectId: record.projectId
            })).catch(() => {});
          }
        }
      }

      return {
        success: true,
        backup: entry,
        pruned,
        remote: entry.remote ? entry.remote.key : null,
        remoteError: entry.remoteError || null
      };
    } catch (err) {
      if (!savedLocally) {
        try { if (fs.existsSync(localPath)) fs.unlinkSync(localPath); } catch (e) {}
        try { if (finalPath && finalPath !== localPath && fs.existsSync(finalPath)) fs.unlinkSync(finalPath); } catch (e) {}
      }
      if (trigger !== 'pre-restore') {
        record.schedule.lastRunAt = new Date().toISOString();
        record.schedule.lastStatus = 'error';
      }
      record.lastError = this.redactMessage(err.message, password);
      this.save();
      this.emit('backup_failed', { databaseId: id, error: record.lastError });
      try {
        const telErr = require('./telemetryService');
        telErr.recordFeatureUsage(`db_backup:${record.engine}`, false);
        telErr.captureOperationFailure({
          operation: 'database_backup',
          stage: 'dump',
          kind: record.engine,
          message: record.lastError,
          durationMs: Date.now() - startedAt
        });
      } catch (e) {}
      if (trigger !== 'pre-restore') {
        const ns = getNotificationService();
        if (ns && typeof ns.notify === 'function') {
          Promise.resolve(ns.notify({
            event: 'backup_failed',
            level: 'error',
            title: `Copia fallida: ${record.name}`,
            message: `No se pudo completar la copia (${trigger}) de ${record.name} (${record.engine}): ${record.lastError}`,
            projectId: record.projectId
          })).catch(() => {});
        }
      }
      throw new Error(`Copia fallida: ${record.lastError}`);
    } finally {
      try {
        await this.docker(['exec', record.containerName, 'rm', '-f', containerPath], { timeout: 30000 });
      } catch (e) {}
      if (configInContainer) {
        try {
          await this.docker(['exec', record.containerName, 'rm', '-f', configInContainer], { timeout: 15000 });
        } catch (e) {}
      }
      this.runningBackups.delete(id);
      if (!bypassOpGuard && this._activeOps.get(id)?.kind === 'backup') {
        this._activeOps.delete(id);
      }
    }
  }

  async gzipFile(src, dest) {
    await pipeline(fs.createReadStream(src), zlib.createGzip({ level: 6 }), fs.createWriteStream(dest));
  }

  async gunzipFile(src, dest, maxBytes = 2 * 1024 * 1024 * 1024) {
    let total = 0;
    const limiter = new Transform({
      transform(chunk, _enc, cb) {
        total += chunk.length;
        if (total > maxBytes) {
          cb(new Error(`El archivo descomprimido supera el límite seguro de ${Math.round(maxBytes / (1024 * 1024))} MB`));
          return;
        }
        cb(null, chunk);
      }
    });
    try {
      await pipeline(fs.createReadStream(src), zlib.createGunzip(), limiter, fs.createWriteStream(dest));
    } catch (err) {
      try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch (e) {}
      throw err;
    }
  }

  /**
   * Valida en streaming que un volcado SQL plano no contenga meta-comandos de
   * cliente (`\!`, `system`, `source`, `COPY ... PROGRAM`, etc.) capaces de
   * ejecutar comandos arbitrarios dentro del contenedor al restaurar.
   * @param {string} filePath
   * @param {string} family
   */
  async assertSafeSqlFile(filePath, family) {
    const isPg = family === 'postgresql';
    // En psql, `\gexec`, `\g |cmd`, `\o |cmd`, `\!` y `\copy ... program` pueden ir
    // tanto al inicio de línea como tras una sentencia SQL en la misma línea (`SELECT ... \gexec`).
    const pgMetaRe = /(?:^|\s)\\(?:!|gexec\b|g\s+\||o\s+\||copy\b[\s\S]{0,120}\bprogram\b)|\bCOPY\b[\s\S]{0,200}\b(?:FROM|TO)\s+PROGRAM\b/im;
    const mysqlMetaRe = /(?:^|[^\\])(?:\\\\)*\\[!TPe.]|^\s*(?:system|tee|pager|edit|source)(?:\s|;|$)/im;
    let carry = '';
    const stream = fs.createReadStream(filePath, { encoding: 'utf8', highWaterMark: 128 * 1024 });
    for await (const chunk of stream) {
      const windowText = carry + chunk;
      const lines = windowText.split(/\r?\n/);
      carry = lines.pop() || '';
      const body = lines.join('\n');
      if (isPg ? pgMetaRe.test(body) : mysqlMetaRe.test(body)) {
        stream.destroy();
        throw new Error(
          isPg
            ? 'Volcado PostgreSQL rechazado por seguridad: contiene meta-comandos de shell (\\!, \\gexec o COPY ... PROGRAM).'
            : 'Volcado SQL rechazado por seguridad: contiene comandos de cliente peligrosos (\\!, system, source, tee o pager).'
        );
      }
    }
    if (carry && (isPg ? pgMetaRe.test(carry) : mysqlMetaRe.test(carry))) {
      throw new Error(
        isPg
          ? 'Volcado PostgreSQL rechazado por seguridad: contiene meta-comandos de shell (\\!, \\gexec o COPY ... PROGRAM).'
          : 'Volcado SQL rechazado por seguridad: contiene comandos de cliente peligrosos (\\!, system, source, tee o pager).'
      );
    }
  }

  /**
   * Filtra en streaming sentencias `USE`, `CREATE DATABASE` y `GTID_PURGED` en
   * volcados MySQL/MariaDB para evitar sobrescribir otra BD o fallar en GTID.
   * @param {string} src
   * @param {string} dest
   */
  async sanitizeMysqlSqlFile(src, dest) {
    const stripLineRe = /^\s*(?:USE\s+`?[a-zA-Z0-9_$-]+`?\s*;?\s*$|CREATE\s+DATABASE\b[^;\n]*;?\s*$|SET\s+@@GLOBAL\.GTID_PURGED\s*=)/i;
    const out = fs.createWriteStream(dest, { encoding: 'utf8', mode: 0o600 });
    let carry = '';
    const reader = fs.createReadStream(src, { encoding: 'utf8', highWaterMark: 128 * 1024 });
    try {
      for await (const chunk of reader) {
        const text = (carry + chunk).replace(/^\uFEFF/, '');
        const lines = text.split(/\r?\n/);
        carry = lines.pop() || '';
        const filtered = lines.map((line) => (stripLineRe.test(line) ? `-- [Culkibo] omitido` : line)).join('\n') + '\n';
        if (!out.write(filtered)) {
          await new Promise((resolve, reject) => {
            out.once('drain', resolve);
            out.once('error', reject);
          });
        }
      }
      if (carry) {
        const finalLine = stripLineRe.test(carry) ? '-- [Culkibo] omitido\n' : `${carry}\n`;
        out.write(finalLine);
      }
      await new Promise((resolve, reject) => {
        out.once('finish', resolve);
        out.once('error', reject);
        out.end();
      });
    } catch (err) {
      out.destroy();
      try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch (e) {}
      throw err;
    }
  }

  /** Comprueba si un fichero en disco comienza por la cabecera gzip (0x1f 0x8b). */
  hasGzipMagic(filePath) {
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.alloc(2);
      const n = fs.readSync(fd, buf, 0, 2, 0);
      return n === 2 && buf[0] === 0x1f && buf[1] === 0x8b;
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Comprueba si un volcado PostgreSQL usa formato personalizado (PGDMP) o SQL plano. */
  isPgCustomFormat(filePath) {
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.alloc(5);
      const n = fs.readSync(fd, buf, 0, 5, 0);
      return n === 5 && buf.toString('ascii') === 'PGDMP';
    } finally {
      fs.closeSync(fd);
    }
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
    return (record.backups || []).map((b) => {
      let localAvailable = false;
      try {
        localAvailable = fs.existsSync(assertContainedPath(dir, b.fileName));
      } catch (e) {}
      return {
        ...b,
        localAvailable,
        remoteAvailable: Boolean(b.remote && b.remote.key)
      };
    });
  }

  /** Resuelve (o descarga desde S3) la ruta local verificada de una copia para descarga en navegador. */
  async getBackupFilePath(id, backupId) {
    const record = this.mustGet(id);
    const entry = (record.backups || []).find((b) => b.id === backupId);
    if (!entry) throw new Error(`Copia ${backupId} no encontrada`);
    const dir = this.backupDir(id);
    const candidate = assertContainedPath(dir, entry.fileName);
    let downloaded = false;

    if (!fs.existsSync(candidate)) {
      if (entry.remote && entry.remote.key) {
        const s3 = this.s3ClientFor();
        if (!s3) throw new Error('La copia sólo existe en remoto y no hay S3 configurado');
        await s3.downloadFile(entry.remote.key, candidate);
        downloaded = true;
      } else {
        throw new Error('El fichero de la copia no existe ni en disco ni en el bucket S3');
      }
    }
    const stat = fs.statSync(candidate);
    return { filePath: candidate, fileName: entry.fileName, sizeBytes: stat.size, downloaded };
  }

  /** Registra una copia subida manualmente por el usuario (.sql, .dump, .gz, .rdb, .archive.gz).
   * @param {string} id
   * @param {{ fileName: string, tempPath: string, sha256?: string | null, sizeBytes?: number }} opts
   */
  async registerUploadedBackup(id, { fileName, tempPath, sha256 = null, sizeBytes = 0 }) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      if (!tempPath || !fs.existsSync(tempPath)) {
        throw new Error('Fichero temporal de copia no encontrado');
      }
      const rawBase = path.basename(String(fileName || 'uploaded.sql.gz')).replace(/[^a-zA-Z0-9._-]/g, '_');
      if (!rawBase || rawBase.startsWith('.')) {
        throw new Error('Nombre de archivo de copia inválido');
      }
      if (!/\.(sql|dump|rdb|gz|archive\.gz|ckb1|zip|snapshot)$/i.test(rawBase)) {
        throw new Error('Formato no soportado. Usa .sql, .sql.gz, .dump, .dump.gz, .rdb, .rdb.gz, .archive.gz, .zip, .snapshot o .ckb1');
      }
      const stat = fs.statSync(tempPath);
      if (stat.size <= 0) {
        throw new Error('El archivo subido está vacío (0 bytes)');
      }
      const isEncryptedUpload = rawBase.endsWith('.ckb1') || hasCkb1Magic(tempPath);
      /** @type {any} */
      let encryptionMeta = null;
      if (isEncryptedUpload) {
        const hdr = inspectCkb1Header(tempPath);
        if (!hdr.valid) {
          throw new Error(`El archivo .ckb1 no tiene una cabecera cifrada válida: ${hdr.reason}`);
        }
        encryptionMeta = { format: 'CKB1', cipher: 'aes-256-gcm', keyId: hdr.keyId };
      } else if (rawBase.endsWith('.gz') && !this.hasGzipMagic(tempPath)) {
        throw new Error('El archivo .gz no tiene una cabecera gzip válida');
      }

      const dir = this.backupDir(id);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const finalName = `upload_${record.engine}_${stamp}_${rawBase.slice(-80)}`;
      const destPath = assertContainedPath(dir, finalName);
      try {
        fs.renameSync(tempPath, destPath);
      } catch (e) {
        fs.copyFileSync(tempPath, destPath);
        try { fs.unlinkSync(tempPath); } catch (_) {}
      }

      const computedHash = sha256 || await this.sha256File(destPath);
      const entry = {
        id: `bk_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
        fileName: finalName,
        sizeBytes: sizeBytes || stat.size,
        sha256: computedHash,
        createdAt: new Date().toISOString(),
        trigger: 'upload',
        durationMs: 0,
        pinned: true,
        encrypted: isEncryptedUpload,
        encryption: encryptionMeta,
        lastVerification: null,
        lastDrill: null,
        remote: null,
        remoteError: null
      };
      record.backups.unshift(entry);
      this.save();
      return entry;
    });
  }

  /** Elimina una copia concreta del historial, del disco local y opcionalmente de S3. */
  async deleteBackup(id, backupId, { deleteRemote = false } = {}) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      this.assertNoActiveLongOp(id);
      const idx = (record.backups || []).findIndex((b) => b.id === backupId);
      if (idx === -1) throw new Error(`Copia ${backupId} no encontrada`);
      const entry = record.backups[idx];
      const dir = this.backupDir(id);
      try {
        const localPath = assertContainedPath(dir, entry.fileName);
        if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
      } catch (e) {}

      let remoteDeleted = false;
      if (deleteRemote && entry.remote && entry.remote.key) {
        const s3 = this.s3ClientFor();
        if (s3) {
          await s3.deleteObject(entry.remote.key);
          remoteDeleted = true;
        }
      }
      record.backups.splice(idx, 1);
      this.save();
      return { success: true, backupId, remoteDeleted };
    });
  }

  // -------------------------------------------------------------------------
  // Restauración
  // -------------------------------------------------------------------------

  /**
   * Restaura desde una copia local o, si ya no está en disco, descargándola
   * primero del bucket. Si la copia está cifrada (`CKB1`), descifra y verifica
   * todos los authTag AES-256-GCM ANTES de tocar la base activa.
   */
  /** @param {string} id @param {{ backupId?: string | null, remoteKey?: string | null, createSafetySnapshot?: boolean, decryptionKey?: Buffer | null }} [opts] */
  async restore(id, { backupId = null, remoteKey = null, createSafetySnapshot = true, decryptionKey = null } = {}) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      const engine = ENGINES[record.engine];
      this.assertNoActiveLongOp(id);
      if (!(await this.isDockerAvailable())) throw new Error('Docker no está disponible');

      // Reservar el slot de operación activa ANTES de descargar de S3 para impedir colisión con backups programados
      const restoreStartedAt = Date.now();
      this._activeOps.set(id, { kind: 'restore', startedAt: restoreStartedAt });

      const dir = this.backupDir(id);
      /** @type {string | null} */
      let archivePath = null;
      let downloaded = false;
      /** @type {string | null} */
      let tempRemotePath = null;
      /** @type {string | null} */
      let decryptedTempPath = null;
      /** @type {string} */
      let plainPath = '';
      /** @type {string | null} */
      let sanitizedSqlPath = null;
      let madeTemp = false;
      let copiedToContainer = false;
      const inContainer = `/tmp/culkibo_restore_${crypto.randomBytes(6).toString('hex')}`;
      /** @type {any} */
      let safetyBackup = null;
      /** @type {string | null} */
      let safetyBackupWarning = null;
      let methodUsed = engine.family;

      try {
        if (backupId) {
          const entry = (record.backups || []).find((b) => b.id === backupId);
          if (!entry) throw new Error(`Copia ${backupId} no encontrada en el historial`);
          const candidate = assertContainedPath(dir, entry.fileName);
          if (fs.existsSync(candidate)) {
            archivePath = candidate;
            const actual = await this.sha256File(candidate);
            if (entry.sha256 && actual !== entry.sha256) {
              throw new Error('La copia local no coincide con su sha256: fichero corrupto, no se restaura');
            }
          } else if (entry.remote && entry.remote.key) {
            const s3 = this.s3ClientFor();
            if (!s3) throw new Error('La copia sólo existe en remoto y no hay S3 configurado');
            archivePath = candidate;
            await s3.downloadFile(entry.remote.key, archivePath, { expectedSha256Hex: entry.sha256 || null });
            downloaded = true;
            if (entry.sha256) {
              const actual = await this.sha256File(archivePath);
              if (actual !== entry.sha256) {
                try { fs.unlinkSync(archivePath); } catch (e) {}
                throw new Error('La copia descargada de S3 no coincide con su sha256: descarga corrupta, no se restaura');
              }
            }
          } else {
            throw new Error('La copia no está ni en disco ni en el bucket');
          }
        } else if (remoteKey) {
          const s3 = this.s3ClientFor();
          if (!s3) throw new Error('No hay almacenamiento S3 configurado');
          const safeBase = path.basename(String(remoteKey)).replace(/[^a-zA-Z0-9._-]/g, '_') || 'backup.gz';
          tempRemotePath = assertContainedPath(dir, `remote_${Date.now().toString(36)}_${safeBase}`);
          archivePath = tempRemotePath;
          await s3.downloadFile(String(remoteKey), archivePath);
          downloaded = true;
        } else {
          throw new Error('Indique backupId o remoteKey');
        }

        // Validar integridad básica ANTES de crear snapshot o tocar el contenedor vivo
        const archStat = fs.statSync(archivePath);
        if (archStat.size <= 0) {
          throw new Error('El archivo de copia está vacío (0 bytes), no se restaura');
        }

        // Si es un volcado cifrado CKB1, autenticar TODOS los authTag AEAD en staging ANTES de tocar la BD viva
        let workPath = archivePath;
        if (archivePath.endsWith('.ckb1') || hasCkb1Magic(archivePath)) {
          const innerName = path.basename(archivePath).replace(/\.ckb1$/i, '') || 'decrypted.gz';
          decryptedTempPath = path.join(this.tmpDir, `dec_${record.id}_${crypto.randomBytes(5).toString('hex')}_${innerName}`);
          const ring = decryptionKey ? decryptionKey : this._getBackupKeyRing();
          await decryptBackupFile(archivePath, decryptedTempPath, ring);
          workPath = decryptedTempPath;
        }

        if (workPath.endsWith('.gz') && !this.hasGzipMagic(workPath)) {
          throw new Error('El archivo de copia .gz no tiene una cabecera gzip válida, no se restaura');
        }

        // Instantánea automática de seguridad previa a la restauración (1-clic Undo)
        if (createSafetySnapshot !== false) {
          try {
            const snap = await this.runBackup(id, {
              trigger: 'pre-restore',
              skipS3: true,
              skipRetention: true,
              bypassOpGuard: true
            });
            safetyBackup = snap.backup || null;
          } catch (snapErr) {
            safetyBackupWarning = `No se pudo crear la copia previa de seguridad: ${snapErr.message}`;
            console.warn(`[Databases] ${safetyBackupWarning}`);
          }
        }

        plainPath = workPath;
        if (workPath.endsWith('.gz') && !workPath.endsWith('.archive.gz')) {
          plainPath = path.join(this.tmpDir, `restore_${record.id}_${crypto.randomBytes(5).toString('hex')}`);
          madeTemp = true;
          await this.gunzipFile(workPath, plainPath);
        }

        if (engine.family === 'redis') {
          methodUsed = 'rdb-replace';
          const dataDir = record.dataDir || this.resolveDataDir(engine, record.image);
          // Verificar cabecera mágica de 5 bytes `REDIS` antes de detener el contenedor o sustituir dump.rdb
          const rdbHeader = Buffer.alloc(5);
          const rdbFd = fs.openSync(plainPath, 'r');
          try {
            const bytesRead = fs.readSync(rdbFd, rdbHeader, 0, 5, 0);
            if (bytesRead < 5 || rdbHeader.toString('ascii') !== 'REDIS') {
              throw new Error('El archivo de copia no es un volcado RDB de Redis/Valkey válido (falta cabecera mágica REDIS)');
            }
          } finally {
            fs.closeSync(rdbFd);
          }

          await this.docker(['stop', '-t', '30', record.containerName], { timeout: 90000 });
          try {
            try {
              await this.docker(
                ['run', '--rm', '-v', `${record.volumeName}:${dataDir}`, '--entrypoint', 'rm',
                 record.image, '-rf', `${dataDir}/appendonlydir`, `${dataDir}/appendonly.aof`],
                { timeout: 120000 }
              );
            } catch (e) {}
            await this.docker(['cp', plainPath, `${record.containerName}:${dataDir}/dump.rdb`], { timeout: 3600 * 1000 });
          } catch (cpErr) {
            // Nunca dejar Redis detenido si falló el `docker cp`
            try { await this.docker(['start', record.containerName], { timeout: 90000 }); } catch (e) {}
            throw cpErr;
          }
          await this.docker(['start', record.containerName], { timeout: 90000 });
          record.status = 'running';
          this._recordRestoreAudit(record, {
            kind: 'restore',
            backupId,
            remoteKey,
            method: methodUsed,
            status: 'ok',
            safetyBackupId: safetyBackup ? safetyBackup.id : null,
            durationMs: Date.now() - restoreStartedAt
          });
          this.save();
          this.emit('restore_completed', { databaseId: id, method: methodUsed, downloaded, safetyBackupId: safetyBackup ? safetyBackup.id : null });
          return { success: true, databaseId: id, method: methodUsed, downloaded, safetyBackup, safetyBackupWarning };
        }

        if (engine.family === 'mongodb') {
          await this.docker(['cp', plainPath, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
          copiedToContainer = true;
          const authCfg = this._writeEngineAuthConfig(engine, this.decryptPassword(record), `mongo_r_${record.id}`);
          try {
            await this.docker(['cp', authCfg.localPath, `${record.containerName}:${authCfg.containerPath}`], { timeout: 30000 });
            await this.docker([
              'exec', record.containerName, 'mongorestore',
              `--config=${authCfg.containerPath}`,
              `--username=${record.username}`,
              '--authenticationDatabase=admin',
              `--archive=${inContainer}`, '--gzip', '--drop'
            ], { timeout: 6 * 3600 * 1000 });
          } finally {
            try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
            try { await this.docker(['exec', record.containerName, 'rm', '-f', authCfg.containerPath], { timeout: 15000 }); } catch (e) {}
          }
        } else if (engine.family === 'clickhouse') {
          const safeDb = assertIdentifier(record.dbName, 'base de datos');
          await this.docker(['cp', plainPath, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
          copiedToContainer = true;
          const authCfg = this._writeEngineAuthConfig(engine, this.decryptPassword(record), `ch_r_${record.id}`);
          try {
            await this.docker(['cp', authCfg.localPath, `${record.containerName}:${authCfg.containerPath}`], { timeout: 30000 });
            await this.docker([
              'exec', record.containerName, 'clickhouse-client',
              '--config-file', authCfg.containerPath,
              '--user', record.username,
              '--query', `RESTORE DATABASE \`${safeDb}\` FROM File('${inContainer}')`
            ], { timeout: 6 * 3600 * 1000 });
          } finally {
            try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
            try { await this.docker(['exec', record.containerName, 'rm', '-f', authCfg.containerPath], { timeout: 15000 }); } catch (e) {}
          }
        } else if (engine.family === 'qdrant' || engine.family === 'meilisearch') {
          await this.docker(['cp', plainPath, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
          copiedToContainer = true;
          const authCfg = this._writeEngineAuthConfig(engine, this.decryptPassword(record), `${engine.family}_r_${record.id}`);
          try {
            await this.docker(['cp', authCfg.localPath, `${record.containerName}:${authCfg.containerPath}`], { timeout: 30000 });
            if (engine.family === 'qdrant') {
              await this.docker([
                'exec', record.containerName, 'curl', '-fsS', '-K', authCfg.containerPath,
                '-X', 'POST', `http://127.0.0.1:${engine.port}/snapshots/upload`,
                '-F', `snapshot=@${inContainer}`
              ], { timeout: 6 * 3600 * 1000 });
            } else {
              await this.docker([
                'exec', record.containerName, 'curl', '-fsS', '-K', authCfg.containerPath,
                '-X', 'POST', `http://127.0.0.1:${engine.port}/dumps`,
                '--data-binary', `@${inContainer}`
              ], { timeout: 6 * 3600 * 1000 });
            }
          } finally {
            try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
            try { await this.docker(['exec', record.containerName, 'rm', '-f', authCfg.containerPath], { timeout: 15000 }); } catch (e) {}
          }
        } else if (engine.family === 'postgresql') {
          // Cerrar sesiones abiertas sobre la BD para evitar bloqueos en DROP/CREATE de pg_restore o psql
          try {
            const safeDb = assertIdentifier(record.dbName, 'base de datos');
            await this.docker([
              'exec', record.containerName, 'psql',
              '-U', record.username, '-d', 'postgres', '-v', 'ON_ERROR_STOP=0',
              '-c', `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${safeDb}' AND pid <> pg_backend_pid();`
            ], { timeout: 30000 });
          } catch (e) {}

          if (this.isPgCustomFormat(plainPath)) {
            await this.docker(['cp', plainPath, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
            copiedToContainer = true;
            const plan = engine.restore({ username: record.username, dbName: record.dbName, inFile: inContainer });
            const argv = this.wrapInContainer(engine, plan.program, plan.args);
            await this.docker(['exec', record.containerName, ...argv], { timeout: 6 * 3600 * 1000 });
          } else {
            // Volcado SQL plano (.sql / .sql.gz subido manualmente o de otro proveedor)
            await this.assertSafeSqlFile(plainPath, 'postgresql');
            await this.docker([
              'exec', '-i', record.containerName, 'psql',
              '-U', record.username, '-d', record.dbName, '-v', 'ON_ERROR_STOP=1'
            ], { timeout: 6 * 3600 * 1000, inputFile: plainPath });
          }
        } else {
          const plan = engine.restore({ username: record.username, dbName: record.dbName, inFile: inContainer });
          let inputForRestore = plainPath;
          if (plan.stdinFile && (engine.family === 'mysql' || engine.family === 'mariadb')) {
            await this.assertSafeSqlFile(plainPath, engine.family);
            sanitizedSqlPath = path.join(this.tmpDir, `sanitized_${record.id}_${crypto.randomBytes(5).toString('hex')}.sql`);
            await this.sanitizeMysqlSqlFile(plainPath, sanitizedSqlPath);
            inputForRestore = sanitizedSqlPath;
          }
          if (!plan.stdinFile) {
            await this.docker(['cp', inputForRestore, `${record.containerName}:${inContainer}`], { timeout: 3600 * 1000 });
            copiedToContainer = true;
          }
          const argv = this.wrapInContainer(engine, plan.program, plan.args);
          if (plan.stdinFile) {
            await this.docker(['exec', '-i', record.containerName, ...argv], {
              timeout: 6 * 3600 * 1000,
              inputFile: inputForRestore
            });
          } else {
            await this.docker(['exec', record.containerName, ...argv], { timeout: 6 * 3600 * 1000 });
          }
        }

        this._recordRestoreAudit(record, {
          kind: 'restore',
          backupId,
          remoteKey,
          method: methodUsed,
          status: 'ok',
          safetyBackupId: safetyBackup ? safetyBackup.id : null,
          durationMs: Date.now() - restoreStartedAt
        });
        this.save();
        this.emit('restore_completed', { databaseId: id, safetyBackupId: safetyBackup ? safetyBackup.id : null });
        try { require('./telemetryService').recordFeatureUsage(`db_restore:${record.engine}`, true); } catch (e) {}
        return { success: true, databaseId: id, method: methodUsed, downloaded, safetyBackup, safetyBackupWarning };
      } catch (err) {
        const safeErrMsg = this.redactMessage(err.message, this.decryptPassword(record));
        this._recordRestoreAudit(record, {
          kind: 'restore',
          backupId,
          remoteKey,
          method: methodUsed,
          status: 'failed',
          safetyBackupId: safetyBackup ? safetyBackup.id : null,
          durationMs: Date.now() - restoreStartedAt,
          error: safeErrMsg
        });
        this.save();
        this.emit('restore_failed', { databaseId: id, error: safeErrMsg });
        const ns = getNotificationService();
        if (ns && typeof ns.notify === 'function') {
          Promise.resolve(ns.notify({
            event: 'backup_failed',
            level: 'error',
            title: `Restauración fallida: ${record.name}`,
            message: `Error al restaurar ${record.name} (${record.engine}): ${safeErrMsg}`,
            projectId: record.projectId
          })).catch(() => {});
        }
        try {
          const ts = require('./telemetryService');
          ts.recordFeatureUsage(`db_restore:${record.engine}`, false);
          ts.captureOperationFailure({
            operation: 'database_restore',
            stage: 'restore',
            kind: record.engine,
            message: safeErrMsg
          });
        } catch (e) {}
        if (safetyBackup) {
          err.safetyBackupId = safetyBackup.id;
        }
        throw err;
      } finally {
        if (copiedToContainer) {
          try { await this.docker(['exec', record.containerName, 'rm', '-f', inContainer], { timeout: 15000 }); } catch (e) {}
        }
        if (madeTemp && plainPath) { try { fs.unlinkSync(plainPath); } catch (e) {} }
        if (decryptedTempPath) { try { fs.unlinkSync(decryptedTempPath); } catch (e) {} }
        if (sanitizedSqlPath) { try { fs.unlinkSync(sanitizedSqlPath); } catch (e) {} }
        if (tempRemotePath) { try { fs.unlinkSync(tempRemotePath); } catch (e) {} }
        if (this._activeOps.get(id)?.kind === 'restore') {
          this._activeOps.delete(id);
        }
      }
    });
  }

  // -------------------------------------------------------------------------
  // Diagnóstico en vivo e inspección de base de datos
  // -------------------------------------------------------------------------

  /** Inspecciona el estado real del contenedor en Docker (`running`, `exited`, `missing`, ...). */
  async inspectContainer(containerName) {
    try {
      const { stdout } = await this.docker(['inspect', '--format', '{{.State.Status}}', containerName], { timeout: 10000 });
      return (stdout || '').trim() || 'unknown';
    } catch (e) {
      return 'missing';
    }
  }

  /** Comprueba si el volumen de datos persistente existe en Docker. */
  async volumeExists(volumeName) {
    try {
      await this.docker(['volume', 'inspect', volumeName], { timeout: 10000 });
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Comprueba conectividad autenticada real, latencia, versión del motor,
   * tamaño lógico y volumen en disco, y top 15 tablas/colecciones.
   */
  async inspectDatabase(id) {
    const record = this.mustGet(id);
    const engine = ENGINES[record.engine];
    const localBackups = this.listBackups(id);
    const localBackupsBytes = localBackups.reduce((acc, b) => acc + (b.localAvailable ? (Number(b.sizeBytes) || 0) : 0), 0);

    /** @type {any} */
    const base = {
      id: record.id,
      name: record.name,
      engine: record.engine,
      reachable: false,
      latencyMs: null,
      version: null,
      dbSizeBytes: null,
      tables: [],
      volumeSizeBytes: null,
      localBackupsBytes,
      localBackupsCount: localBackups.filter((b) => b.localAvailable).length,
      containerStatus: record.status,
      recoverable: false,
      activeOperation: this._activeOps.get(id) || null,
      error: null
    };

    if (!(await this.isDockerAvailable())) {
      base.error = 'Docker no está disponible';
      return base;
    }

    const liveStatus = await this.inspectContainer(record.containerName);
    base.containerStatus = liveStatus;
    if (liveStatus === 'missing') {
      base.recoverable = await this.volumeExists(record.volumeName);
      base.error = base.recoverable
        ? 'El contenedor no existe pero el volumen de datos sigue intacto. Puedes recrearlo sin perder datos.'
        : 'El contenedor no existe en Docker.';
      return base;
    }
    if (liveStatus !== 'running') {
      base.error = `El contenedor está en estado «${liveStatus}»`;
      return base;
    }

    const started = Date.now();
    try {
      if (engine.family === 'postgresql') {
        const ver = await this.docker([
          'exec', record.containerName, 'psql', '-U', record.username, '-d', record.dbName,
          '-tAc', 'SELECT version();'
        ], { timeout: 15000 });
        base.latencyMs = Date.now() - started;
        base.reachable = true;
        base.version = (ver.stdout || '').trim().split('\n')[0] || null;

        const sz = await this.docker([
          'exec', record.containerName, 'psql', '-U', record.username, '-d', record.dbName,
          '-tAc', 'SELECT pg_database_size(current_database());'
        ], { timeout: 15000 });
        const nSz = parseInt((sz.stdout || '').trim(), 10);
        if (Number.isFinite(nSz)) base.dbSizeBytes = nSz;

        const tbl = await this.docker([
          'exec', record.containerName, 'psql', '-U', record.username, '-d', record.dbName,
          '-tAF', '\t', '-c',
          "SELECT schemaname || '.' || relname, pg_total_relation_size(relid), n_live_tup FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 15;"
        ], { timeout: 15000 });
        base.tables = (tbl.stdout || '').trim().split(/\r?\n/).filter(Boolean).map((line) => {
          const [name, size, rows] = line.split('\t');
          return { name, sizeBytes: parseInt(size, 10) || 0, rows: parseInt(rows, 10) || 0 };
        });
      } else if (engine.family === 'mysql' || engine.family === 'mariadb') {
        const cli = record.engine === 'mariadb' ? 'mariadb' : 'mysql';
        const ver = await this.docker([
          'exec', record.containerName, ...this.wrapInContainer(engine, cli, ['-u', 'root', '-N', '-B', '-e', 'SELECT VERSION();'])
        ], { timeout: 15000 });
        base.latencyMs = Date.now() - started;
        base.reachable = true;
        base.version = (ver.stdout || '').trim().split('\n')[0] || null;

        const safeDb = assertIdentifier(record.dbName, 'base de datos');
        const tbl = await this.docker([
          'exec', record.containerName, ...this.wrapInContainer(engine, cli, [
            '-u', 'root', '-N', '-B', '-e',
            `SELECT table_name, IFNULL(data_length + index_length, 0), IFNULL(table_rows, 0) FROM information_schema.tables WHERE table_schema='${safeDb}' ORDER BY (data_length + index_length) DESC LIMIT 15;`
          ])
        ], { timeout: 15000 });
        let total = 0;
        base.tables = (tbl.stdout || '').trim().split(/\r?\n/).filter(Boolean).map((line) => {
          const [name, size, rows] = line.split('\t');
          const s = parseInt(size, 10) || 0;
          total += s;
          return { name, sizeBytes: s, rows: parseInt(rows, 10) || 0 };
        });
        base.dbSizeBytes = total;
      } else if (engine.family === 'redis') {
        const cli = record.engine === 'valkey' ? 'valkey-cli' : 'redis-cli';
        const info = await this.docker(['exec', record.containerName, cli, 'INFO', 'server'], { timeout: 15000 });
        base.latencyMs = Date.now() - started;
        base.reachable = true;
        const verMatch = (info.stdout || '').match(/(?:redis_version|valkey_version):([^\r\n]+)/);
        base.version = verMatch ? `${record.engine} ${verMatch[1].trim()}` : record.engine;
        const mem = await this.docker(['exec', record.containerName, cli, 'INFO', 'memory'], { timeout: 15000 });
        const memMatch = (mem.stdout || '').match(/used_memory:(\d+)/);
        if (memMatch) base.dbSizeBytes = parseInt(memMatch[1], 10);
        const ks = await this.docker(['exec', record.containerName, cli, 'INFO', 'keyspace'], { timeout: 15000 });
        base.tables = (ks.stdout || '').trim().split(/\r?\n/).filter((l) => /^db\d+:/.test(l)).map((l) => {
          const [dbKey, rest] = l.split(':');
          const keysMatch = (rest || '').match(/keys=(\d+)/);
          return { name: dbKey, sizeBytes: 0, rows: keysMatch ? parseInt(keysMatch[1], 10) : 0 };
        });
      } else if (engine.family === 'mongodb') {
        const evalScript = [
          "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD);",
          `const d = db.getSiblingDB(${JSON.stringify(record.dbName)});`,
          "const st = d.stats();",
          "const cols = d.getCollectionNames().slice(0, 15).map(n => ({ name: n, sizeBytes: 0, rows: d.getCollection(n).estimatedDocumentCount() }));",
          "print(JSON.stringify({ version: db.version(), dbSizeBytes: st.dataSize || 0, tables: cols }));"
        ].join(' ');
        const out = await this.docker([
          'exec', record.containerName, 'mongosh', '--quiet', '--eval', evalScript
        ], { timeout: 15000 });
        base.latencyMs = Date.now() - started;
        const lines = (out.stdout || '').trim().split(/\r?\n/).filter(Boolean);
        const lastLine = lines[lines.length - 1] || '';
        try {
          const parsed = JSON.parse(lastLine);
          base.reachable = true;
          base.version = parsed.version ? `MongoDB ${parsed.version}` : record.image;
          base.dbSizeBytes = Number(parsed.dbSizeBytes) || 0;
          base.tables = Array.isArray(parsed.tables) ? parsed.tables : [];
        } catch (e) {
          base.reachable = true;
          base.version = record.image;
        }
      } else if (engine.family === 'clickhouse') {
        const authCfg = this._writeEngineAuthConfig(engine, this.decryptPassword(record), `ch_i_${record.id}`);
        try {
          await this.docker(['cp', authCfg.localPath, `${record.containerName}:${authCfg.containerPath}`], { timeout: 15000 });
          const ver = await this.docker([
            'exec', record.containerName, 'clickhouse-client',
            '--config-file', authCfg.containerPath, '--user', record.username, '--query', 'SELECT version()'
          ], { timeout: 15000 });
          base.latencyMs = Date.now() - started;
          base.reachable = true;
          base.version = `ClickHouse ${(ver.stdout || '').trim()}`;
          const safeDb = assertIdentifier(record.dbName, 'base de datos');
          const tbl = await this.docker([
            'exec', record.containerName, 'clickhouse-client',
            '--config-file', authCfg.containerPath, '--user', record.username, '--query',
            `SELECT name, total_bytes, total_rows FROM system.tables WHERE database='${safeDb}' ORDER BY total_bytes DESC LIMIT 15 FORMAT TSV`
          ], { timeout: 15000 });
          let total = 0;
          base.tables = (tbl.stdout || '').trim().split(/\r?\n/).filter(Boolean).map((line) => {
            const [name, size, rows] = line.split('\t');
            const s = parseInt(size, 10) || 0;
            total += s;
            return { name, sizeBytes: s, rows: parseInt(rows, 10) || 0 };
          });
          base.dbSizeBytes = total;
        } finally {
          try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
          try { await this.docker(['exec', record.containerName, 'rm', '-f', authCfg.containerPath], { timeout: 15000 }); } catch (e) {}
        }
      } else if (engine.family === 'qdrant' || engine.family === 'meilisearch') {
        const authCfg = this._writeEngineAuthConfig(engine, this.decryptPassword(record), `${engine.family}_i_${record.id}`);
        try {
          await this.docker(['cp', authCfg.localPath, `${record.containerName}:${authCfg.containerPath}`], { timeout: 15000 });
          const endpoint = engine.family === 'qdrant'
            ? `http://127.0.0.1:${engine.port}/collections`
            : `http://127.0.0.1:${engine.port}/stats`;
          const out = await this.docker([
            'exec', record.containerName, 'curl', '-fsS', '-K', authCfg.containerPath, endpoint
          ], { timeout: 15000 });
          base.latencyMs = Date.now() - started;
          base.reachable = true;
          base.version = record.image;
          try {
            const parsed = JSON.parse((out.stdout || '').trim());
            if (engine.family === 'qdrant' && Array.isArray(parsed?.result?.collections)) {
              base.tables = parsed.result.collections.slice(0, 15).map((c) => ({ name: c.name, sizeBytes: 0, rows: 0 }));
            } else if (engine.family === 'meilisearch' && parsed) {
              base.dbSizeBytes = Number(parsed.databaseSize) || 0;
              base.tables = Object.entries(parsed.indexes || {}).slice(0, 15).map(([name, info]) => ({
                name, sizeBytes: 0, rows: Number(info?.numberOfDocuments) || 0
              }));
            }
          } catch (e) {}
        } finally {
          try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
          try { await this.docker(['exec', record.containerName, 'rm', '-f', authCfg.containerPath], { timeout: 15000 }); } catch (e) {}
        }
      }

      // Tamaño del volumen en disco con `du -sk` (compatible con BusyBox/Alpine y GNU coreutils)
      try {
        const dataDir = record.dataDir || this.resolveDataDir(engine, record.image);
        const du = await this.docker(['exec', record.containerName, 'du', '-sk', dataDir], { timeout: 15000 });
        const kb = parseInt(((du.stdout || '').trim().split(/\s+/)[0] || ''), 10);
        if (Number.isFinite(kb)) base.volumeSizeBytes = kb * 1024;
      } catch (e) {}
    } catch (err) {
      base.error = this.redactMessage(err.message, this.decryptPassword(record));
    }

    return base;
  }

  // -------------------------------------------------------------------------
  // Retención
  // -------------------------------------------------------------------------

  /**
   * Plan de retención abuelo-padre-hijo (con soporte opcional de ventana horaria
   * y protección de instantáneas `pre-restore` y copias fijadas).
   *
   * @param {Array<{id:string, createdAt:string, trigger?:string, pinned?:boolean, remote?:any, remotePendingDelete?:boolean, localDeleted?:boolean}>} backups
   * @param {{hourly?:number | string, daily?:number | string, weekly?:number | string}} [policy]
   * @returns {{keep:string[], prune:string[], reasons:Object}}
   */
  planRetention(backups, policy = {}) {
    const hourly = Math.max(0, parseInt(String(policy.hourly ?? 0), 10) || 0);
    const daily = Math.max(0, parseInt(String(policy.daily ?? 0), 10) || 0);
    const weekly = Math.max(0, parseInt(String(policy.weekly ?? 0), 10) || 0);

    const validTime = (ts) => {
      const t = new Date(ts).getTime();
      return Number.isFinite(t) ? t : null;
    };

    const sorted = (backups || [])
      .filter((b) => b && b.id && !b.remotePendingDelete && !b.localDeleted && validTime(b.createdAt) !== null)
      .slice()
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const keep = new Set();
    const reasons = {};

    if (sorted.length) {
      keep.add(sorted[0].id);
      reasons[sorted[0].id] = 'última copia';
    }

    // Proteger también la copia S3 remota verificada más reciente (evita borrar el último backup offsite si los últimos locales fallaron al subir)
    const newestRemote = sorted.find((b) => Boolean(b.remote && b.remote.key));
    if (newestRemote && !keep.has(newestRemote.id)) {
      keep.add(newestRemote.id);
      reasons[newestRemote.id] = 'última copia S3 verificada';
    }

    // Proteger copias fijadas y las 3 instantáneas `pre-restore` más recientes
    let preRestoreKept = 0;
    for (const b of sorted) {
      if (b.pinned) {
        if (!keep.has(b.id)) reasons[b.id] = 'fijada';
        keep.add(b.id);
      } else if (b.trigger === 'pre-restore' && preRestoreKept < 3) {
        if (!keep.has(b.id)) reasons[b.id] = 'seguridad pre-restore';
        keep.add(b.id);
        preRestoreKept++;
      }
    }

    // Claves en UTC (evita duplicados/huecos en cambios de horario DST)
    const hourKey = (d) => {
      const x = new Date(d);
      return `${x.getUTCFullYear()}-${String(x.getUTCMonth() + 1).padStart(2, '0')}-${String(x.getUTCDate()).padStart(2, '0')}T${String(x.getUTCHours()).padStart(2, '0')}`;
    };
    const dayKey = (d) => {
      const x = new Date(d);
      return `${x.getUTCFullYear()}-${String(x.getUTCMonth() + 1).padStart(2, '0')}-${String(x.getUTCDate()).padStart(2, '0')}`;
    };
    const weekKey = (d) => {
      const x = new Date(d);
      x.setUTCHours(0, 0, 0, 0);
      x.setUTCDate(x.getUTCDate() + 3 - ((x.getUTCDay() + 6) % 7));
      const jan4 = new Date(Date.UTC(x.getUTCFullYear(), 0, 4));
      const week = 1 + Math.round(((x.getTime() - jan4.getTime()) / 86400000 - 3 + ((jan4.getUTCDay() + 6) % 7)) / 7);
      return `${x.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
    };

    const pickNewestPerBucket = (keyFn, limit, label) => {
      if (limit <= 0) return;
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

    if (hourly > 0) pickNewestPerBucket(hourKey, hourly, 'horaria');
    pickNewestPerBucket(dayKey, daily, 'diaria');
    pickNewestPerBucket(weekKey, weekly, 'semanal');

    return {
      keep: sorted.filter((b) => keep.has(b.id)).map((b) => b.id),
      prune: sorted.filter((b) => !keep.has(b.id)).map((b) => b.id),
      reasons
    };
  }

  /** Aplica el plan: borra el fichero local y el objeto remoto con lock por BD. */
  async applyRetention(id) {
    return this.withLock(id, async () => {
      const record = this.mustGet(id);
      const effectivePolicy = { ...(record.retention || {}) };
      if ((effectivePolicy.hourly == null || effectivePolicy.hourly === 0) && record.schedule?.enabled && isSubDailyCron(record.schedule.cron)) {
        effectivePolicy.hourly = 24;
      }
      const plan = this.planRetention(record.backups, effectivePolicy);
      if (!plan.prune.length) return { pruned: 0, kept: plan.keep.length };

      const dir = this.backupDir(id);
      const s3 = this.s3ClientFor();
      let pruned = 0;
      const keepIds = new Set(plan.keep);

      for (const backupId of plan.prune) {
        const entry = record.backups.find((b) => b.id === backupId);
        if (!entry) continue;
        try {
          const p = assertContainedPath(dir, entry.fileName);
          if (fs.existsSync(p)) fs.unlinkSync(p);
        } catch (e) {}
        if (s3 && entry.remote && entry.remote.key) {
          try {
            await s3.deleteObject(entry.remote.key);
          } catch (e) {
            console.warn(`[Databases] No se pudo borrar el objeto remoto: ${e.message}`);
            // Mantener entrada marcada para no perder rastro del objeto S3 huérfano
            entry.remotePendingDelete = true;
            entry.localDeleted = true;
            keepIds.add(entry.id);
            continue;
          }
        }
        pruned++;
      }

      record.backups = record.backups.filter((b) => keepIds.has(b.id));
      this.save();
      return { pruned, kept: record.backups.length };
    });
  }

  /** @param {string} id @param {{ hourly?: number | string, daily?: number | string, weekly?: number | string }} [opts] */
  setRetention(id, { hourly = 0, daily = 0, weekly = 0 } = {}) {
    const record = this.mustGet(id);
    const h = Math.max(0, Math.min(168, parseInt(String(hourly), 10) || 0));
    const d = Math.max(0, Math.min(365, parseInt(String(daily), 10) || 0));
    const w = Math.max(0, Math.min(260, parseInt(String(weekly), 10) || 0));
    if (h === 0 && d === 0 && w === 0) {
      throw new Error('La retención no puede ser 0 diarias y 0 semanales');
    }
    /** @type {any} */
    const next = { daily: d, weekly: w };
    if (h > 0) next.hourly = h;
    record.retention = next;
    this.save();
    return this.toPublic(record);
  }

  // -------------------------------------------------------------------------
  // Planificador
  // -------------------------------------------------------------------------

  /**
   * Analiza una expresión cron de 5 campos.
   */
  parseCron(expression) {
    const raw = String(expression || '').trim();
    if (raw.length > 200) {
      throw new Error('Expresión cron demasiado larga (máximo 200 caracteres)');
    }
    const expr = CRON_ALIASES[raw] || raw;
    const parts = expr.split(/\s+/).filter(Boolean);
    if (parts.length !== 5) {
      throw new Error(`Expresión cron inválida: se esperan 5 campos, hay ${parts.length}`);
    }

    return parts.map((field, i) => {
      const { name, min, max } = CRON_FIELDS[i];
      const allowed = new Set();

      for (const token of field.split(',')) {
        const slashParts = token.split('/');
        if (slashParts.length > 2) {
          throw new Error(`Token cron inválido en ${name}: ${token}`);
        }
        const [rangePart, stepPart] = slashParts;
        if (stepPart !== undefined && !/^\d+$/.test(stepPart)) {
          throw new Error(`Paso inválido en el campo ${name}: ${token}`);
        }
        const step = stepPart === undefined ? 1 : Number(stepPart);
        if (!Number.isInteger(step) || step < 1) {
          throw new Error(`Paso inválido en el campo ${name}: ${token}`);
        }

        let lo;
        let hi;
        if (rangePart === '*') {
          lo = min; hi = max;
        } else if (rangePart.includes('-')) {
          const bounds = rangePart.split('-');
          if (bounds.length !== 2 || !/^\d+$/.test(bounds[0]) || !/^\d+$/.test(bounds[1])) {
            throw new Error(`Rango inválido en el campo ${name}: ${token}`);
          }
          lo = Number(bounds[0]); hi = Number(bounds[1]);
        } else {
          if (!/^\d+$/.test(rangePart)) {
            throw new Error(`Valor inválido en el campo ${name}: ${token}`);
          }
          lo = Number(rangePart);
          hi = stepPart === undefined ? lo : max;
        }

        if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < min || hi > max || lo > hi) {
          throw new Error(`Valor fuera de rango en el campo ${name}: ${token} (permitido ${min}-${max})`);
        }
        for (let v = lo; v <= hi; v += step) {
          allowed.add(i === 4 && v === 7 ? 0 : v);
        }
      }
      return allowed;
    });
  }

  /**
   * Siguiente ejecución en hora local del servidor, estrictamente posterior a
   * `from`. Devuelve null si no hay ninguna en 366 días.
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
    this.parseCron(expr);

    record.schedule.cron = expr;
    record.schedule.enabled = Boolean(enabled);
    const next = record.schedule.enabled ? this.nextCronRun(expr) : null;
    record.schedule.nextRunAt = next ? next.toISOString() : null;
    this.save();
    if (record.schedule.enabled && !this.schedulerTimer) {
      this.startScheduler({ catchUp: false });
    }
    return this.toPublic(record);
  }

  startScheduler({ intervalMs = SCHEDULER_TICK_MS, catchUp = true } = {}) {
    if (this.schedulerTimer) return this.schedulerTimer;

    if (catchUp) {
      let launched = 0;
      for (const record of this.state.databases) {
        if (!record.schedule || !record.schedule.enabled || !record.schedule.nextRunAt) continue;
        const due = new Date(record.schedule.nextRunAt).getTime();
        const age = Date.now() - due;
        if (age > 0 && age < MAX_CATCH_UP_MS) {
          if (this.runningBackups.size + launched >= MAX_CONCURRENT_BACKUPS) continue;
          const next = this.nextCronRun(record.schedule.cron);
          record.schedule.nextRunAt = next ? next.toISOString() : null;
          this.save();
          launched++;
          console.log(`[Databases] Copia perdida de ${record.name}; recuperando`);
          this.runBackup(record.id, { trigger: 'catch-up' }).catch((e) =>
            console.error(`[Databases] Recuperación fallida: ${e.message}`)
          );
        } else if (age >= MAX_CATCH_UP_MS) {
          // Ventana expirada (>7 días): avanzar nextRunAt para no dejarlo atascado en el pasado
          try {
            const next = this.nextCronRun(record.schedule.cron);
            record.schedule.nextRunAt = next ? next.toISOString() : null;
            this.save();
          } catch (e) {}
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

  async tick(now = new Date()) {
    const fired = [];
    for (const record of this.state.databases) {
      if (this.runningBackups.size >= MAX_CONCURRENT_BACKUPS) break;
      const s = record.schedule;
      if (!s || !s.enabled || !s.cron) continue;

      try {
        this.parseCron(s.cron);
      } catch (err) {
        console.error(`[Databases] Horario inválido en ${record.name}: ${err.message}. Se desactiva.`);
        s.enabled = false;
        s.lastStatus = 'horario-invalido';
        this.save();
        const ns = getNotificationService();
        if (ns && typeof ns.notify === 'function') {
          Promise.resolve(ns.notify({
            event: 'backup_failed',
            level: 'warning',
            title: `Horario de copias desactivado: ${record.name}`,
            message: `La expresión cron "${s.cron}" es inválida (${err.message}) y la programación automática se ha desactivado.`,
            projectId: record.projectId
          })).catch(() => {});
        }
        continue;
      }

      if (!s.nextRunAt) {
        const next = this.nextCronRun(s.cron, now);
        s.nextRunAt = next ? next.toISOString() : null;
        this.save();
        continue;
      }
      if (new Date(s.nextRunAt).getTime() > now.getTime()) continue;
      if (this.runningBackups.has(record.id) || this._activeOps.has(record.id)) continue;

      const next = this.nextCronRun(s.cron, now);
      s.nextRunAt = next ? next.toISOString() : null;
      this.save();

      fired.push(record.id);
      this.runBackup(record.id, { trigger: 'scheduled' }).catch((e) =>
        console.error(`[Databases] Copia programada fallida (${record.name}): ${e.message}`)
      );
    }

    // Watchdog perezoso (máx. 1 vez/hora, 0 timers extra): detecta copias silenciosamente atascadas (Coolify #10636)
    const nowMs = now.getTime();
    if (nowMs - this._lastWatchdogAt >= 3600 * 1000) {
      this._lastWatchdogAt = nowMs;
      try {
        this.checkBackupHealth({ now, notify: true });
      } catch (e) {}
    }

    return { firedAt: now.toISOString(), fired };
  }

  // -------------------------------------------------------------------------
  // Cifrado de copias (Key-ring AEAD CKB1 + rotación por keyId)
  // -------------------------------------------------------------------------

  /**
   * Activa o desactiva el cifrado cliente AES-256-GCM (`CKB1`) para copias S3/R2.
   * Desactivar nunca borra las claves retiradas: las copias anteriores siguen siendo restaurables.
   * @param {{ enabled?: boolean, passphrase?: string | null, keyHex?: string | null }} [opts]
   */
  setBackupEncryption({ enabled = true, passphrase = null, keyHex = null } = {}) {
    const prev = this.state.backupEncryption || { enabled: false, activeKeyId: null, keys: [] };
    if (!enabled) {
      this.state.backupEncryption = {
        ...prev,
        enabled: false
      };
      this.save({ strict: true });
      return this.getBackupEncryptionConfig();
    }

    // Si ya hay clave activa y no se pasó material nuevo, simplemente reactivar
    if (!passphrase && !keyHex && prev.activeKeyId && Array.isArray(prev.keys) && prev.keys.some((k) => k.keyId === prev.activeKeyId)) {
      this.state.backupEncryption = { ...prev, enabled: true };
      this.save({ strict: true });
      return this.getBackupEncryptionConfig();
    }

    const { keyBuf, keyId, source } = this._materializeBackupKey({ passphrase, keyHex });
    const nextKeys = (prev.keys || []).map((k) => (k.status === 'active' ? { ...k, status: 'retired' } : k));
    if (!nextKeys.some((k) => k.keyId === keyId)) {
      nextKeys.push({
        keyId,
        keyEnc: encryptSecret(keyBuf.toString('hex'), this.cryptoKey),
        source,
        createdAt: new Date().toISOString(),
        status: 'active'
      });
    } else {
      for (const k of nextKeys) {
        if (k.keyId === keyId) k.status = 'active';
      }
    }

    this.state.backupEncryption = {
      enabled: true,
      activeKeyId: keyId,
      keys: nextKeys
    };
    this.save({ strict: true });
    return this.getBackupEncryptionConfig();
  }

  /**
   * Rota la clave activa de cifrado `CKB1` conservando las claves previas como
   * `retired` en el anillo para descifrar copias históricas sin re-cifrar todo el bucket.
   * @param {{ passphrase?: string | null, keyHex?: string | null }} [opts]
   */
  rotateBackupEncryptionKey({ passphrase = null, keyHex = null } = {}) {
    const prev = this.state.backupEncryption || { enabled: false, activeKeyId: null, keys: [] };
    const previousKeyId = prev.activeKeyId || null;
    const { keyBuf, keyId, source } = this._materializeBackupKey({ passphrase, keyHex });
    if (previousKeyId && keyId === previousKeyId) {
      throw new Error('La nueva clave coincide con la clave activa actual; proporciona una clave diferente');
    }
    const nextKeys = (prev.keys || []).map((k) => ({ ...k, status: 'retired' }));
    const existing = nextKeys.find((k) => k.keyId === keyId);
    if (existing) {
      existing.status = 'active';
    } else {
      nextKeys.push({
        keyId,
        keyEnc: encryptSecret(keyBuf.toString('hex'), this.cryptoKey),
        source,
        createdAt: new Date().toISOString(),
        status: 'active'
      });
    }
    this.state.backupEncryption = {
      enabled: true,
      activeKeyId: keyId,
      keys: nextKeys
    };
    this.save({ strict: true });
    return {
      previousKeyId,
      activeKeyId: keyId,
      keyCount: nextKeys.length,
      config: this.getBackupEncryptionConfig()
    };
  }

  /** @param {{ passphrase?: string | null, keyHex?: string | null }} [opts] */
  _materializeBackupKey({ passphrase = null, keyHex = null } = {}) {
    if (keyHex) {
      const clean = String(keyHex).trim();
      if (!/^[a-fA-F0-9]{64}$/.test(clean)) {
        throw new Error('keyHex inválido: debe ser una clave AES-256 de 64 caracteres hexadecimales (32 bytes)');
      }
      const keyBuf = Buffer.from(clean, 'hex');
      return { keyBuf, keyId: computeKeyId(keyBuf), source: 'raw-hex' };
    }
    if (passphrase) {
      const derived = deriveBackupKeyFromPassphrase(passphrase);
      return { keyBuf: derived.key, keyId: derived.keyId, source: 'scrypt-passphrase' };
    }
    const keyBuf = crypto.randomBytes(32);
    return { keyBuf, keyId: computeKeyId(keyBuf), source: 'generated' };
  }

  /** Vista pública del anillo de cifrado de copias: NUNCA expone material secreto. */
  getBackupEncryptionConfig() {
    const cfg = this.state.backupEncryption;
    if (!cfg) {
      return { enabled: false, activeKeyId: null, keyCount: 0, keys: [] };
    }
    return {
      enabled: Boolean(cfg.enabled),
      activeKeyId: cfg.activeKeyId || null,
      keyCount: Array.isArray(cfg.keys) ? cfg.keys.length : 0,
      keys: (cfg.keys || []).map((k) => ({
        keyId: k.keyId,
        source: k.source || 'generated',
        createdAt: k.createdAt,
        status: k.status || 'retired'
      }))
    };
  }

  /** @returns {{ keyId: string, key: Buffer } | null} */
  _getActiveBackupKey() {
    const cfg = this.state.backupEncryption;
    if (!cfg || !cfg.activeKeyId || !Array.isArray(cfg.keys)) return null;
    const entry = cfg.keys.find((k) => k.keyId === cfg.activeKeyId);
    if (!entry || !entry.keyEnc) return null;
    const hex = decryptSecret(entry.keyEnc, this.cryptoKey);
    const key = Buffer.from(hex, 'hex');
    if (key.length !== 32) return null;
    return { keyId: entry.keyId, key };
  }

  /** @returns {Map<string, Buffer>} */
  _getBackupKeyRing() {
    /** @type {Map<string, Buffer>} */
    const ring = new Map();
    const cfg = this.state.backupEncryption;
    if (!cfg || !Array.isArray(cfg.keys)) return ring;
    for (const entry of cfg.keys) {
      if (!entry || !entry.keyEnc || !entry.keyId) continue;
      try {
        const key = Buffer.from(decryptSecret(entry.keyEnc, this.cryptoKey), 'hex');
        if (key.length === 32) ring.set(entry.keyId, key);
      } catch (e) {}
    }
    return ring;
  }

  // -------------------------------------------------------------------------
  // Historial de auditoría, verificación automática, drills DR y clonado
  // -------------------------------------------------------------------------

  _recordRestoreAudit(record, entry) {
    if (!Array.isArray(record.restoreHistory)) record.restoreHistory = [];
    record.restoreHistory.unshift({
      id: `rst_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      executedAt: new Date().toISOString(),
      ...entry
    });
    if (record.restoreHistory.length > MAX_AUDIT_HISTORY) {
      record.restoreHistory.length = MAX_AUDIT_HISTORY;
    }
  }

  _recordVerificationAudit(record, entry) {
    if (!Array.isArray(record.verificationHistory)) record.verificationHistory = [];
    record.verificationHistory.unshift({
      id: `ver_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      verifiedAt: new Date().toISOString(),
      ...entry
    });
    if (record.verificationHistory.length > MAX_AUDIT_HISTORY) {
      record.verificationHistory.length = MAX_AUDIT_HISTORY;
    }
  }

  listRestoreHistory(id) {
    const record = this.mustGet(id);
    return (record.restoreHistory || []).slice();
  }

  listVerificationHistory(id) {
    const record = this.mustGet(id);
    return (record.verificationHistory || []).slice();
  }

  /**
   * Verificación multicapa de una copia sin tocar la base viva:
   *  1. Tamaño > 0 y coincidencia estricta SHA-256
   *  2. Descifrado AEAD `CKB1` verificando TODOS los authTag por bloque
   *  3. Integridad del stream gzip (CRC32 + límite anti-bomba)
   *  4. Cabecera mágica del motor (`PGDMP`, `REDIS`, seguridad SQL sin meta-comandos)
   *  5. Verificación S3 `HEAD` (existencia y tamaño remoto) si aplica
   *
   * @param {string} id
   * @param {string} backupId
   * @param {{ checkRemote?: boolean, decryptionKey?: Buffer | null }} [opts]
   */
  async verifyBackup(id, backupId, { checkRemote = true, decryptionKey = null } = {}) {
    const record = this.mustGet(id);
    const engine = ENGINES[record.engine];
    const entry = (record.backups || []).find((b) => b.id === backupId);
    if (!entry) throw new Error(`Copia ${backupId} no encontrada en el historial`);

    const startedAt = Date.now();
    const dir = this.backupDir(id);
    const candidate = assertContainedPath(dir, entry.fileName);
    /** @type {Record<string, any>} */
    const checks = {
      exists: false,
      sha256: null,
      aead: null,
      gzip: null,
      format: null,
      remoteHead: null
    };
    /** @type {string | null} */
    let tempDownloadPath = null;
    /** @type {string | null} */
    let tempDecryptedPath = null;
    /** @type {string | null} */
    let tempGunzipPath = null;

    try {
      let targetPath = candidate;
      if (!fs.existsSync(targetPath)) {
        if (entry.remote && entry.remote.key) {
          const s3 = this.s3ClientFor();
          if (!s3) throw new Error('Copia ausente en disco y no hay S3 configurado');
          tempDownloadPath = path.join(this.tmpDir, `ver_dl_${record.id}_${crypto.randomBytes(5).toString('hex')}_${entry.fileName}`);
          await s3.downloadFile(entry.remote.key, tempDownloadPath);
          targetPath = tempDownloadPath;
        } else {
          throw new Error('Fichero de copia ausente en disco y sin réplica S3');
        }
      }
      checks.exists = true;

      const stat = fs.statSync(targetPath);
      if (stat.size <= 0) throw new Error('El fichero de copia está vacío (0 bytes)');

      // 1. SHA-256
      const actualSha = await this.sha256File(targetPath);
      if (entry.sha256 && actualSha !== entry.sha256) {
        checks.sha256 = false;
        throw new Error(`SHA-256 no coincide: esperado ${entry.sha256.slice(0, 12)}…, obtenido ${actualSha.slice(0, 12)}…`);
      }
      checks.sha256 = true;

      // 2. AEAD CKB1 si está cifrado
      let workPath = targetPath;
      if (entry.encrypted || targetPath.endsWith('.ckb1') || hasCkb1Magic(targetPath)) {
        const innerName = path.basename(entry.fileName).replace(/\.ckb1$/i, '') || 'backup.gz';
        tempDecryptedPath = path.join(this.tmpDir, `ver_dec_${record.id}_${crypto.randomBytes(5).toString('hex')}_${innerName}`);
        const ring = decryptionKey ? decryptionKey : this._getBackupKeyRing();
        const dec = await decryptBackupFile(targetPath, tempDecryptedPath, ring);
        checks.aead = { ok: true, keyId: dec.keyId, chunks: dec.chunks };
        workPath = tempDecryptedPath;
      }

      // 3. Integridad gzip
      let inspectPath = workPath;
      if (workPath.endsWith('.gz')) {
        if (!this.hasGzipMagic(workPath)) {
          checks.gzip = false;
          throw new Error('Cabecera gzip (0x1f 0x8b) inválida');
        }
        tempGunzipPath = path.join(this.tmpDir, `ver_gunz_${record.id}_${crypto.randomBytes(5).toString('hex')}`);
        await this.gunzipFile(workPath, tempGunzipPath);
        checks.gzip = true;
        inspectPath = tempGunzipPath;
      }

      // 4. Magic bytes / seguridad SQL por motor
      if (engine.family === 'postgresql') {
        if (this.isPgCustomFormat(inspectPath)) {
          checks.format = 'pg-custom-PGDMP';
        } else {
          await this.assertSafeSqlFile(inspectPath, 'postgresql');
          checks.format = 'pg-plain-sql';
        }
      } else if (engine.family === 'redis') {
        const hdr = Buffer.alloc(5);
        const fd = fs.openSync(inspectPath, 'r');
        try {
          const n = fs.readSync(fd, hdr, 0, 5, 0);
          if (n < 5 || hdr.toString('ascii') !== 'REDIS') {
            throw new Error('Cabecera mágica REDIS ausente en volcado RDB');
          }
        } finally {
          fs.closeSync(fd);
        }
        checks.format = 'redis-RDB';
      } else if (engine.family === 'mysql' || engine.family === 'mariadb') {
        await this.assertSafeSqlFile(inspectPath, engine.family);
        checks.format = `${engine.family}-sql`;
      } else if (engine.family === 'mongodb') {
        checks.format = 'mongo-archive-gz';
      } else {
        checks.format = `${engine.family}-artifact`;
      }

      // 5. Remoto S3 HEAD
      if (checkRemote && entry.remote && entry.remote.key) {
        const s3 = this.s3ClientFor();
        if (s3) {
          const head = await s3.headObject(entry.remote.key);
          if (!head) {
            checks.remoteHead = false;
            throw new Error(`El objeto remoto ${entry.remote.key} ya no existe en S3`);
          }
          if (head.sizeBytes !== entry.sizeBytes) {
            checks.remoteHead = false;
            throw new Error(`Tamaño remoto S3 (${head.sizeBytes} B) distinto del registrado (${entry.sizeBytes} B)`);
          }
          checks.remoteHead = { ok: true, sizeBytes: head.sizeBytes, etag: head.etag };
        }
      }

      const durationMs = Date.now() - startedAt;
      const verifiedAt = new Date().toISOString();
      entry.lastVerification = { ok: true, verifiedAt, checks, durationMs, error: null };
      this._recordVerificationAudit(record, { backupId, ok: true, checks, durationMs, error: null });
      this.save();
      this.emit('backup_verified', { databaseId: id, backupId, ok: true, durationMs });
      return { ok: true, status: 'verified', databaseId: id, backupId, verifiedAt, checks, durationMs, error: null };
    } catch (err) {
      const durationMs = Date.now() - startedAt;
      const verifiedAt = new Date().toISOString();
      const errMsg = this.redactMessage(err.message, this.decryptPassword(record));
      entry.lastVerification = { ok: false, verifiedAt, checks, durationMs, error: errMsg };
      this._recordVerificationAudit(record, { backupId, ok: false, checks, durationMs, error: errMsg });
      this.save();
      this.emit('backup_verification_failed', { databaseId: id, backupId, error: errMsg });
      const ns = getNotificationService();
      if (ns && typeof ns.notify === 'function') {
        Promise.resolve(ns.notify({
          event: 'backup_failed',
          level: 'error',
          title: `Verificación de copia fallida: ${record.name}`,
          message: `La copia ${entry.fileName} (${backupId}) no superó la verificación de integridad: ${errMsg}`,
          projectId: record.projectId
        })).catch(() => {});
      }
      return { ok: false, status: 'failed', databaseId: id, backupId, verifiedAt, checks, durationMs, error: errMsg };
    } finally {
      for (const f of [tempDownloadPath, tempDecryptedPath, tempGunzipPath]) {
        if (f) { try { fs.unlinkSync(f); } catch (e) {} }
      }
    }
  }

  /**
   * Simulacro real de recuperación ante desastres (Restore Drill):
   *  1. Ejecuta `verifyBackup()` completo (SHA-256 + AEAD + gzip + magic)
   *  2. Levanta un contenedor efímero y completamente aislado (`--network none`, sin puertos)
   *  3. Restaura la copia verificada en el contenedor efímero
   *  4. Ejecuta una consulta real del motor para confirmar que los datos responden
   *  5. Destruye siempre el contenedor efímero y registra el resultado en `restoreHistory`
   *
   * @param {string} id
   * @param {{ backupId?: string | null, timeoutMs?: number, decryptionKey?: Buffer | null }} [opts]
   */
  async runRestoreDrill(id, { backupId = null, timeoutMs = 120000, decryptionKey = null } = {}) {
    const record = this.mustGet(id);
    const engine = ENGINES[record.engine];
    const targetEntry = backupId
      ? (record.backups || []).find((b) => b.id === backupId)
      : (record.backups || [])[0];
    if (!targetEntry) {
      throw new Error(backupId ? `Copia ${backupId} no encontrada` : 'No hay ninguna copia disponible para ejecutar un simulacro de restauración');
    }
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible: no se puede ejecutar el simulacro de restauración');
    }

    const startedAt = Date.now();
    const drillContainer = `culkibo_drill_${record.id}_${crypto.randomBytes(4).toString('hex')}`;
    const drillPassword = generatePassword();
    const envFile = path.join(this.tmpDir, `env_drill_${crypto.randomBytes(6).toString('hex')}`);
    const inContainer = `/tmp/culkibo_drill_${crypto.randomBytes(5).toString('hex')}`;
    /** @type {string | null} */
    let decryptedTempPath = null;
    /** @type {string | null} */
    let gunzipTempPath = null;
    /** @type {string | null} */
    let sanitizedSqlPath = null;
    let containerCreated = false;

    try {
      // 1. Pre-verificación criptográfica e integridad antes de arrancar Docker
      const preCheck = await this.verifyBackup(id, targetEntry.id, { checkRemote: false, decryptionKey });
      if (!preCheck.ok) {
        throw new Error(`Pre-verificación fallida antes del drill: ${preCheck.error}`);
      }

      const dir = this.backupDir(id);
      let workPath = assertContainedPath(dir, targetEntry.fileName);
      if (targetEntry.encrypted || workPath.endsWith('.ckb1') || hasCkb1Magic(workPath)) {
        const innerName = path.basename(workPath).replace(/\.ckb1$/i, '') || 'drill.gz';
        decryptedTempPath = path.join(this.tmpDir, `drill_dec_${crypto.randomBytes(5).toString('hex')}_${innerName}`);
        await decryptBackupFile(workPath, decryptedTempPath, decryptionKey || this._getBackupKeyRing());
        workPath = decryptedTempPath;
      }

      let plainPath = workPath;
      if (workPath.endsWith('.gz') && !workPath.endsWith('.archive.gz')) {
        gunzipTempPath = path.join(this.tmpDir, `drill_plain_${crypto.randomBytes(5).toString('hex')}`);
        await this.gunzipFile(workPath, gunzipTempPath);
        plainPath = gunzipTempPath;
      }

      // 2. Levantar contenedor efímero aislado (--network none, 0 puertos, memoria acotada)
      const drillMem = Math.max(128, Math.min(512, record.memoryMb || 512));
      const drillEnv = {
        ...engine.initEnv({ username: record.username, password: drillPassword, dbName: record.dbName }),
        ...engine.clientEnv({ password: drillPassword })
      };
      fs.writeFileSync(envFile, formatDockerEnvFile(drillEnv), { encoding: 'utf8', mode: 0o600 });

      const runArgs = [
        'run', '-d',
        '--name', drillContainer,
        '--network', 'none',
        '--env-file', envFile,
        '--memory', `${drillMem}m`,
        '--memory-swap', `${drillMem}m`,
        '--cpus', '1',
        '--pids-limit', '256',
        '--security-opt', 'no-new-privileges',
        '--label', 'culkibo.managed=true',
        '--label', 'culkibo.role=restore-drill',
        record.image,
        ...(engine.command ? engine.command() : [])
      ];
      await this.docker(runArgs, { timeout: timeoutMs });
      containerCreated = true;

      // 3. Restaurar en el contenedor efímero + ejecutar sonda real de lectura
      let objectCount = 0;
      if (engine.family === 'postgresql') {
        if (this.isPgCustomFormat(plainPath)) {
          await this.docker(['cp', plainPath, `${drillContainer}:${inContainer}`], { timeout: timeoutMs });
          const plan = engine.restore({ username: record.username, dbName: record.dbName, inFile: inContainer });
          await this.docker(['exec', drillContainer, ...this.wrapInContainer(engine, plan.program, plan.args)], { timeout: timeoutMs });
        } else {
          await this.assertSafeSqlFile(plainPath, 'postgresql');
          await this.docker(
            ['exec', '-i', drillContainer, 'psql', '-U', record.username, '-d', record.dbName, '-v', 'ON_ERROR_STOP=1'],
            { timeout: timeoutMs, inputFile: plainPath }
          );
        }
        const probe = await this.docker([
          'exec', drillContainer, 'psql', '-U', record.username, '-d', record.dbName, '-tAc',
          "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema');"
        ], { timeout: 30000 });
        objectCount = parseInt((probe.stdout || '').trim(), 10) || 0;
      } else if (engine.family === 'mysql' || engine.family === 'mariadb') {
        await this.assertSafeSqlFile(plainPath, engine.family);
        sanitizedSqlPath = path.join(this.tmpDir, `drill_sql_${crypto.randomBytes(5).toString('hex')}.sql`);
        await this.sanitizeMysqlSqlFile(plainPath, sanitizedSqlPath);
        const plan = engine.restore({ username: record.username, dbName: record.dbName, inFile: inContainer });
        await this.docker(
          ['exec', '-i', drillContainer, ...this.wrapInContainer(engine, plan.program, plan.args)],
          { timeout: timeoutMs, inputFile: sanitizedSqlPath }
        );
        const cli = record.engine === 'mariadb' ? 'mariadb' : 'mysql';
        const safeDb = assertIdentifier(record.dbName, 'base de datos');
        const probe = await this.docker([
          'exec', drillContainer, ...this.wrapInContainer(engine, cli, [
            '-u', 'root', '-N', '-B', '-e',
            `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${safeDb}';`
          ])
        ], { timeout: 30000 });
        objectCount = parseInt((probe.stdout || '').trim(), 10) || 0;
      } else if (engine.family === 'redis') {
        const dataDir = record.dataDir || this.resolveDataDir(engine, record.image);
        await this.docker(['stop', '-t', '10', drillContainer], { timeout: 30000 });
        await this.docker(['cp', plainPath, `${drillContainer}:${dataDir}/dump.rdb`], { timeout: timeoutMs });
        await this.docker(['start', drillContainer], { timeout: 30000 });
        const cli = record.engine === 'valkey' ? 'valkey-cli' : 'redis-cli';
        const probe = await this.docker(['exec', drillContainer, cli, 'DBSIZE'], { timeout: 30000 });
        const m = /(\d+)/.exec(probe.stdout || '');
        objectCount = m ? parseInt(m[1], 10) : 0;
      } else if (engine.family === 'mongodb') {
        await this.docker(['cp', plainPath, `${drillContainer}:${inContainer}`], { timeout: timeoutMs });
        const authCfg = this._writeEngineAuthConfig(engine, drillPassword, 'drill_mongo');
        try {
          await this.docker(['cp', authCfg.localPath, `${drillContainer}:${authCfg.containerPath}`], { timeout: 15000 });
          await this.docker([
            'exec', drillContainer, 'mongorestore',
            `--config=${authCfg.containerPath}`, `--username=${record.username}`,
            '--authenticationDatabase=admin', `--archive=${inContainer}`, '--gzip', '--drop'
          ], { timeout: timeoutMs });
        } finally {
          try { fs.unlinkSync(authCfg.localPath); } catch (e) {}
        }
        const probe = await this.docker([
          'exec', drillContainer, 'mongosh', '--quiet', '--eval',
          `db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); print(db.getSiblingDB(${JSON.stringify(record.dbName)}).getCollectionNames().length);`
        ], { timeout: 30000 });
        objectCount = parseInt((probe.stdout || '').trim(), 10) || 0;
      } else {
        await this.docker(['cp', plainPath, `${drillContainer}:${inContainer}`], { timeout: timeoutMs });
        objectCount = 1;
      }

      const durationMs = Date.now() - startedAt;
      const executedAt = new Date().toISOString();
      targetEntry.lastDrill = { ok: true, executedAt, objectCount, durationMs, error: null };
      this._recordRestoreAudit(record, {
        kind: 'drill',
        backupId: targetEntry.id,
        method: engine.family,
        status: 'ok',
        objectCount,
        durationMs
      });
      this.save();
      this.emit('restore_drill_completed', { databaseId: id, backupId: targetEntry.id, objectCount, durationMs });
      return { ok: true, databaseId: id, backupId: targetEntry.id, engine: record.engine, objectCount, durationMs, executedAt, error: null };
    } catch (err) {
      const durationMs = Date.now() - startedAt;
      const executedAt = new Date().toISOString();
      const errMsg = this.redactMessage(err.message, drillPassword, this.decryptPassword(record));
      targetEntry.lastDrill = { ok: false, executedAt, objectCount: 0, durationMs, error: errMsg };
      this._recordRestoreAudit(record, {
        kind: 'drill',
        backupId: targetEntry.id,
        method: engine.family,
        status: 'failed',
        objectCount: 0,
        durationMs,
        error: errMsg
      });
      this.save();
      this.emit('restore_drill_failed', { databaseId: id, backupId: targetEntry.id, error: errMsg });
      const ns = getNotificationService();
      if (ns && typeof ns.notify === 'function') {
        Promise.resolve(ns.notify({
          event: 'backup_failed',
          level: 'error',
          title: `Simulacro DR fallido: ${record.name}`,
          message: `El simulacro de restauración de ${record.name} (${targetEntry.fileName}) ha fallado: ${errMsg}`,
          projectId: record.projectId
        })).catch(() => {});
      }
      return { ok: false, databaseId: id, backupId: targetEntry.id, engine: record.engine, objectCount: 0, durationMs, executedAt, error: errMsg };
    } finally {
      if (containerCreated) {
        try { await this.docker(['rm', '-f', drillContainer], { timeout: 30000 }); } catch (e) {}
      }
      for (const f of [envFile, decryptedTempPath, gunzipTempPath, sanitizedSqlPath]) {
        if (f) { try { fs.unlinkSync(f); } catch (e) {} }
      }
    }
  }

  /**
   * Clona / ramifica una base de datos a una instancia nueva completamente aislada
   * (o restaura un `backupId` histórico en una BD nueva sin tocar producción).
   *
   * @param {string} sourceId
   * @param {{
   *   name?: string,
   *   projectId?: string,
   *   backupId?: string | null,
   *   memoryMb?: number,
   *   cpus?: number,
   *   tuningPreset?: string,
   *   branchLabel?: string | null
   * }} [opts]
   */
  async cloneDatabase(sourceId, opts = {}) {
    const source = this.mustGet(sourceId);
    if (!(await this.isDockerAvailable())) {
      throw new Error('Docker no está disponible: no se puede clonar la base de datos');
    }

    // 1. Obtener o generar la instantánea origen
    /** @type {any} */
    let sourceBackupEntry = null;
    if (opts.backupId) {
      sourceBackupEntry = (source.backups || []).find((b) => b.id === opts.backupId) || null;
      if (!sourceBackupEntry) {
        throw new Error(`Copia origen ${opts.backupId} no encontrada en ${source.name}`);
      }
    } else {
      const snap = await this.runBackup(sourceId, { trigger: 'clone', skipS3: true, skipRetention: true });
      sourceBackupEntry = snap.backup;
    }
    if (!sourceBackupEntry) {
      throw new Error(`No se pudo obtener la copia origen para clonar ${source.name}`);
    }

    const srcFile = await this.getBackupFilePath(sourceId, sourceBackupEntry.id);

    // 2. Aprovisionar la nueva BD destino aislada (nueva clave, nuevo volumen, 0 puertos)
    const branchTag = opts.branchLabel ? String(opts.branchLabel).slice(0, 32) : 'clone';
    const created = await this.provision({
      projectId: opts.projectId || source.projectId,
      engine: source.engine,
      name: opts.name || `${source.name} (${branchTag})`,
      dbName: source.dbName || undefined,
      username: source.username,
      image: source.image,
      memoryMb: opts.memoryMb || source.memoryMb,
      cpus: opts.cpus || source.cpus,
      tuningPreset: opts.tuningPreset || (source.tuning && source.tuning.preset) || undefined
    });

    const targetRecord = this.mustGet(created.id);
    try {
      // 3. Copiar artefacto verificado a la carpeta de backups del destino y restaurarlo allí
      const targetDir = this.backupDir(targetRecord.id);
      const seedFileName = `clone_${sourceBackupEntry.fileName}`;
      const seedPath = assertContainedPath(targetDir, seedFileName);
      fs.copyFileSync(srcFile.filePath, seedPath);
      const seedEntry = {
        id: `bk_clone_${crypto.randomBytes(4).toString('hex')}`,
        fileName: seedFileName,
        sizeBytes: fs.statSync(seedPath).size,
        sha256: sourceBackupEntry.sha256 || await this.sha256File(seedPath),
        createdAt: new Date().toISOString(),
        trigger: 'clone-seed',
        durationMs: 0,
        pinned: true,
        encrypted: Boolean(sourceBackupEntry.encrypted),
        encryption: sourceBackupEntry.encryption || null,
        lastVerification: null,
        lastDrill: null,
        remote: null,
        remoteError: null
      };
      targetRecord.backups.unshift(seedEntry);
      this.save();

      await this.restore(targetRecord.id, { backupId: seedEntry.id, createSafetySnapshot: false });

      targetRecord.clonedFrom = {
        sourceDatabaseId: source.id,
        sourceBackupId: sourceBackupEntry.id,
        branchLabel: opts.branchLabel || null,
        clonedAt: new Date().toISOString()
      };
      this.save({ strict: true });
      return {
        ...this.toPublic(targetRecord),
        connectionString: created.connectionString
      };
    } catch (err) {
      // Limpieza total: nunca dejar contenedores/volúmenes huérfanos si falla el clonado
      try { await this.remove(targetRecord.id, { deleteVolume: true, deleteBackups: true }); } catch (e) {}
      throw new Error(`Clonado fallido desde ${source.name}: ${err.message}`);
    }
  }

  /**
   * Watchdog de SLA de copias: detecta copias programadas que dejaron de ejecutarse
   * silenciosamente (Coolify #10636), último estado en error o verificación fallida.
   *
   * @param {{ now?: Date, maxMissedFactor?: number, notify?: boolean }} [opts]
   */
  checkBackupHealth({ now = new Date(), maxMissedFactor = 2, notify = false } = {}) {
    const nowMs = now instanceof Date ? now.getTime() : Date.now();
    const factor = Math.max(1.2, Math.min(10, Number(maxMissedFactor) || 2));
    /** @type {Array<{ databaseId: string, name: string, engine: string, severity: 'warning' | 'critical', code: string, message: string, ageMs?: number, expectedIntervalMs?: number }>} */
    const alerts = [];
    let totalScheduled = 0;
    let healthyCount = 0;
    let staleCount = 0;
    let erroredCount = 0;
    let unverifiedCount = 0;

    for (const record of this.state.databases) {
      const s = record.schedule || {};
      const latestBackup = (record.backups || [])[0] || null;
      if (latestBackup && (!latestBackup.lastVerification || latestBackup.lastVerification.ok !== true)) {
        unverifiedCount++;
        if (latestBackup.lastVerification && latestBackup.lastVerification.ok === false) {
          alerts.push({
            databaseId: record.id,
            name: record.name,
            engine: record.engine,
            severity: 'critical',
            code: 'VERIFICATION_FAILED',
            message: `Última copia ${latestBackup.fileName} falló la verificación: ${latestBackup.lastVerification.error || 'corrupta'}`
          });
        }
      }

      if (!s.enabled) continue;
      totalScheduled++;
      let hasIssue = false;

      if (s.lastStatus === 'error' || s.lastStatus === 'horario-invalido') {
        erroredCount++;
        hasIssue = true;
        alerts.push({
          databaseId: record.id,
          name: record.name,
          engine: record.engine,
          severity: 'critical',
          code: 'LAST_BACKUP_ERROR',
          message: `La última copia programada de ${record.name} terminó en estado "${s.lastStatus}"${record.lastError ? `: ${record.lastError}` : ''}`
        });
      }

      // Calcular cadencia real del cron entre dos disparos consecutivos
      let expectedIntervalMs = 24 * 3600 * 1000;
      try {
        const r1 = this.nextCronRun(s.cron, new Date(nowMs));
        const r2 = r1 ? this.nextCronRun(s.cron, r1) : null;
        if (r1 && r2) {
          expectedIntervalMs = Math.max(60000, r2.getTime() - r1.getTime());
        }
      } catch (e) {}

      const refTs = s.lastRunAt ? Date.parse(s.lastRunAt) : Date.parse(record.createdAt || '');
      if (Number.isFinite(refTs)) {
        const ageMs = nowMs - refTs;
        if (ageMs > expectedIntervalMs * factor) {
          staleCount++;
          hasIssue = true;
          alerts.push({
            databaseId: record.id,
            name: record.name,
            engine: record.engine,
            severity: 'warning',
            code: 'BACKUP_STALE',
            ageMs,
            expectedIntervalMs,
            message: `${record.name} lleva ${Math.round(ageMs / 60000)} min sin copia completada (esperado <= ${Math.round((expectedIntervalMs * factor) / 60000)} min)`
          });
        }
      }

      if (!hasIssue) healthyCount++;
    }

    if (notify && alerts.length > 0) {
      const ns = getNotificationService();
      if (ns && typeof ns.notify === 'function') {
        const hasCrit = alerts.some((a) => a.severity === 'critical');
        Promise.resolve(ns.notify({
          event: 'backup_failed',
          level: hasCrit ? 'error' : 'warning',
          title: `Alerta SLA de copias (${alerts.length} incidencias)`,
          message: alerts.slice(0, 5).map((a) => `[${a.code}] ${a.message}`).join('\n')
        })).catch(() => {});
      }
    }

    return {
      healthy: alerts.length === 0,
      checkedAt: new Date(nowMs).toISOString(),
      alerts,
      summary: {
        totalScheduled,
        healthy: healthyCount,
        stale: staleCount,
        errored: erroredCount,
        unverified: unverifiedCount
      }
    };
  }

  // -------------------------------------------------------------------------
  // Configuración S3 / R2
  // -------------------------------------------------------------------------

  /**
   * Guarda la configuración del bucket. Admite edición parcial conservando las
   * credenciales existentes si el usuario deja vacíos o enmascarados los campos.
   */
  setS3Config(config = {}) {
    if (config === null || config.enabled === false) {
      this.state.s3 = null;
      this.save();
      return { configured: false };
    }
    const existing = this.state.s3;
    const rawAccess = String(config.accessKeyId || '').trim();
    const rawSecret = String(config.secretAccessKey || '').trim();
    const isMaskedAccess = !rawAccess || rawAccess.includes('***') || rawAccess.includes('…');
    const isMaskedSecret = !rawSecret || /^\*+$/.test(rawSecret);

    // Defensa anti-exfiltración (Dokploy GHSA-7f32-g5xc-mqr7): si cambia el endpoint o bucket,
    // exigir que se vuelvan a introducir las credenciales reales para no filtrar el secreto guardado.
    if (existing) {
      const nextEndpointRaw = config.endpoint ? String(config.endpoint).trim() : existing.endpoint;
      let nextOrigin = nextEndpointRaw;
      try { nextOrigin = new URL(nextEndpointRaw).origin; } catch (e) {}
      const nextBucket = config.bucket ? String(config.bucket).trim() : existing.bucket;
      const endpointChanged = nextOrigin !== existing.endpoint || nextBucket !== existing.bucket;
      if (endpointChanged && (isMaskedAccess || isMaskedSecret)) {
        throw new Error('Al cambiar el endpoint o bucket S3 debes volver a introducir Access Key y Secret Key completos por seguridad');
      }
    }

    const resolvedConfig = {
      ...config,
      endpoint: config.endpoint || existing?.endpoint,
      region: config.region || existing?.region || 'auto',
      bucket: config.bucket || existing?.bucket,
      forcePathStyle: config.forcePathStyle !== undefined
        ? config.forcePathStyle
        : (config.pathStyle !== undefined ? config.pathStyle : existing?.forcePathStyle),
      accessKeyId: isMaskedAccess && existing ? existing.accessKeyId : rawAccess,
      secretAccessKey: isMaskedSecret && existing
        ? decryptSecret(existing.secretAccessKeyEnc, this.cryptoKey)
        : rawSecret
    };

    const probe = new S3Client(resolvedConfig);
    this.state.s3 = {
      endpoint: probe.origin,
      region: probe.region,
      bucket: probe.bucket,
      forcePathStyle: probe.forcePathStyle,
      prefix: String(config.prefix !== undefined ? config.prefix : (existing?.prefix || 'culkibo/')).replace(/^\/+/, ''),
      accessKeyId: resolvedConfig.accessKeyId,
      secretAccessKeyEnc: encryptSecret(resolvedConfig.secretAccessKey, this.cryptoKey)
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

  /**
   * Lista objetos almacenados en el bucket S3/R2 configurado para recuperación disaster-recovery.
   * @param {{ prefix?: string | null, maxKeys?: number }} [opts]
   */
  async listRemoteObjects({ prefix = null, maxKeys = 200 } = {}) {
    const s3 = this.s3ClientFor();
    if (!s3) throw new Error('No hay almacenamiento S3 configurado');
    const targetPrefix = prefix !== null && prefix !== undefined ? String(prefix) : this.s3Prefix();
    return s3.listObjectsV2(targetPrefix, { maxKeys });
  }

  /** Prueba de extremo a extremo del bucket: escribe, lee y borra siempre el objeto de prueba. */
  async testS3() {
    const s3 = this.s3ClientFor();
    if (!s3) throw new Error('No hay almacenamiento S3 configurado');
    const key = `${this.s3Prefix()}.culkibo-test-${crypto.randomBytes(6).toString('hex')}`;
    const payload = Buffer.from(`culkibo ${new Date().toISOString()}\n`, 'utf8');
    await s3.putObject(key, payload, 'text/plain');
    try {
      const head = await s3.headObject(key);
      return { success: true, endpoint: s3.origin, bucket: s3.bucket, verifiedBytes: head ? head.sizeBytes : payload.length };
    } finally {
      await s3.deleteObject(key).catch(() => {});
    }
  }
}

const instance = Object.assign(new DatabaseManager(), {
  DatabaseManager,
  ENGINES,
  PGBOUNCER_IMAGE,
  computeTuningConfig,
  loadOrCreateKey,
  generatePassword,
  encryptSecret,
  decryptSecret,
  computeKeyId,
  deriveBackupKeyFromPassphrase,
  encryptBackupFile,
  decryptBackupFile,
  hasCkb1Magic,
  inspectCkb1Header
});

module.exports = instance;
