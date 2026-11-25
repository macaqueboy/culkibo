/**
 * Catálogo de servicios de un clic.
 *
 * ---------------------------------------------------------------------------
 * POR QUÉ ESTE FORMATO, Y NO CIEN PLANTILLAS
 * ---------------------------------------------------------------------------
 *
 * Coolify tiene ~100 plantillas y la mayoría son un `docker-compose.yml` pegado
 * del README del proyecto. Funcionan el día que se pegan y se pudren después:
 * nadie verifica las etiquetas, nadie pone límites de recursos y los secretos
 * salen de `openssl rand` interpolado en YAML. El resultado es un catálogo
 * grande donde una fracción arranca.
 *
 * Aquí la apuesta es la contraria: un formato pequeño y estricto, trece
 * ejemplos verificados, y que la comunidad añada el resto copiando la forma.
 * Una plantilla que no declara imagen fijada, límites, volumen, sonda y
 * secretos NO SE CARGA (ver `validateTemplate`). Es más fácil añadir una
 * plantilla correcta que una rota.
 *
 * ---------------------------------------------------------------------------
 * FORMA DE UNA PLANTILLA
 * ---------------------------------------------------------------------------
 *
 *   id          Identificador estable, `[a-z0-9-]`. Entra en nombres de
 *               contenedor y de volumen: por eso la lista blanca es estricta.
 *   name        Nombre visible.
 *   category    Clave de `CATEGORIES`.
 *   summary     Una línea. Es lo que se lee en la rejilla del catálogo.
 *   description Un párrafo. Qué es y para qué sirve, sin marketing.
 *   licence     La licencia REAL del proyecto, incluido cuando no es OSI. Un
 *               orquestador Apache-2.0 no puede esconder que n8n no es libre.
 *   website     Enlace al proyecto, no a nuestra documentación.
 *
 *   database    Base de datos gestionada, aprovisionada por `databaseManager`.
 *               No se duplica nada: la plantilla sólo dice qué motor quiere y
 *               hereda cifrado en reposo, copias programadas, retención, subida
 *               a S3 y red aislada por instalación.
 *
 *   secrets     Secretos generados al instalar, con `crypto.randomBytes`.
 *               Nunca hay una contraseña por defecto en este fichero.
 *
 *   sidecars[]  Contenedores auxiliares sin ruta HTTP propia (ClickHouse para
 *               Plausible, por ejemplo). Viven en la misma red de la instalación.
 *
 *   app         El contenedor que sirve HTTP y recibe el dominio.
 *     image     Etiqueta FIJADA. Nunca `latest`: `latest` convierte un reinicio
 *               en una actualización mayor no pedida.
 *     port      Puerto DENTRO del contenedor.
 *     readiness Sonda HTTP que ejecuta el orquestador contra el puerto
 *               publicado (ver más abajo por qué no es un HEALTHCHECK de Docker).
 *
 *   nextSteps   Qué tiene que hacer la persona al terminar. En español.
 *   notes       Las pegas honestas. Si un proyecto ha quitado su consola web,
 *               se dice aquí y no se descubre después.
 *
 * ---------------------------------------------------------------------------
 * POR QUÉ LA SONDA NO ES UN `HEALTHCHECK` DE DOCKER
 * ---------------------------------------------------------------------------
 *
 * `databaseManager` sí inyecta `--health-cmd`, y es lo correcto allí: son cinco
 * imágenes conocidas y cada motor trae su cliente (`pg_isready`, `mysqladmin`,
 * `valkey-cli`). Aquí son trece imágenes de trece equipos distintos y no se
 * puede dar por hecho que dentro haya `curl`, `wget` o `nc`. Una sonda que
 * invoca un binario inexistente deja el contenedor en `unhealthy` para siempre
 * y miente peor que no tener sonda.
 *
 * La alternativa es mejor, no peor: el orquestador hace una petición HTTP real
 * contra el puerto publicado. Comprueba a la vez que el proceso vive, que
 * escucha, que la publicación del puerto funciona y que responde HTTP — cuatro
 * cosas, y la única que un HEALTHCHECK interno verificaría es la primera.
 * Además da progreso honesto mientras se instala, que es justo lo que pide una
 * instalación de un clic.
 *
 * `expect` es una lista de códigos: un servicio recién instalado y sin
 * configurar suele contestar 302 (a su asistente inicial) o 401, y eso ES estar
 * sano. Tratar sólo el 200 como sano daría por fallida media instalación.
 *
 * ---------------------------------------------------------------------------
 * ETIQUETAS DE IMAGEN
 * ---------------------------------------------------------------------------
 *
 * Las diecisiete referencias de este fichero se resolvieron contra la API de
 * cada registro el 16 de septiembre de 2026: se pidió el manifiesto de cada
 * etiqueta y las diecisiete devolvieron 200 con su digest. No están copiadas de
 * un README.
 *
 * Un hallazgo que justifica el método: la etiqueta `stable` de n8n y su
 * `latest` comparten digest con `2.39.6`, NO con `2.40.1`, que es la versión
 * más alta publicada. Fijar «la más alta» habría instalado una versión que su
 * propio proyecto todavía no promociona como estable.
 */

// ---------------------------------------------------------------------------
// Categorías
// ---------------------------------------------------------------------------

// Sin mayúsculas forzadas en ninguna etiqueta: en español el uso de versalitas
// o Title Case es una falta de ortografía según la RAE, y a 11 px las tildes
// desaparecen. La jerarquía se hace con peso tipográfico.
const CATEGORIES = [
  { id: 'ia', label: 'Inteligencia artificial' },
  { id: 'automatizacion', label: 'Automatización' },
  { id: 'analitica', label: 'Analítica' },
  { id: 'contenido', label: 'Contenido' },
  { id: 'datos', label: 'Datos' },
  { id: 'desarrollo', label: 'Desarrollo' },
  { id: 'monitorizacion', label: 'Monitorización' },
  { id: 'productividad', label: 'Productividad' },
  { id: 'seguridad', label: 'Seguridad' },
  { id: 'docs', label: 'Documentación y wikis' },
  { id: 'media', label: 'Multimedia y archivos' },
  { id: 'mensajeria', label: 'Mensajería' }
];

/**
 * @typedef {{ name: string, path: string }} TemplateVolume
 * @typedef {{ name: string, path: string, content: string }} TemplateFile
 * @typedef {{ containerPort: number, label: string }} TemplateExtraPort
 * @typedef {{ path: string, expect: number[], timeoutMs?: number }} TemplateReadiness
 * @typedef {{ type: 'exec', cmd: string[], timeoutMs?: number } | { type: 'tcp', port: number, timeoutMs?: number }} SidecarReadiness
 * @typedef {{
 *   name: string,
 *   image: string,
 *   memoryMb: number,
 *   cpus: number,
 *   env?: Record<string, string>,
 *   volumes?: TemplateVolume[],
 *   files?: TemplateFile[],
 *   command?: string[],
 *   readiness?: SidecarReadiness,
 *   dependsOn?: string[],
 *   startAfterApp?: boolean,
 *   coupledWithApp?: boolean,
 *   coupledTagOnly?: boolean
 * }} TemplateSidecar
 * @typedef {{
 *   engine: 'postgres' | 'mysql' | 'mariadb' | 'valkey' | 'redis' | 'mongodb',
 *   image?: string,
 *   dbName?: string,
 *   username?: string,
 *   memoryMb?: number,
 *   cpus?: number,
 *   readyTimeoutMs?: number
 * }} TemplateDatabase
 * @typedef {{ bytes: number, encoding: 'hex' | 'base64' | 'base64url' }} TemplateSecretSpec
 * @typedef {{
 *   id: string,
 *   name: string,
 *   category: string,
 *   summary: string,
 *   description: string,
 *   website: string,
 *   licence: string,
 *   tags?: string[],
 *   database: TemplateDatabase | null,
 *   secrets: Record<string, TemplateSecretSpec>,
 *   sidecars?: TemplateSidecar[],
 *   app: {
 *     image: string,
 *     port: number,
 *     extraPorts?: TemplateExtraPort[],
 *     memoryMb: number,
 *     cpus: number,
 *     shmSize?: string,
 *     env: Record<string, string>,
 *     volumes?: TemplateVolume[],
 *     files?: TemplateFile[],
 *     command?: string[],
 *     readiness: TemplateReadiness
 *   },
 *   nextSteps?: string[],
 *   notes?: string[]
 * }} CatalogTemplate
 */

/**
 * Auxiliar Valkey fijado y listo para comprobar disponibilidad con `valkey-cli ping`.
 * @param {number} [memoryMb]
 * @returns {TemplateSidecar}
 */
function makeValkeySidecar(memoryMb = 256) {
  return {
    name: 'valkey',
    image: 'valkey/valkey:8.1-alpine',
    memoryMb,
    cpus: 0.5,
    env: {},
    volumes: [{ name: 'data', path: '/data' }],
    command: ['valkey-server', '--save', '60', '1', '--loglevel', 'warning'],
    readiness: { type: 'exec', cmd: ['valkey-cli', 'ping'], timeoutMs: 30000 }
  };
}

/**
 * Auxiliar ClickHouse fijado con supresión de logs de consulta para VPS compactos
 * y sonda TCP real en el puerto HTTP 8123.
 * @param {number} [memoryMb]
 * @param {Record<string, string>} [extraEnv]
 * @returns {TemplateSidecar}
 */
function makeClickhouseSidecar(memoryMb = 2048, extraEnv = {}) {
  return {
    name: 'clickhouse',
    image: 'clickhouse/clickhouse-server:25.8-alpine',
    memoryMb,
    cpus: memoryMb >= 1536 ? 2 : 1,
    env: { CLICKHOUSE_SKIP_USER_SETUP: '1', ...extraEnv },
    volumes: [{ name: 'clickhouse', path: '/var/lib/clickhouse' }],
    files: [
      {
        name: 'logs.xml',
        path: '/etc/clickhouse-server/config.d/logging.xml',
        content:
          '<clickhouse>\n' +
          '  <logger><level>warning</level><console>true</console></logger>\n' +
          '  <query_thread_log remove="remove"/>\n' +
          '  <query_log remove="remove"/>\n' +
          '  <text_log remove="remove"/>\n' +
          '  <trace_log remove="remove"/>\n' +
          '  <metric_log remove="remove"/>\n' +
          '  <asynchronous_metric_log remove="remove"/>\n' +
          '  <session_log remove="remove"/>\n' +
          '  <part_log remove="remove"/>\n' +
          '</clickhouse>\n'
      },
      {
        name: 'user.xml',
        path: '/etc/clickhouse-server/users.d/logging.xml',
        content:
          '<clickhouse>\n' +
          '  <profiles><default>\n' +
          '    <log_queries>0</log_queries>\n' +
          '    <log_query_threads>0</log_query_threads>\n' +
          '  </default></profiles>\n' +
          '</clickhouse>\n'
      }
    ],
    readiness: { type: 'tcp', port: 8123, timeoutMs: 45000 }
  };
}

// ---------------------------------------------------------------------------
// Plantillas
// ---------------------------------------------------------------------------

/** @type {CatalogTemplate[]} */
const TEMPLATES = [
  // -------------------------------------------------------------------------
  {
    id: 'n8n',
    name: 'n8n',
    category: 'automatizacion',
    summary: 'Automatización de flujos de trabajo con más de 400 integraciones y nodos de IA.',
    description:
      'Conecta APIs, bases de datos y modelos de lenguaje en flujos visuales que se ejecutan ' +
      'en tu servidor. Es la alternativa autohospedada a Zapier y Make, y la que mejor encaja ' +
      'con agentes: cada flujo se puede disparar por webhook.',
    website: 'https://n8n.io',
    licence: 'Sustainable Use License (código a la vista, no es software libre OSI)',
    tags: ['flujos', 'integraciones', 'webhooks', 'ia'],
    database: { engine: 'postgres', dbName: 'n8n', username: 'n8n', memoryMb: 512 },
    secrets: {
      // n8n cifra con esta clave las credenciales que guardes dentro. Si cambia,
      // dejan de poder descifrarse: por eso se genera una vez y se conserva.
      N8N_ENCRYPTION_KEY: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'n8nio/n8n:2.39.6',
      port: 5678,
      memoryMb: 1536,
      cpus: 1,
      env: {
        DB_TYPE: 'postgresdb',
        DB_POSTGRESDB_HOST: '{{db.host}}',
        DB_POSTGRESDB_PORT: '{{db.port}}',
        DB_POSTGRESDB_DATABASE: '{{db.name}}',
        DB_POSTGRESDB_USER: '{{db.user}}',
        DB_POSTGRESDB_PASSWORD: '{{db.password}}',
        N8N_ENCRYPTION_KEY: '{{secret.N8N_ENCRYPTION_KEY}}',
        N8N_HOST: '{{domain}}',
        N8N_PORT: '5678',
        N8N_PROTOCOL: '{{protocol}}',
        WEBHOOK_URL: '{{url}}/',
        N8N_EDITOR_BASE_URL: '{{url}}',
        GENERIC_TIMEZONE: '{{tz}}',
        // Sin esto n8n avisa en cada arranque de que los ficheros de
        // configuración son legibles por otros usuarios del contenedor.
        N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: 'true',
        N8N_SECURE_COOKIE: '{{isHttps}}',
        N8N_DIAGNOSTICS_ENABLED: 'false',
        N8N_RUNNERS_ENABLED: 'true'
      },
      volumes: [{ name: 'data', path: '/home/node/.n8n' }],
      // n8n responde 200 en la raíz una vez el editor está servido.
      readiness: { path: '/', expect: [200, 302, 401] }
    },
    nextSteps: [
      'Abre la URL y crea la cuenta de propietario: el primer registro se queda con la instancia.',
      'Comprueba que los webhooks apuntan a tu dominio antes de publicar ningún flujo.'
    ],
    notes: [
      'La licencia de n8n permite uso interno y autohospedado, pero no ofrecerlo como servicio a terceros.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'wordpress',
    name: 'WordPress',
    category: 'contenido',
    summary: 'Webs, blogs y tiendas WooCommerce en un clic, con MariaDB aislada y HTTPS automático.',
    description:
      'El CMS más usado del mundo, listo para producción o migración desde otro hosting. ' +
      'Incluye base de datos MariaDB cifrada en red privada, límite de subida de 512 MB para ' +
      'importar backups y detección automática de HTTPS detrás de Caddy.',
    website: 'https://wordpress.org',
    licence: 'GPLv2+',
    tags: ['cms', 'wordpress', 'woocommerce', 'blog', 'tienda'],
    database: { engine: 'mariadb', dbName: 'wordpress', username: 'wordpress', memoryMb: 512 },
    secrets: {
      WORDPRESS_AUTH_KEY: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_SECURE_AUTH_KEY: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_LOGGED_IN_KEY: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_NONCE_KEY: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_AUTH_SALT: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_SECURE_AUTH_SALT: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_LOGGED_IN_SALT: { bytes: 32, encoding: 'base64url' },
      WORDPRESS_NONCE_SALT: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'wordpress:6.7.2-apache',
      port: 80,
      memoryMb: 1024,
      cpus: 1,
      env: {
        WORDPRESS_DB_HOST: '{{db.host}}:{{db.port}}',
        WORDPRESS_DB_USER: '{{db.user}}',
        WORDPRESS_DB_PASSWORD: '{{db.password}}',
        WORDPRESS_DB_NAME: '{{db.name}}',
        WORDPRESS_AUTH_KEY: '{{secret.WORDPRESS_AUTH_KEY}}',
        WORDPRESS_SECURE_AUTH_KEY: '{{secret.WORDPRESS_SECURE_AUTH_KEY}}',
        WORDPRESS_LOGGED_IN_KEY: '{{secret.WORDPRESS_LOGGED_IN_KEY}}',
        WORDPRESS_NONCE_KEY: '{{secret.WORDPRESS_NONCE_KEY}}',
        WORDPRESS_AUTH_SALT: '{{secret.WORDPRESS_AUTH_SALT}}',
        WORDPRESS_SECURE_AUTH_SALT: '{{secret.WORDPRESS_SECURE_AUTH_SALT}}',
        WORDPRESS_LOGGED_IN_SALT: '{{secret.WORDPRESS_LOGGED_IN_SALT}}',
        WORDPRESS_NONCE_SALT: '{{secret.WORDPRESS_NONCE_SALT}}',
        WORDPRESS_CONFIG_EXTRA:
          "if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') { $_SERVER['HTTPS'] = 'on'; }"
      },
      files: [
        {
          name: 'culkibo-uploads.ini',
          path: '/usr/local/etc/php/conf.d/culkibo-uploads.ini',
          content:
            'file_uploads = On\n' +
            'memory_limit = 512M\n' +
            'upload_max_filesize = 512M\n' +
            'post_max_size = 512M\n' +
            'max_execution_time = 300\n'
        }
      ],
      volumes: [{ name: 'content', path: '/var/www/html/wp-content' }],
      readiness: { path: '/', expect: [200, 301, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/wp-admin para completar la instalación en 1 minuto o importar tu copia de WordPress.',
      'Si vienes de otro hosting, puedes restaurar tu volcado .sql desde el asistente de migración o usar All-in-One WP Migration (hasta 512 MB).'
    ],
    notes: [
      'Todas las fotos, temas y plugins viven en un volumen persistente (/var/www/html/wp-content) protegido contra reinicios.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'ghost',
    name: 'Ghost',
    category: 'contenido',
    summary: 'Publicación profesional: blog, boletín y suscripciones de pago en un solo sitio.',
    description:
      'El gestor de contenidos que usan medios y autores independientes. Trae editor, ' +
      'boletines por correo, membresías y SEO sin depender de una tienda de extensiones.',
    website: 'https://ghost.org',
    licence: 'MIT',
    tags: ['blog', 'boletin', 'cms', 'suscripciones'],
    // Ghost sólo soporta MySQL 8 en producción, no MariaDB y no MySQL 9. Se
    // reutiliza `databaseManager` sobreescribiendo la imagen: la rama 8.4 es
    // LTS y tiene soporte hasta 2032, mientras que 8.0 caducó en abril de 2026.
    database: { engine: 'mysql', image: 'mysql:8.4', dbName: 'ghost', username: 'ghost', memoryMb: 768 },
    secrets: {},
    app: {
      image: 'ghost:6.64.0-alpine',
      port: 2368,
      memoryMb: 1024,
      cpus: 1,
      env: {
        url: '{{url}}',
        database__client: 'mysql',
        database__connection__host: '{{db.host}}',
        database__connection__port: '{{db.port}}',
        database__connection__user: '{{db.user}}',
        database__connection__password: '{{db.password}}',
        database__connection__database: '{{db.name}}',
        NODE_ENV: 'production'
      },
      volumes: [{ name: 'content', path: '/var/lib/ghost/content' }],
      readiness: { path: '/', expect: [200, 301, 302] }
    },
    nextSteps: [
      'Entra en {{url}}/ghost para crear la cuenta de administración.',
      'Configura el envío de correo (Mailgun) si vas a usar boletines: Ghost no envía nada sin ello.'
    ],
    notes: [
      'La primera arrancada tarda: Ghost migra el esquema de la base de datos antes de responder.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'plausible',
    name: 'Plausible',
    category: 'analitica',
    summary: 'Analítica web sin cookies ni datos personales, compatible con el RGPD.',
    description:
      'Mide visitas, fuentes y conversiones con un script de menos de 1 KB. No usa cookies, ' +
      'no cruza datos entre sitios y no necesita banner de consentimiento.',
    website: 'https://plausible.io',
    licence: 'AGPLv3',
    tags: ['analitica', 'rgpd', 'sin cookies'],
    database: { engine: 'postgres', dbName: 'plausible', username: 'plausible', memoryMb: 512 },
    secrets: {
      // Phoenix exige al menos 64 bytes para la clave de firma de sesiones.
      SECRET_KEY_BASE: { bytes: 64, encoding: 'base64' },
      TOTP_VAULT_KEY: { bytes: 32, encoding: 'base64' }
    },
    sidecars: [makeClickhouseSidecar(2048)],
    app: {
      image: 'ghcr.io/plausible/community-edition:v3.2.1',
      port: 8000,
      memoryMb: 1536,
      cpus: 1,
      command: ['sh', '-c', '/entrypoint.sh db createdb && /entrypoint.sh db migrate && /entrypoint.sh run'],
      env: {
        BASE_URL: '{{url}}',
        SECRET_KEY_BASE: '{{secret.SECRET_KEY_BASE}}',
        TOTP_VAULT_KEY: '{{secret.TOTP_VAULT_KEY}}',
        DATABASE_URL: '{{db.url}}',
        CLICKHOUSE_DATABASE_URL: 'http://{{sidecar.clickhouse.host}}:8123/plausible_events_db',
        DISABLE_REGISTRATION: 'invite_only'
      },
      volumes: [{ name: 'data', path: '/var/lib/plausible' }],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Regístrate en {{url}}/register: la primera cuenta es la de administración y después el registro queda cerrado.',
      'Añade tu sitio y copia el script de seguimiento.'
    ],
    notes: [
      'ClickHouse necesita 2 GB de memoria: en un VPS de 2 GB en total, Plausible no cabe junto a nada más.',
      'El envío de correo (invitaciones, informes) requiere configurar SMTP a mano en las variables de la instalación.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'uptime-kuma',
    name: 'Uptime Kuma',
    category: 'monitorizacion',
    summary: 'Vigila que tus sitios respondan y avisa por Telegram, Discord o correo cuando caen.',
    description:
      'Sondas HTTP, TCP, ping, DNS y certificados con histórico y páginas de estado públicas. ' +
      'Noventa canales de notificación incluidos.',
    website: 'https://uptime.kuma.pet',
    licence: 'MIT',
    tags: ['monitorizacion', 'avisos', 'pagina de estado'],
    // SQLite dentro del volumen: para el número de sondas de un VPS es de
    // sobra, y evita arrastrar un motor entero por una tabla de latencias.
    database: null,
    secrets: {},
    app: {
      image: 'louislam/uptime-kuma:2.5.4',
      port: 3001,
      memoryMb: 512,
      cpus: 0.5,
      env: { UPTIME_KUMA_PORT: '3001' },
      volumes: [{ name: 'data', path: '/app/data' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Crea la cuenta de administración en el primer arranque: hasta que exista, cualquiera puede crearla.',
      'Añade una sonda para el propio panel de Culkibo y otra para tus dominios.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'metabase',
    name: 'Metabase',
    category: 'analitica',
    summary: 'Cuadros de mando y consultas sobre tus bases de datos sin escribir SQL.',
    description:
      'Se conecta a PostgreSQL, MySQL, MongoDB y una veintena más, y deja construir preguntas ' +
      'y paneles arrastrando. Quien sepa SQL lo escribe; quien no, no lo necesita.',
    website: 'https://www.metabase.com',
    licence: 'AGPLv3 (edición comunitaria)',
    tags: ['bi', 'cuadros de mando', 'sql', 'informes'],
    // La base de datos de aplicación. Metabase arranca con H2 embebido si no se
    // le dice otra cosa, y su propia documentación advierte de que H2 se
    // corrompe y NO debe usarse en producción.
    database: { engine: 'postgres', dbName: 'metabase', username: 'metabase', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'metabase/metabase:v0.63.18',
      port: 3000,
      memoryMb: 2048,
      cpus: 2,
      env: {
        MB_DB_TYPE: 'postgres',
        MB_DB_HOST: '{{db.host}}',
        MB_DB_PORT: '{{db.port}}',
        MB_DB_DBNAME: '{{db.name}}',
        MB_DB_USER: '{{db.user}}',
        MB_DB_PASS: '{{db.password}}',
        MB_SITE_URL: '{{url}}',
        JAVA_TOOL_OPTIONS: '-Xmx1500m'
      },
      volumes: [{ name: 'plugins', path: '/plugins' }],
      // Metabase tarda en levantar la JVM y migrar; la sonda espera hasta 4 min.
      readiness: { path: '/api/health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'El primer arranque tarda entre uno y tres minutos: la JVM migra el esquema antes de contestar.',
      'Crea la cuenta de administración y conecta tu primera base de datos.'
    ],
    notes: [
      'Metabase necesita 2 GB de memoria de verdad. Con menos, la JVM muere por OOM a mitad de una consulta.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'minio',
    name: 'MinIO',
    category: 'datos',
    summary: 'Almacenamiento de objetos compatible con S3 para copias, adjuntos y archivos.',
    description:
      'Expone una API S3 en tu propio servidor. Sirve como destino de las copias programadas ' +
      'de Culkibo y como almacén de ficheros para cualquier aplicación que hable S3.',
    website: 'https://min.io',
    licence: 'AGPLv3',
    tags: ['s3', 'objetos', 'copias', 'almacenamiento'],
    database: null,
    secrets: {
      MINIO_ROOT_PASSWORD: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z',
      // 9000 es la API S3. Es el puerto que recibe el dominio.
      port: 9000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        MINIO_ROOT_USER: 'culkibo',
        MINIO_ROOT_PASSWORD: '{{secret.MINIO_ROOT_PASSWORD}}',
        MINIO_BROWSER: 'off'
      },
      volumes: [{ name: 'data', path: '/data' }],
      command: ['server', '/data'],
      // La API S3 contesta 403 a una petición anónima sin firmar. Eso es estar
      // viva: exigir 200 daría por muerta una instalación correcta.
      readiness: { path: '/minio/health/live', expect: [200] }
    },
    nextSteps: [
      'Copia el usuario y la contraseña de la instalación: son las claves de acceso S3.',
      'Configúralo como destino de copias en Configuración › Almacenamiento de copias.'
    ],
    notes: [
      'MinIO retiró la consola web de la edición comunitaria en 2025. Esta instalación sirve la API S3, ' +
      'no un panel: para administrarla se usa el cliente «mc» o cualquier cliente S3.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'gitea',
    name: 'Gitea',
    category: 'desarrollo',
    summary: 'Tu propio GitHub: repositorios, incidencias, revisiones y acciones de CI.',
    description:
      'Servidor Git ligero escrito en Go, con interfaz web, peticiones de fusión, registro de ' +
      'paquetes y Gitea Actions compatible con los flujos de GitHub.',
    website: 'https://about.gitea.com',
    licence: 'MIT',
    tags: ['git', 'repositorios', 'ci', 'incidencias'],
    database: null,
    secrets: {},
    app: {
      image: 'gitea/gitea:1.27.3',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        USER_UID: '1000',
        USER_GID: '1000',
        GITEA__database__DB_TYPE: 'sqlite3',
        GITEA__server__DOMAIN: '{{domain}}',
        GITEA__server__ROOT_URL: '{{url}}/',
        GITEA__server__SSH_DOMAIN: '{{domain}}',
        // Sin servidor SSH interno: el puerto 22 del host es del sistema y
        // publicarlo desde un contenedor es una forma conocida de quedarse sin
        // acceso al servidor. Se clona por HTTPS.
        GITEA__server__DISABLE_SSH: 'true',
        GITEA__service__DISABLE_REGISTRATION: 'false'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre la URL y completa el asistente inicial AHORA: hasta que lo hagas, quien llegue primero configura el servidor.',
      'En el asistente, crea la cuenta de administración y desactiva el registro abierto.'
    ],
    notes: [
      'El acceso por SSH viene desactivado: se clona por HTTPS con un token personal.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'vaultwarden',
    name: 'Vaultwarden',
    category: 'seguridad',
    summary: 'Gestor de contraseñas compatible con los clientes de Bitwarden.',
    description:
      'Implementación en Rust del servidor de Bitwarden: las aplicaciones móviles, las ' +
      'extensiones y la web oficiales funcionan contra ella. Consume una fracción de memoria.',
    website: 'https://github.com/dani-garcia/vaultwarden',
    licence: 'AGPLv3',
    tags: ['contrasenas', 'bitwarden', 'boveda'],
    database: null,
    secrets: {
      ADMIN_TOKEN: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'vaultwarden/server:1.37.3-alpine',
      port: 80,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        DOMAIN: '{{url}}',
        ADMIN_TOKEN: '{{secret.ADMIN_TOKEN}}',
        // Registro cerrado por defecto. Una bóveda de contraseñas en un dominio
        // público con registro abierto es una invitación, no un servicio.
        SIGNUPS_ALLOWED: 'false',
        // Con el registro cerrado hace falta poder invitar desde /admin.
        INVITATIONS_ALLOWED: 'true',
        ROCKET_PORT: '80'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/alive', expect: [200] }
    },
    nextSteps: [
      'Guarda el ADMIN_TOKEN en un sitio seguro: es la llave del panel {{url}}/admin.',
      'Entra en /admin e invita a tu propia cuenta: el registro abierto viene desactivado a propósito.'
    ],
    notes: [
      'Vaultwarden no es un producto de Bitwarden Inc. y no está auditado por ellos. Para uso personal y de equipos pequeños.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'redis-commander',
    name: 'Valkey con Redis Commander',
    category: 'datos',
    summary: 'Una caché Valkey lista para usar, con interfaz web para inspeccionar sus claves.',
    description:
      'Aprovisiona una base clave-valor Valkey gestionada por Culkibo y le pone delante Redis ' +
      'Commander para ver, buscar y editar claves desde el navegador.',
    website: 'https://github.com/joeferner/redis-commander',
    licence: 'MIT',
    tags: ['redis', 'valkey', 'cache', 'inspector'],
    // La caché es una base de datos gestionada más: hereda contraseña generada,
    // cifrado en reposo y copias programadas como cualquier otra.
    database: { engine: 'valkey', username: 'culkibo', memoryMb: 512 },
    secrets: {
      HTTP_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'ghcr.io/joeferner/redis-commander:0.9.1',
      port: 8081,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        REDIS_HOSTS: 'valkey:{{db.host}}:{{db.port}}:0:{{db.password}}',
        // Autenticación básica obligatoria. Un inspector de claves sin
        // contraseña en un dominio público entrega la caché entera.
        HTTP_USER: 'culkibo',
        HTTP_PASSWORD: '{{secret.HTTP_PASSWORD}}',
        // La imagen es de 2022 y su Node antiguo avisa de esto en cada arranque.
        NODE_OPTIONS: '--openssl-legacy-provider'
      },
      volumes: [],
      readiness: { path: '/', expect: [200, 401] }
    },
    nextSteps: [
      'Entra con el usuario «culkibo» y la contraseña HTTP_PASSWORD de la instalación.',
      'La cadena de conexión de Valkey está en Bases de datos › credenciales.'
    ],
    notes: [
      'Redis Commander apenas recibe mantenimiento desde 2022. Sirve para inspeccionar, no para operar en producción.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'umami',
    name: 'Umami',
    category: 'analitica',
    summary: 'Analítica web ligera y respetuosa con la privacidad, con panel propio.',
    description:
      'Alternativa a Google Analytics de menos de 2 KB de script. Sin cookies, con métricas por ' +
      'sitio, eventos personalizados y paneles públicos compartibles.',
    website: 'https://umami.is',
    licence: 'MIT',
    tags: ['analitica', 'privacidad', 'eventos'],
    database: { engine: 'postgres', dbName: 'umami', username: 'umami', memoryMb: 512 },
    secrets: {
      APP_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/umami-software/umami:3.3.1',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        DATABASE_TYPE: 'postgresql',
        APP_SECRET: '{{secret.APP_SECRET}}',
        DISABLE_TELEMETRY: '1'
      },
      volumes: [],
      // Umami migra el esquema al arrancar; /api/heartbeat responde cuando acaba.
      readiness: { path: '/api/heartbeat', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Entra con el usuario «admin» y la contraseña «umami», y cámbiala de inmediato.',
      'Añade tu sitio y pega el script de seguimiento en tus páginas.'
    ],
    notes: [
      'La contraseña inicial es pública y la fija el propio proyecto. Cambiarla es el primer paso, no una recomendación.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'listmonk',
    name: 'Listmonk',
    category: 'contenido',
    summary: 'Gestor de listas de correo y boletines, con plantillas y estadísticas.',
    description:
      'Servidor de boletines autohospedado escrito en Go. Importa suscriptores, segmenta con SQL, ' +
      'envía por cualquier SMTP y mide aperturas y clics.',
    website: 'https://listmonk.app',
    licence: 'AGPLv3',
    tags: ['boletin', 'correo', 'suscriptores'],
    database: { engine: 'postgres', dbName: 'listmonk', username: 'listmonk', memoryMb: 512 },
    secrets: {
      LISTMONK_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'listmonk/listmonk:v6.2.0',
      port: 9000,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        LISTMONK_app__address: '0.0.0.0:9000',
        LISTMONK_db__host: '{{db.host}}',
        LISTMONK_db__port: '{{db.port}}',
        LISTMONK_db__user: '{{db.user}}',
        LISTMONK_db__password: '{{db.password}}',
        LISTMONK_db__database: '{{db.name}}',
        LISTMONK_db__ssl_mode: 'disable',
        LISTMONK_ADMIN_USER: 'admin',
        LISTMONK_ADMIN_PASSWORD: '{{secret.LISTMONK_ADMIN_PASSWORD}}'
      },
      volumes: [{ name: 'uploads', path: '/listmonk/uploads' }],
      // Listmonk no crea su esquema solo: hay que invocar --install antes de
      // servir. La cadena es CONSTANTE y no lleva ningún dato del usuario; las
      // credenciales llegan por el fichero de entorno, no por aquí.
      command: [
        'sh', '-c',
        './listmonk --install --idempotent --yes --config "" && ' +
        './listmonk --upgrade --yes --config "" && ' +
        'exec ./listmonk --config ""'
      ],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Entra con «admin» y la contraseña de la instalación.',
      'Configura un servidor SMTP en Configuración: sin él Listmonk no envía nada.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'nocodb',
    name: 'NocoDB',
    category: 'productividad',
    summary: 'Hojas de cálculo colaborativas sobre bases de datos reales. Alternativa a Airtable.',
    description:
      'Convierte una base de datos en una interfaz de tablas, formularios, galerías y kanban. ' +
      'Se puede conectar a bases existentes sin migrar nada.',
    website: 'https://nocodb.com',
    licence: 'AGPLv3',
    tags: ['airtable', 'tablas', 'formularios', 'sin codigo'],
    database: { engine: 'postgres', dbName: 'nocodb', username: 'nocodb', memoryMb: 512 },
    secrets: {
      NC_AUTH_JWT_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'nocodb/nocodb:2026.09.0',
      port: 8080,
      memoryMb: 1536,
      cpus: 1,
      env: {
        NC_DB: 'pg://{{db.host}}:{{db.port}}?u={{db.user}}&p={{db.password}}&d={{db.name}}',
        NC_AUTH_JWT_SECRET: '{{secret.NC_AUTH_JWT_SECRET}}',
        NC_PUBLIC_URL: '{{url}}',
        NC_DISABLE_TELE: 'true'
      },
      volumes: [{ name: 'data', path: '/usr/app/data' }],
      readiness: { path: '/api/v1/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Crea la cuenta de administración: la primera que se registre se queda con la instancia.',
      'Crea una base nueva o conecta una existente desde «Conectar fuente de datos».'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'stirling-pdf',
    name: 'Stirling PDF',
    category: 'productividad',
    summary: 'Cincuenta herramientas de PDF en tu servidor: unir, dividir, firmar, OCR y comprimir.',
    description:
      'Todo lo que se suele subir a una web gratuita de PDF, hecho en tu propio servidor y sin ' +
      'que el documento salga de él. Incluye OCR, conversión y firma.',
    website: 'https://stirlingpdf.com',
    licence: 'MIT',
    tags: ['pdf', 'ocr', 'documentos', 'firma'],
    database: null,
    secrets: {
      SECURITY_INITIALLOGIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'ghcr.io/stirling-tools/s-pdf:2.14.3',
      port: 8080,
      memoryMb: 2048,
      cpus: 2,
      env: {
        DOCKER_ENABLE_SECURITY: 'true',
        // Sin login, cualquiera que encuentre el dominio procesa documentos en
        // tu servidor. Para una herramienta que recibe ficheros, es obligatorio.
        SECURITY_ENABLELOGIN: 'true',
        SECURITY_INITIALLOGIN_USERNAME: 'culkibo',
        SECURITY_INITIALLOGIN_PASSWORD: '{{secret.SECURITY_INITIALLOGIN_PASSWORD}}',
        SECURITY_CSRFDISABLED: 'false',
        INSTALL_BOOK_AND_ADVANCED_HTML_OPS: 'false',
        LANGS: 'es_ES,en_GB',
        SYSTEM_DEFAULTLOCALE: 'es-ES'
      },
      volumes: [
        { name: 'config', path: '/configs' },
        { name: 'logs', path: '/logs' }
      ],
      readiness: { path: '/login', expect: [200, 302, 401], timeoutMs: 240000 }
    },
    nextSteps: [
      'Entra con «culkibo» y la contraseña de la instalación, y créate un usuario propio.',
      'El OCR descarga sus diccionarios la primera vez que se usa.'
    ],
    notes: [
      'La imagen arranca una JVM con LibreOffice detrás: cuenta con 2 GB de memoria y un minuto largo de arranque.'
    ]
  },

  // -------------------------------------------------------------------------
  // Stack 2026: Inteligencia artificial, BaaS, búsqueda, observabilidad y correo dev
  // -------------------------------------------------------------------------
  {
    id: 'open-webui',
    name: 'Open WebUI',
    category: 'ia',
    summary: 'Interfaz web de chat con modelos locales (Ollama) y APIs OpenAI/Anthropic/Gemini.',
    description:
      'Interfaz completa estilo ChatGPT en tu propio servidor con soporte RAG, documentos, búsqueda web, ' +
      'usuarios con roles y conexión directa a Ollama o a cualquier pasarela compatible con OpenAI.',
    website: 'https://openwebui.com',
    licence: 'Open WebUI License (BSD-3 modificado con cláusula de marca)',
    tags: ['ia', 'llm', 'chat', 'ollama', 'rag'],
    database: null,
    secrets: {
      WEBUI_SECRET_KEY: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/open-webui/open-webui:0.6.5',
      port: 8080,
      memoryMb: 1024,
      cpus: 2,
      env: {
        WEBUI_SECRET_KEY: '{{secret.WEBUI_SECRET_KEY}}',
        WEBUI_URL: '{{url}}',
        ENABLE_SIGNUP: 'true',
        DEFAULT_LOCALE: 'es-ES'
      },
      volumes: [{ name: 'data', path: '/app/backend/data' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea la primera cuenta, que pasará a ser administradora.',
      'En Ajustes → Conexiones añade tu instancia de Ollama o tu clave de API.'
    ],
    notes: [
      'El primer arranque descarga modelos ligeros de embeddings; dale ~60 segundos antes de abrirlo.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'ollama',
    name: 'Ollama',
    category: 'ia',
    summary: 'Motor local para ejecutar modelos de lenguaje abiertos (Llama, Qwen, Mistral, DeepSeek).',
    description:
      'Sirve modelos de IA locales mediante API HTTP compatible con OpenAI en una red privada. ' +
      'Se integra de forma nativa con Open WebUI, n8n y LiteLLM sin enviar datos fuera de tu servidor.',
    website: 'https://ollama.com',
    licence: 'MIT',
    tags: ['ia', 'llm', 'modelos', 'inferencia'],
    database: null,
    secrets: {},
    app: {
      image: 'ollama/ollama:0.6.2',
      port: 11434,
      memoryMb: 2048,
      cpus: 2,
      env: {
        OLLAMA_HOST: '0.0.0.0:11434',
        OLLAMA_KEEP_ALIVE: '5m'
      },
      volumes: [{ name: 'models', path: '/root/.ollama' }],
      readiness: { path: '/api/tags', expect: [200] }
    },
    nextSteps: [
      'Descarga un modelo ligero dentro del contenedor (p. ej. `ollama pull qwen2.5:3b`).',
      'Mantén el dominio protegido con Basic Auth o úsalo solo en red local.'
    ],
    notes: [
      'Sin GPU los modelos corren en CPU: calcula al menos 4 GB de RAM libres para modelos de 3B-7B.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'qdrant',
    name: 'Qdrant',
    category: 'ia',
    summary: 'Base de datos vectorial en Rust de muy baja latencia para RAG y búsqueda semántica.',
    description:
      'Motor vectorial optimizado en Rust con filtrado avanzado por metadatos, cuantización y panel web ' +
      'incorporado. Protegido desde el primer segundo con API Key aleatoria.',
    website: 'https://qdrant.tech',
    licence: 'Apache-2.0',
    tags: ['ia', 'vectores', 'rag', 'busqueda', 'rust'],
    database: null,
    secrets: {
      QDRANT__SERVICE__API_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'qdrant/qdrant:v1.13.4',
      port: 6333,
      memoryMb: 1024,
      cpus: 1,
      env: {
        QDRANT__SERVICE__API_KEY: '{{secret.QDRANT__SERVICE__API_KEY}}'
      },
      volumes: [{ name: 'storage', path: '/qdrant/storage' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Consulta la API Key generada en «Credenciales» y pásala en la cabecera `api-key`.',
      'Abre {{url}}/dashboard para inspeccionar colecciones y vectores.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'litellm',
    name: 'LiteLLM Proxy',
    category: 'ia',
    summary: 'Pasarela unificada OpenAI para +100 proveedores LLM con control de costes y claves virtuales.',
    description:
      'Centraliza tus proveedores de IA (OpenAI, Anthropic, Gemini, Bedrock, Ollama) detrás de una única ' +
      'API compatible con OpenAI, con presupuestos por equipo, fallback automático y registros en PostgreSQL.',
    website: 'https://www.litellm.ai',
    licence: 'MIT',
    tags: ['ia', 'gateway', 'openai', 'proxy', 'costes'],
    database: { engine: 'postgres', dbName: 'litellm', username: 'litellm', memoryMb: 512 },
    secrets: {
      LITELLM_MASTER_KEY: { bytes: 24, encoding: 'hex' },
      LITELLM_SALT_KEY: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/berriai/litellm:v1.63.11',
      port: 4000,
      memoryMb: 768,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        LITELLM_MASTER_KEY: 'sk-{{secret.LITELLM_MASTER_KEY}}',
        LITELLM_SALT_KEY: '{{secret.LITELLM_SALT_KEY}}',
        STORE_MODEL_IN_DB: 'True'
      },
      volumes: [],
      readiness: { path: '/health/liveliness', expect: [200, 401], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/ui e inicia sesión con la clave maestra (`sk-...`) desde «Credenciales».',
      'Añade tus proveedores de IA y genera claves virtuales con límite de gasto.'
    ],
    notes: [
      'Guarda `LITELLM_SALT_KEY`: se usa para cifrar las claves de proveedores dentro de PostgreSQL.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'pocketbase',
    name: 'PocketBase',
    category: 'datos',
    summary: 'Backend en un solo binario Go con SQLite en tiempo real, autenticación y almacenamiento.',
    description:
      'Alternativa ultraligera a Firebase y Supabase en menos de 40 MB de RAM: base SQLite integrada, ' +
      'suscripciones en vivo, panel de administración y API REST lista al instante.',
    website: 'https://pocketbase.io',
    licence: 'MIT',
    tags: ['baas', 'sqlite', 'auth', 'realtime', 'go'],
    database: null,
    secrets: {},
    app: {
      image: 'ghcr.io/muchobien/pocketbase:0.25.9',
      port: 8090,
      memoryMb: 256,
      cpus: 1,
      env: {
        PB_ENCRYPTION_KEY: ''
      },
      volumes: [{ name: 'pb_data', path: '/pb_data' }],
      readiness: { path: '/api/health', expect: [200] }
    },
    nextSteps: [
      'Revisa los registros del contenedor para obtener el enlace de creación del superusuario (`/_/`).'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'directus',
    name: 'Directus',
    category: 'contenido',
    summary: 'CMS headless y capa de datos instantánea sobre PostgreSQL con REST, GraphQL y flujos.',
    description:
      'Convierte cualquier esquema SQL en una API REST y GraphQL completa con panel editorial moderno, ' +
      'permisos granulares, automatizaciones y gestión de archivos.',
    website: 'https://directus.io',
    licence: 'BSL 1.1 (código a la vista; libre para proyectos menores a 5M USD de ingresos)',
    tags: ['cms', 'headless', 'api', 'graphql', 'datos'],
    database: { engine: 'postgres', dbName: 'directus', username: 'directus', memoryMb: 512 },
    secrets: {
      DIRECTUS_SECRET: { bytes: 32, encoding: 'hex' },
      ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'directus/directus:11.5.1',
      port: 8055,
      memoryMb: 768,
      cpus: 1,
      env: {
        SECRET: '{{secret.DIRECTUS_SECRET}}',
        DB_CLIENT: 'pg',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_DATABASE: '{{db.name}}',
        DB_USER: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        ADMIN_EMAIL: 'admin@culkibo.local',
        ADMIN_PASSWORD: '{{secret.ADMIN_PASSWORD}}',
        PUBLIC_URL: '{{url}}',
        WEBSOCKETS_ENABLED: 'true'
      },
      volumes: [{ name: 'uploads', path: '/directus/uploads' }],
      readiness: { path: '/server/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con `admin@culkibo.local` y la contraseña en «Credenciales».',
      'Cambia el correo de administración desde el perfil de usuario tras entrar.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'meilisearch',
    name: 'Meilisearch',
    category: 'datos',
    summary: 'Motor de búsqueda instantánea tolerante a erratas en Rust (alternativa libre a Algolia).',
    description:
      'Búsqueda full-text en menos de 50 ms con tolerancia a errores tipográficos, filtros facetados ' +
      'y resaltado de resultados. Incluye clave maestra autogenerada.',
    website: 'https://www.meilisearch.com',
    licence: 'MIT',
    tags: ['busqueda', 'algolia', 'rust', 'fulltext'],
    database: null,
    secrets: {
      MEILI_MASTER_KEY: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'getmeili/meilisearch:v1.13.3',
      port: 7700,
      memoryMb: 512,
      cpus: 1,
      env: {
        MEILI_ENV: 'production',
        MEILI_MASTER_KEY: '{{secret.MEILI_MASTER_KEY}}',
        MEILI_NO_ANALYTICS: 'true'
      },
      volumes: [{ name: 'meili_data', path: '/meili_data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Usa la clave maestra de «Credenciales» para generar claves de búsqueda de sólo lectura para el frontend.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'grafana',
    name: 'Grafana',
    category: 'monitorizacion',
    summary: 'Paneles de métricas, alertas y observabilidad listos para conectar al `/metrics` de Culkibo.',
    description:
      'Visualiza Prometheus, Loki, PostgreSQL y métricas del propio daemon de Culkibo con cuadros de ' +
      'mando profesionales, alertas y usuarios.',
    website: 'https://grafana.com',
    licence: 'AGPLv3',
    tags: ['metricas', 'prometheus', 'dashboards', 'observabilidad'],
    database: null,
    secrets: {
      GF_SECURITY_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'grafana/grafana:11.5.2',
      port: 3000,
      memoryMb: 512,
      cpus: 1,
      env: {
        GF_SECURITY_ADMIN_USER: 'admin',
        GF_SECURITY_ADMIN_PASSWORD: '{{secret.GF_SECURITY_ADMIN_PASSWORD}}',
        GF_SERVER_ROOT_URL: '{{url}}',
        GF_USERS_ALLOW_SIGN_UP: 'false'
      },
      volumes: [{ name: 'data', path: '/var/lib/grafana' }],
      readiness: { path: '/api/health', expect: [200] }
    },
    nextSteps: [
      'Entra en {{url}} como `admin` con la contraseña generada en «Credenciales».',
      'Añade tu servidor Prometheus o PostgreSQL como fuente de datos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'mailpit',
    name: 'Mailpit',
    category: 'desarrollo',
    summary: 'Bandeja SMTP de pruebas y depuración de correos con visor HTML, API y análisis de enlaces.',
    description:
      'Captura todos los correos salientes de tus entornos de staging y desarrollo sin enviar emails ' +
      'reales a clientes. Interfaz web rápida, búsqueda y vista previa móvil/escritorio.',
    website: 'https://mailpit.axllent.org',
    licence: 'MIT',
    tags: ['smtp', 'email', 'testing', 'staging'],
    database: null,
    secrets: {},
    app: {
      image: 'axllent/mailpit:v1.22.3',
      port: 8025,
      extraPorts: [{ containerPort: 1025, label: 'SMTP' }],
      memoryMb: 256,
      cpus: 1,
      env: {
        MP_DATABASE: '/data/mailpit.db',
        MP_MAX_MESSAGES: '5000'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/livez', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para ver los correos capturados.',
      'Apunta el cliente SMTP de tus apps de prueba al contenedor en el puerto 1025.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // A. Inteligencia artificial (6 nuevas → 10 en total)
  // -------------------------------------------------------------------------
  {
    id: 'flowise',
    name: 'Flowise',
    category: 'ia',
    summary: 'Constructor visual de agentes, cadenas RAG y flujos sobre modelos de lenguaje.',
    description:
      'Diseña flujos conversacionales, agentes con herramientas y pipelines RAG arrastrando nodos ' +
      'sobre PostgreSQL, con API REST lista para incrustar en cualquier producto.',
    website: 'https://flowiseai.com',
    licence: 'Apache-2.0',
    tags: ['ia', 'agentes', 'rag', 'langchain', 'flujos'],
    database: { engine: 'postgres', dbName: 'flowise', username: 'flowise', memoryMb: 512 },
    secrets: {
      FLOWISE_PASSWORD: { bytes: 24, encoding: 'base64url' },
      FLOWISE_SECRETKEY_OVERWRITE: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'flowiseai/flowise:3.1.4',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        PORT: '3000',
        FLOWISE_USERNAME: 'admin',
        FLOWISE_PASSWORD: '{{secret.FLOWISE_PASSWORD}}',
        FLOWISE_SECRETKEY_OVERWRITE: '{{secret.FLOWISE_SECRETKEY_OVERWRITE}}',
        DATABASE_TYPE: 'postgres',
        DATABASE_HOST: '{{db.host}}',
        DATABASE_PORT: '{{db.port}}',
        DATABASE_USER: '{{db.user}}',
        DATABASE_PASSWORD: '{{db.password}}',
        DATABASE_NAME: '{{db.name}}',
        BLOB_STORAGE_PATH: '/root/.flowise/storage',
        APIKEY_PATH: '/root/.flowise',
        SECRETKEY_PATH: '/root/.flowise',
        LOG_PATH: '/root/.flowise/logs'
      },
      volumes: [{ name: 'data', path: '/root/.flowise' }],
      readiness: { path: '/api/v1/ping', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} e inicia sesión con «admin» y la contraseña FLOWISE_PASSWORD en «Credenciales».',
      'Añade tus claves de OpenAI, Anthropic, Gemini u Ollama desde la pestaña de credenciales de Flowise.'
    ],
    notes: [
      'Guarda FLOWISE_SECRETKEY_OVERWRITE: cifra todas las API keys almacenadas dentro de tus flujos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'anythingllm',
    name: 'AnythingLLM',
    category: 'ia',
    summary: 'Espacios de trabajo privados para chatear con documentos, bases de conocimiento y agentes.',
    description:
      'Ingesta PDFs, repositorios, webs y documentación interna en espacios aislados por equipo, ' +
      'con soporte para modelos locales (Ollama) y proveedores comerciales.',
    website: 'https://anythingllm.com',
    licence: 'MIT',
    tags: ['ia', 'rag', 'documentos', 'chat', 'agentes'],
    database: null,
    secrets: {
      JWT_SECRET: { bytes: 32, encoding: 'hex' },
      AUTH_TOKEN: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'mintplexlabs/anythingllm:1.20.0',
      port: 3001,
      memoryMb: 1536,
      cpus: 2,
      env: {
        STORAGE_DIR: '/app/server/storage',
        SERVER_PORT: '3001',
        JWT_SECRET: '{{secret.JWT_SECRET}}',
        AUTH_TOKEN: '{{secret.AUTH_TOKEN}}',
        DISABLE_TELEMETRY: 'true'
      },
      volumes: [{ name: 'storage', path: '/app/server/storage' }],
      readiness: { path: '/api/ping', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y completa el asistente inicial seleccionando tu proveedor LLM y motor vectorial.',
      'El acceso queda protegido con AUTH_TOKEN desde el primer arranque: cópialo desde «Credenciales».'
    ],
    notes: [
      'La base vectorial LanceDB y SQLite se guardan en el volumen persistente `/app/server/storage`.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'chromadb',
    name: 'Chroma',
    category: 'ia',
    summary: 'Base de datos vectorial open source para embeddings, memoria de agentes y RAG.',
    description:
      'Almacena y consulta colecciones de vectores con metadatos mediante HTTP. Lista para conectar ' +
      'con LangChain, LlamaIndex, Flowise o tus propios agentes de IA.',
    website: 'https://www.trychroma.com',
    licence: 'Apache-2.0',
    tags: ['ia', 'vectores', 'embeddings', 'rag'],
    database: null,
    secrets: {
      CHROMA_SERVER_AUTHN_CREDENTIALS: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'chromadb/chroma:1.5.9',
      port: 8000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        IS_PERSISTENT: 'TRUE',
        PERSIST_DIRECTORY: '/data',
        ANONYMIZED_TELEMETRY: 'FALSE',
        CHROMA_SERVER_AUTHN_PROVIDER: 'chromadb.auth.token_authn.TokenAuthenticationServerProvider',
        CHROMA_SERVER_AUTHN_CREDENTIALS: '{{secret.CHROMA_SERVER_AUTHN_CREDENTIALS}}'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/api/v2/heartbeat', expect: [200] }
    },
    nextSteps: [
      'Copia el token CHROMA_SERVER_AUTHN_CREDENTIALS en «Credenciales» y envíalo en la cabecera `Authorization: Bearer`.',
      'Usa {{url}} como endpoint HTTP desde tu cliente Python o TypeScript de Chroma.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'weaviate',
    name: 'Weaviate',
    category: 'ia',
    summary: 'Motor de búsqueda vectorial e híbrida BM25 + embeddings con API REST y gRPC.',
    description:
      'Base de datos vectorial escrita en Go que combina búsqueda semántica con filtrado estructurado ' +
      'y BM25. Arranca con acceso anónimo desactivado y clave de administración generada.',
    website: 'https://weaviate.io',
    licence: 'BSD-3-Clause',
    tags: ['ia', 'vectores', 'busqueda', 'hibrida', 'grpc'],
    database: null,
    secrets: {
      AUTHENTICATION_APIKEY_ALLOWED_KEYS: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'cr.weaviate.io/semitechnologies/weaviate:1.40.7',
      port: 8080,
      extraPorts: [{ containerPort: 50051, label: 'gRPC' }],
      memoryMb: 1536,
      cpus: 2,
      env: {
        QUERY_DEFAULTS_LIMIT: '25',
        PERSISTENCE_DATA_PATH: '/var/lib/weaviate',
        DEFAULT_VECTORIZER_MODULE: 'none',
        CLUSTER_HOSTNAME: 'node1',
        AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'false',
        AUTHENTICATION_APIKEY_ENABLED: 'true',
        AUTHENTICATION_APIKEY_ALLOWED_KEYS: '{{secret.AUTHENTICATION_APIKEY_ALLOWED_KEYS}}',
        AUTHENTICATION_APIKEY_USERS: 'admin@culkibo.local',
        AUTHORIZATION_ADMINLIST_ENABLED: 'true',
        AUTHORIZATION_ADMINLIST_USERS: 'admin@culkibo.local'
      },
      volumes: [{ name: 'data', path: '/var/lib/weaviate' }],
      readiness: { path: '/v1/.well-known/ready', expect: [200] }
    },
    nextSteps: [
      'Usa la clave AUTHENTICATION_APIKEY_ALLOWED_KEYS de «Credenciales» en tus clientes Weaviate.',
      'El puerto 50051 queda disponible en bucle local para clientes gRPC de alto rendimiento.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'searxng',
    name: 'SearXNG',
    category: 'ia',
    summary: 'Metabuscador privado sin rastreo con API JSON ideal para dar búsqueda web a tus LLMs.',
    description:
      'Agrega resultados de decenas de motores de búsqueda sin perfilarte ni guardar historial. ' +
      'Se integra directamente con Open WebUI, Flowise y agentes autónomos como motor de búsqueda.',
    website: 'https://docs.searxng.org',
    licence: 'AGPLv3',
    tags: ['ia', 'busqueda', 'privacidad', 'rag', 'metabuscador'],
    database: null,
    secrets: {
      SEARXNG_SECRET: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'searxng/searxng:2026.11.18-b867c56a5',
      port: 8080,
      memoryMb: 512,
      cpus: 1,
      env: {
        SEARXNG_BASE_URL: '{{url}}/',
        SEARXNG_SECRET: '{{secret.SEARXNG_SECRET}}',
        SEARXNG_REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379/0',
        SEARXNG_LIMITER: 'true'
      },
      volumes: [{ name: 'config', path: '/etc/searxng' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para probar búsquedas privadas de inmediato.',
      'Para habilitar salidas `?format=json` en agentes de IA, activa `json` en `/etc/searxng/settings.yml`.'
    ],
    notes: [
      'Incluye Valkey aislado para limitar peticiones y evitar bloqueos de los motores ascendentes.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'crawl4ai',
    name: 'Crawl4AI',
    category: 'ia',
    summary: 'Rastreador web con navegador headless que convierte páginas dinámicas en Markdown limpio para IA.',
    description:
      'Renderiza JavaScript con Chromium y extrae contenido estructurado o Markdown listo para RAG, ' +
      'protegido por token Bearer y con memoria compartida `/dev/shm` dimensionada.',
    website: 'https://crawl4ai.com',
    licence: 'Apache-2.0',
    tags: ['ia', 'scraping', 'markdown', 'rag', 'navegador'],
    database: null,
    secrets: {
      CRAWL4AI_API_TOKEN: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'unclecode/crawl4ai:0.9.5',
      port: 11235,
      memoryMb: 2048,
      cpus: 2,
      shmSize: '1g',
      env: {
        CRAWL4AI_API_TOKEN: '{{secret.CRAWL4AI_API_TOKEN}}',
        MAX_CONCURRENT_TASKS: '4'
      },
      volumes: [{ name: 'data', path: '/home/appuser/.crawl4ai' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Copia CRAWL4AI_API_TOKEN desde «Credenciales» y pásalo como `Authorization: Bearer` al consultar `/crawl`.',
      'Consulta la documentación interactiva en {{url}}/playground.'
    ],
    notes: [
      'Ejecuta Chromium internamente: necesita al menos 2 GB de RAM y 1 GB de `/dev/shm` para no cerrar pestañas.'
    ]
  },

  // -------------------------------------------------------------------------
  // B. Analítica (5 nuevas → 8 en total)
  // -------------------------------------------------------------------------
  {
    id: 'matomo',
    name: 'Matomo',
    category: 'analitica',
    summary: 'Suite completa de analítica web con propiedad total de los datos y cumplimiento RGPD.',
    description:
      'Alternativa madura a Google Analytics con embudos, comercio electrónico, campañas, objetivos ' +
      'y gestión multi-sitio respaldada por MariaDB aislada.',
    website: 'https://matomo.org',
    licence: 'GPLv3',
    tags: ['analitica', 'rgpd', 'ecommerce', 'seo'],
    database: { engine: 'mariadb', dbName: 'matomo', username: 'matomo', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'matomo:5.10.1-apache',
      port: 80,
      memoryMb: 1024,
      cpus: 1,
      env: {
        MATOMO_DATABASE_HOST: '{{db.host}}',
        MATOMO_DATABASE_ADAPTER: 'mysql',
        MATOMO_DATABASE_TABLES_PREFIX: 'matomo_',
        MATOMO_DATABASE_USERNAME: '{{db.user}}',
        MATOMO_DATABASE_PASSWORD: '{{db.password}}',
        MATOMO_DATABASE_DBNAME: '{{db.name}}',
        PHP_MEMORY_LIMIT: '512M'
      },
      volumes: [{ name: 'data', path: '/var/www/html' }],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y completa el asistente web: los datos de conexión a MariaDB ya vienen precargados.',
      'Activa la anonimización de IP en Privacidad si quieres operar sin banner de consentimiento.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'superset',
    name: 'Apache Superset',
    category: 'analitica',
    summary: 'Plataforma moderna de exploración de datos, laboratorio SQL y paneles de BI empresarial.',
    description:
      'Conecta almacenes SQL, crea gráficas interactivas avanzadas y comparte cuadros de mando con ' +
      'caché Valkey y metadatos en PostgreSQL.',
    website: 'https://superset.apache.org',
    licence: 'Apache-2.0',
    tags: ['bi', 'sql', 'dashboards', 'datos', 'analitica'],
    database: { engine: 'postgres', dbName: 'superset', username: 'superset', memoryMb: 512 },
    secrets: {
      SUPERSET_SECRET_KEY: { bytes: 32, encoding: 'base64url' },
      SUPERSET_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'apache/superset:6.0.0',
      port: 8088,
      memoryMb: 2048,
      cpus: 2,
      env: {
        SUPERSET_SECRET_KEY: '{{secret.SUPERSET_SECRET_KEY}}',
        SUPERSET_ADMIN_PASSWORD: '{{secret.SUPERSET_ADMIN_PASSWORD}}',
        SQLALCHEMY_DATABASE_URI: 'postgresql+psycopg2://{{db.user}}:{{db.password}}@{{db.host}}:{{db.port}}/{{db.name}}',
        REDIS_HOST: '{{sidecar.valkey.host}}',
        REDIS_PORT: '6379',
        SUPERSET_LOAD_EXAMPLES: 'no'
      },
      command: [
        'sh', '-c',
        'superset db upgrade && ' +
        '(superset fab create-admin --username admin --firstname Admin --lastname Culkibo ' +
        '--email admin@culkibo.local --password "$SUPERSET_ADMIN_PASSWORD" || true) && ' +
        'superset init && ' +
        'exec gunicorn --bind 0.0.0.0:8088 --workers 2 --timeout 120 "superset.app:create_app()"'
      ],
      volumes: [{ name: 'home', path: '/app/superset_home' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con la contraseña SUPERSET_ADMIN_PASSWORD de «Credenciales».',
      'Añade tus bases de datos SQL desde Settings → Database Connections.'
    ],
    notes: [
      'El primer arranque migra el esquema completo y crea los roles iniciales: puede tardar entre 1 y 3 minutos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'goatcounter',
    name: 'GoatCounter',
    category: 'analitica',
    summary: 'Analítica web ultraligera en Go sin cookies y con consumo mínimo de memoria.',
    description:
      'Mide páginas vistas, referentes y navegadores en menos de 40 MB de RAM sobre SQLite, sin ' +
      'rastrear usuarios ni requerir aviso de cookies.',
    website: 'https://www.goatcounter.com',
    licence: 'MIT',
    tags: ['analitica', 'ligera', 'privacidad', 'go'],
    database: null,
    secrets: {},
    app: {
      image: 'arp242/goatcounter:2.6.0',
      port: 8080,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        GOATCOUNTER_DB: 'sqlite+/home/goatcounter/goatcounter-data/db.sqlite3'
      },
      command: ['serve', '-automigrate', '-listen', ':8080', '-tls', 'none'],
      volumes: [{ name: 'data', path: '/home/goatcounter/goatcounter-data' }],
      readiness: { path: '/', expect: [200, 302, 303] }
    },
    nextSteps: [
      'Abre {{url}} para crear tu primer sitio y tu cuenta de administración.',
      'Copia la etiqueta `<script>` generada en el panel para empezar a registrar visitas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'ackee',
    name: 'Ackee',
    category: 'analitica',
    summary: 'Analítica minimalista en Node.js y MongoDB centrada en la privacidad y la API GraphQL.',
    description:
      'Panel limpio para medir tráfico, eventos personalizados y duración de visitas sin almacenar ' +
      'datos personales ni cookies de terceros.',
    website: 'https://ackee.electerious.com',
    licence: 'MIT',
    tags: ['analitica', 'privacidad', 'graphql', 'mongodb'],
    database: { engine: 'mongodb', dbName: 'ackee', username: 'ackee', memoryMb: 512 },
    secrets: {
      ACKEE_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'electerious/ackee:3.5.1',
      port: 3000,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        WAIT_HOSTS: '{{db.host}}:{{db.port}}',
        ACKEE_MONGODB: '{{db.url}}',
        ACKEE_USERNAME: 'admin',
        ACKEE_PASSWORD: '{{secret.ACKEE_PASSWORD}}',
        ACKEE_ALLOW_ORIGIN: '{{url}}'
      },
      volumes: [],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Entra en {{url}} con usuario «admin» y la contraseña ACKEE_PASSWORD de «Credenciales».',
      'Si vas a trackear otros dominios, añade sus orígenes en ACKEE_ALLOW_ORIGIN desde las variables de entorno.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'shlink',
    name: 'Shlink',
    category: 'analitica',
    summary: 'Acortador de enlaces propio con analítica de clics, códigos QR y API REST.',
    description:
      'Crea enlaces cortos bajo tu propio dominio, controla redirecciones por dispositivo o fecha ' +
      'y mide cada clic sin depender de Bitly.',
    website: 'https://shlink.io',
    licence: 'MIT',
    tags: ['enlaces', 'acortador', 'qr', 'analitica', 'api'],
    database: { engine: 'postgres', dbName: 'shlink', username: 'shlink', memoryMb: 512 },
    secrets: {
      INITIAL_API_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'shlinkio/shlink:4.3.0',
      port: 8080,
      memoryMb: 512,
      cpus: 1,
      env: {
        DEFAULT_DOMAIN: '{{domain}}',
        IS_HTTPS_ENABLED: '{{isHttps}}',
        DB_DRIVER: 'postgres',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_NAME: '{{db.name}}',
        DB_USER: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        INITIAL_API_KEY: '{{secret.INITIAL_API_KEY}}'
      },
      volumes: [],
      readiness: { path: '/rest/health', expect: [200] }
    },
    nextSteps: [
      'Copia INITIAL_API_KEY en «Credenciales» para conectar el panel web oficial `app.shlink.io` o llamar a la API REST.',
      'Asigna un dominio corto a esta instalación antes de compartir enlaces públicos.'
    ],
    notes: [
      'Shlink sirve la API y las redirecciones; su interfaz web se conecta como cliente estático externo usando tu API key.'
    ]
  },

  // -------------------------------------------------------------------------
  // C. Monitorización (8 nuevas → 10 en total)
  // -------------------------------------------------------------------------
  {
    id: 'prometheus',
    name: 'Prometheus',
    category: 'monitorizacion',
    summary: 'Sistema de métricas de series temporales, scraping y reglas de alerta estándar en la nube.',
    description:
      'Recolecta métricas de tus aplicaciones, exportadores y del endpoint `/metrics` de Culkibo, ' +
      'con retención de 30 días y lenguaje de consultas PromQL.',
    website: 'https://prometheus.io',
    licence: 'Apache-2.0',
    tags: ['metricas', 'promql', 'alertas', 'observabilidad'],
    database: null,
    secrets: {},
    app: {
      image: 'prom/prometheus:v3.5.5',
      port: 9090,
      memoryMb: 1024,
      cpus: 1,
      env: {},
      command: [
        '--config.file=/etc/prometheus/prometheus.yml',
        '--storage.tsdb.path=/prometheus',
        '--storage.tsdb.retention.time=30d',
        '--web.enable-lifecycle'
      ],
      files: [
        {
          name: 'prometheus.yml',
          path: '/etc/prometheus/prometheus.yml',
          content:
            'global:\n' +
            '  scrape_interval: 15s\n' +
            '  evaluation_interval: 15s\n\n' +
            'scrape_configs:\n' +
            '  - job_name: prometheus\n' +
            '    static_configs:\n' +
            '      - targets:\n' +
            '          - 127.0.0.1:9090\n'
        }
      ],
      volumes: [{ name: 'data', path: '/prometheus' }],
      readiness: { path: '/-/healthy', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y protege el dominio con Basic Auth o lista blanca de IP antes de exponerlo a internet.',
      'Conecta Prometheus como fuente de datos dentro de Grafana.'
    ],
    notes: [
      'Prometheus no trae autenticación propia: usa el dominio protegido de Culkibo o mantén el acceso en bucle local.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'loki',
    name: 'Grafana Loki',
    category: 'monitorizacion',
    summary: 'Agregador de registros centralizado inspirado en Prometheus, ligero y listo para Grafana.',
    description:
      'Indexa sólo etiquetas en lugar del texto completo para reducir memoria y disco. Configurado en ' +
      'modo monolítico TSDB v13 con retención automática de 14 días.',
    website: 'https://grafana.com/oss/loki',
    licence: 'AGPLv3',
    tags: ['logs', 'registros', 'grafana', 'observabilidad'],
    database: null,
    secrets: {},
    app: {
      image: 'grafana/loki:3.7.0',
      port: 3100,
      memoryMb: 1024,
      cpus: 1,
      env: {},
      command: ['-config.file=/etc/loki/local-config.yaml'],
      files: [
        {
          name: 'local-config.yaml',
          path: '/etc/loki/local-config.yaml',
          content:
            'auth_enabled: false\n' +
            'server:\n' +
            '  http_listen_port: 3100\n' +
            'common:\n' +
            '  instance_addr: 127.0.0.1\n' +
            '  path_prefix: /loki\n' +
            '  storage:\n' +
            '    filesystem:\n' +
            '      chunks_directory: /loki/chunks\n' +
            '      rules_directory: /loki/rules\n' +
            '  replication_factor: 1\n' +
            '  ring:\n' +
            '    kvstore:\n' +
            '      store: inmemory\n' +
            'schema_config:\n' +
            '  configs:\n' +
            '    - from: 2024-01-01\n' +
            '      store: tsdb\n' +
            '      object_store: filesystem\n' +
            '      schema: v13\n' +
            '      index:\n' +
            '        prefix: index_\n' +
            '        period: 24h\n' +
            'limits_config:\n' +
            '  allow_structured_metadata: true\n' +
            '  retention_period: 336h\n' +
            'compactor:\n' +
            '  working_directory: /loki/compactor\n' +
            '  retention_enabled: true\n' +
            '  delete_request_store: filesystem\n'
        }
      ],
      volumes: [{ name: 'data', path: '/loki' }],
      readiness: { path: '/ready', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Añade Loki en Grafana como fuente de datos y envía logs desde Alloy, Promtail o Fluent Bit.',
      'Protege el dominio con Basic Auth si vas a recibir logs desde servidores externos.'
    ],
    notes: [
      'Loki no incluye interfaz web propia: se consulta desde Grafana o con `logcli`.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'victoriametrics',
    name: 'VictoriaMetrics',
    category: 'monitorizacion',
    summary: 'Base de datos de series temporales compatible con Prometheus y alta compresión en disco.',
    description:
      'Acepta remote_write de Prometheus, InfluxDB y OpenTelemetry con una fracción de la RAM de ' +
      'Prometheus tradicional. Incluye interfaz `vmui` y retención de 90 días.',
    website: 'https://victoriametrics.com',
    licence: 'Apache-2.0',
    tags: ['metricas', 'tsdb', 'prometheus', 'observabilidad'],
    database: null,
    secrets: {},
    app: {
      image: 'victoriametrics/victoria-metrics:v1.156.0',
      port: 8428,
      memoryMb: 768,
      cpus: 1,
      env: {},
      command: [
        '--storageDataPath=/victoria-metrics-data',
        '--retentionPeriod=90d',
        '--httpListenAddr=:8428'
      ],
      volumes: [{ name: 'data', path: '/victoria-metrics-data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}}/vmui para explorar series temporales y lanzar consultas MetricsQL/PromQL.',
      'Protege el dominio con Basic Auth si publicas el puerto en internet.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'gatus',
    name: 'Gatus',
    category: 'monitorizacion',
    summary: 'Página de estado declarativa para desarrolladores orientada a condiciones HTTP, DNS y TLS.',
    description:
      'Evalúa código HTTP, latencia, cuerpo de respuesta y caducidad de certificados con consumo ' +
      'mínimo de recursos y almacenamiento persistente en SQLite.',
    website: 'https://gatus.io',
    licence: 'Apache-2.0',
    tags: ['uptime', 'pagina de estado', 'sondas', 'alertas'],
    database: null,
    secrets: {},
    app: {
      image: 'twinproduction/gatus:v5.38.0',
      port: 8080,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        GATUS_CONFIG_PATH: '/config/config.yaml'
      },
      files: [
        {
          name: 'config.yaml',
          path: '/config/config.yaml',
          content:
            'storage:\n' +
            '  type: sqlite\n' +
            '  path: /data/data.db\n' +
            'endpoints:\n' +
            '  - name: Gatus\n' +
            '    url: http://127.0.0.1:8080/health\n' +
            '    interval: 60s\n' +
            '    conditions:\n' +
            '      - "[STATUS] == 200"\n'
        }
      ],
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para ver tu página de estado pública en marcha.',
      'Personaliza los endpoints y canales de alerta editando el fichero de configuración.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'glitchtip',
    name: 'GlitchTip',
    category: 'monitorizacion',
    summary: 'Seguimiento de errores y rendimiento compatible con los SDK oficiales de Sentry.',
    description:
      'Recibe excepciones, trazas y monitores de tus aplicaciones usando los mismos SDK de Sentry ' +
      'pero con una fracción del consumo de memoria. Incluye worker Celery y Valkey aislados.',
    website: 'https://glitchtip.com',
    licence: 'MIT',
    tags: ['errores', 'sentry', 'apm', 'observabilidad'],
    database: { engine: 'postgres', dbName: 'glitchtip', username: 'glitchtip', memoryMb: 512 },
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'worker',
        image: 'glitchtip/glitchtip:7.0.0',
        memoryMb: 512,
        cpus: 0.5,
        dependsOn: ['valkey'],
        startAfterApp: true,
        coupledWithApp: true,
        command: ['./bin/run-celery-with-beat.sh'],
        env: {
          DATABASE_URL: '{{db.url}}',
          REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379/0',
          SECRET_KEY: '{{secret.SECRET_KEY}}',
          GLITCHTIP_DOMAIN: '{{url}}',
          DEFAULT_FROM_EMAIL: 'noreply@{{host}}'
        },
        volumes: []
      }
    ],
    app: {
      image: 'glitchtip/glitchtip:7.0.0',
      port: 8000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379/0',
        SECRET_KEY: '{{secret.SECRET_KEY}}',
        GLITCHTIP_DOMAIN: '{{url}}',
        PORT: '8000',
        DEFAULT_FROM_EMAIL: 'noreply@{{host}}',
        ENABLE_USER_REGISTRATION: 'true',
        ENABLE_ORGANIZATION_CREATION: 'true'
      },
      volumes: [{ name: 'uploads', path: '/code/uploads' }],
      readiness: { path: '/_health/', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Registra tu primera cuenta en {{url}}, crea un proyecto y copia el DSN en tu SDK de Sentry.',
      'Tras crear tu cuenta, pon `ENABLE_USER_REGISTRATION=false` en variables si quieres cerrar registros públicos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'beszel',
    name: 'Beszel',
    category: 'monitorizacion',
    summary: 'Hub ligero de monitorización de servidores Linux con histórico, alertas y Docker stats.',
    description:
      'Panel minimalista sobre PocketBase que recibe métricas de agentes SSH/WebSocket remotos con ' +
      'uso mínimo de CPU y memoria.',
    website: 'https://beszel.dev',
    licence: 'MIT',
    tags: ['servidores', 'metricas', 'alertas', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'henrygd/beszel:0.21.2',
      port: 8090,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        APP_URL: '{{url}}'
      },
      volumes: [{ name: 'data', path: '/beszel_data' }],
      readiness: { path: '/api/health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y crea la cuenta administradora en el primer arranque.',
      'Añade tus servidores remotos instalando `beszel-agent` con la clave pública generada por el hub.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'jaeger',
    name: 'Jaeger',
    category: 'monitorizacion',
    summary: 'Trazado distribuido OpenTelemetry nativo con almacenamiento persistente Badger.',
    description:
      'Inspecciona latencias entre microservicios, consultas SQL y llamadas LLM recibiendo spans ' +
      'por OTLP gRPC (4317) y OTLP HTTP (4318).',
    website: 'https://www.jaegertracing.io',
    licence: 'Apache-2.0',
    tags: ['trazas', 'opentelemetry', 'otlp', 'observabilidad'],
    database: null,
    secrets: {},
    app: {
      image: 'jaegertracing/jaeger:2.23.0',
      port: 16686,
      extraPorts: [
        { containerPort: 4317, label: 'OTLP gRPC' },
        { containerPort: 4318, label: 'OTLP HTTP' }
      ],
      memoryMb: 1024,
      cpus: 1,
      env: {
        SPAN_STORAGE_TYPE: 'badger',
        BADGER_EPHEMERAL: 'false',
        BADGER_DIRECTORY_VALUE: '/badger/data',
        BADGER_DIRECTORY_KEY: '/badger/key'
      },
      volumes: [{ name: 'data', path: '/badger' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para explorar trazas y grafos de dependencias.',
      'Envía trazas OpenTelemetry desde tus servicios locales a los puertos 4317 (gRPC) o 4318 (HTTP).'
    ],
    notes: [
      'Jaeger no trae login propio: activa Basic Auth en el dominio de Culkibo antes de exponer la interfaz.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'healthchecks',
    name: 'Healthchecks',
    category: 'monitorizacion',
    summary: 'Monitorización de tareas cron y trabajos en segundo plano mediante avisos de silencio.',
    description:
      'Asigna una URL de ping a cada cron o copia de seguridad: si el trabajo no avisa a tiempo o ' +
      'falla, alerta al instante por correo, Telegram, Slack o webhook.',
    website: 'https://healthchecks.io',
    licence: 'BSD-3-Clause',
    tags: ['cron', 'alertas', 'deadman', 'monitorizacion'],
    database: { engine: 'postgres', dbName: 'healthchecks', username: 'healthchecks', memoryMb: 512 },
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'healthchecks/healthchecks:v5.0',
      port: 8000,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        DB: 'postgres',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_NAME: '{{db.name}}',
        DB_USER: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        SECRET_KEY: '{{secret.SECRET_KEY}}',
        SITE_ROOT: '{{url}}',
        ALLOWED_HOSTS: '*',
        DEBUG: 'False',
        REGISTRATION_OPEN: 'True'
      },
      volumes: [],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}}, crea tu cuenta y después fija `REGISTRATION_OPEN=False` si no quieres registros abiertos.',
      'Configura SMTP o webhooks en las integraciones del proyecto para recibir alertas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // D. Automatización (5 nuevas → 6 en total)
  // -------------------------------------------------------------------------
  {
    id: 'activepieces',
    name: 'Activepieces',
    category: 'automatizacion',
    summary: 'Automatización sin código extensible en TypeScript con cientos de integraciones y nodos IA.',
    description:
      'Alternativa MIT a Zapier con editor visual rápido, flujos programados, webhooks y agentes, ' +
      'respaldada por PostgreSQL y Valkey aislados.',
    website: 'https://www.activepieces.com',
    licence: 'MIT (edición comunitaria)',
    tags: ['automatizacion', 'flujos', 'webhooks', 'zapier', 'ia'],
    database: { engine: 'postgres', dbName: 'activepieces', username: 'activepieces', memoryMb: 512 },
    secrets: {
      // Activepieces exige exactamente 32 caracteres hexadecimales (16 bytes).
      AP_ENCRYPTION_KEY: { bytes: 16, encoding: 'hex' },
      AP_JWT_SECRET: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'activepieces/activepieces:0.93.0',
      port: 80,
      memoryMb: 1536,
      cpus: 1,
      env: {
        AP_ENGINE_EXECUTABLE_PATH: 'dist/packages/engine/main.js',
        AP_ENVIRONMENT: 'prod',
        AP_FRONTEND_URL: '{{url}}',
        AP_POSTGRES_HOST: '{{db.host}}',
        AP_POSTGRES_PORT: '{{db.port}}',
        AP_POSTGRES_DATABASE: '{{db.name}}',
        AP_POSTGRES_USERNAME: '{{db.user}}',
        AP_POSTGRES_PASSWORD: '{{db.password}}',
        AP_REDIS_HOST: '{{sidecar.valkey.host}}',
        AP_REDIS_PORT: '6379',
        AP_ENCRYPTION_KEY: '{{secret.AP_ENCRYPTION_KEY}}',
        AP_JWT_SECRET: '{{secret.AP_JWT_SECRET}}',
        AP_EXECUTION_MODE: 'UNSANDBOXED',
        AP_TELEMETRY_ENABLED: 'false'
      },
      volumes: [{ name: 'cache', path: '/usr/src/app/cache' }],
      readiness: { path: '/api/v1/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea la primera cuenta de administración.',
      'Conserva AP_ENCRYPTION_KEY: cifra todas las conexiones OAuth y API keys guardadas.'
    ],
    notes: [
      'Ejecuta en modo UNSANDBOXED dentro del contenedor sin privilegios para no requerir privilegios del kernel del host.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'windmill',
    name: 'Windmill',
    category: 'automatizacion',
    summary: 'Plataforma para ejecutar scripts en Python, TypeScript, Go y SQL como flujos y apps internas.',
    description:
      'Convierte cualquier script en un endpoint, tarea programada, flujo DAG o interfaz interna con ' +
      'worker dedicado y cola transaccional en PostgreSQL.',
    website: 'https://www.windmill.dev',
    licence: 'AGPLv3',
    tags: ['scripts', 'flujos', 'python', 'typescript', 'apps internas'],
    database: { engine: 'postgres', dbName: 'windmill', username: 'windmill', memoryMb: 512 },
    secrets: {},
    sidecars: [
      {
        name: 'worker',
        image: 'ghcr.io/windmill-labs/windmill:1.881.0',
        memoryMb: 1024,
        cpus: 1,
        startAfterApp: true,
        coupledWithApp: true,
        env: {
          DATABASE_URL: '{{db.url}}',
          MODE: 'worker',
          WORKER_GROUP: 'default'
        },
        volumes: []
      }
    ],
    app: {
      image: 'ghcr.io/windmill-labs/windmill:1.881.0',
      port: 8000,
      memoryMb: 1536,
      cpus: 2,
      env: {
        DATABASE_URL: '{{db.url}}',
        MODE: 'server',
        BASE_URL: '{{url}}'
      },
      volumes: [],
      readiness: { path: '/api/version', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} e inicia sesión con el usuario inicial documentado por Windmill (`admin@windmill.dev` / `changeme`) y cambia la contraseña de inmediato.',
      'Revisa la cola de workers en la pestaña Workers para comprobar que el auxiliar está activo.'
    ],
    notes: [
      'La contraseña inicial la crea Windmill al migrar: cámbiala nada más entrar.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'node-red',
    name: 'Node-RED',
    category: 'automatizacion',
    summary: 'Programación visual basada en eventos para IoT, APIs, MQTT y automatizaciones.',
    description:
      'Editor de flujos en el navegador sobre Node.js con miles de nodos comunitarios y cifrado de ' +
      'credenciales activado mediante secreto aleatorio.',
    website: 'https://nodered.org',
    licence: 'Apache-2.0',
    tags: ['iot', 'flujos', 'eventos', 'mqtt', 'automatizacion'],
    database: null,
    secrets: {
      NODE_RED_CREDENTIAL_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'nodered/node-red:5.0.10',
      port: 1880,
      memoryMb: 512,
      cpus: 1,
      env: {
        TZ: '{{tz}}',
        NODE_RED_CREDENTIAL_SECRET: '{{secret.NODE_RED_CREDENTIAL_SECRET}}',
        NODE_RED_ENABLE_PROJECTS: 'true'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/', expect: [200, 401] }
    },
    nextSteps: [
      'Activa Basic Auth en el dominio de Culkibo o configura `adminAuth` en `/data/settings.js` antes de publicar Node-RED en internet.',
      'Guarda NODE_RED_CREDENTIAL_SECRET: se usa para cifrar las credenciales de tus flujos.'
    ],
    notes: [
      'Por defecto Node-RED no pide contraseña en el editor: protégelo siempre con autenticación en el borde o en `settings.js`.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'changedetection',
    name: 'changedetection.io',
    category: 'automatizacion',
    summary: 'Detecta cambios en páginas web, precios, repositorios o avisos y envía alertas al instante.',
    description:
      'Vigila URLs periódicamente, resalta diferencias línea a línea y dispara avisos por Telegram, ' +
      'Discord, correo o webhook con filtros CSS y JSONPath.',
    website: 'https://changedetection.io',
    licence: 'Apache-2.0',
    tags: ['web', 'alertas', 'cambios', 'monitorizacion', 'scraping'],
    database: null,
    secrets: {},
    app: {
      image: 'ghcr.io/dgtlmoon/changedetection.io:0.70.4',
      port: 5000,
      memoryMb: 512,
      cpus: 1,
      env: {
        PORT: '5000',
        BASE_URL: '{{url}}',
        USE_X_SETTINGS: '1',
        HIDE_REFERER: 'true'
      },
      volumes: [{ name: 'datastore', path: '/datastore' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}} y establece una contraseña de acceso en Settings → Password cuanto antes.',
      'Añade tus primeras URLs y un canal de notificación compatible con Apprise.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'kestra',
    name: 'Kestra',
    category: 'automatizacion',
    summary: 'Orquestador declarativo en YAML para pipelines de datos, ETL y automatizaciones complejas.',
    description:
      'Define flujos de trabajo con reintentos, ramificaciones, disparadores y cientos de plugins ' +
      'usando PostgreSQL como cola y repositorio persistente.',
    website: 'https://kestra.io',
    licence: 'Apache-2.0',
    tags: ['orquestador', 'etl', 'yaml', 'pipelines', 'datos'],
    database: { engine: 'postgres', dbName: 'kestra', username: 'kestra', memoryMb: 512 },
    secrets: {
      KESTRA_BASIC_AUTH_PASS: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'kestra/kestra:v2.0.11-slim',
      port: 8080,
      memoryMb: 2048,
      cpus: 2,
      env: {
        DATASOURCES_POSTGRES_URL: 'jdbc:postgresql://{{db.host}}:{{db.port}}/{{db.name}}',
        DATASOURCES_POSTGRES_DRIVER_CLASS_NAME: 'org.postgresql.Driver',
        DATASOURCES_POSTGRES_USERNAME: '{{db.user}}',
        DATASOURCES_POSTGRES_PASSWORD: '{{db.password}}',
        KESTRA_REPOSITORY_TYPE: 'postgres',
        KESTRA_QUEUE_TYPE: 'postgres',
        KESTRA_STORAGE_TYPE: 'local',
        KESTRA_STORAGE_LOCAL_BASE_PATH: '/app/storage',
        KESTRA_SERVER_BASIC_AUTH_ENABLED: 'true',
        KESTRA_SERVER_BASIC_AUTH_USERNAME: 'admin@culkibo.local',
        KESTRA_SERVER_BASIC_AUTH_PASSWORD: '{{secret.KESTRA_BASIC_AUTH_PASS}}',
        KESTRA_URL: '{{url}}/'
      },
      command: ['server', 'standalone'],
      volumes: [{ name: 'storage', path: '/app/storage' }],
      readiness: { path: '/', expect: [200, 302, 401], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}} e inicia sesión con `admin@culkibo.local` y KESTRA_BASIC_AUTH_PASS de «Credenciales».',
      'Crea tu primer flujo YAML en el editor visual y pruébalo con ejecuciones manuales.'
    ],
    notes: [
      'Kestra corre sobre la JVM y necesita al menos 2 GB de RAM; el primer arranque tarda ~1 minuto.'
    ]
  },

  // -------------------------------------------------------------------------
  // E. Datos y BaaS (9 nuevas → 13 en total)
  // -------------------------------------------------------------------------
  {
    id: 'pgadmin',
    name: 'pgAdmin 4',
    category: 'datos',
    summary: 'Consola web oficial para administrar bases de datos PostgreSQL, consultas y copias.',
    description:
      'Explora esquemas, lanza consultas SQL con planes EXPLAIN, gestiona roles y monitoriza ' +
      'conexiones de PostgreSQL desde el navegador detrás de HTTPS.',
    website: 'https://www.pgadmin.org',
    licence: 'PostgreSQL License',
    tags: ['postgresql', 'sql', 'administracion', 'datos'],
    database: null,
    secrets: {
      PGADMIN_DEFAULT_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'dpage/pgadmin4:9.19',
      port: 80,
      memoryMb: 512,
      cpus: 1,
      env: {
        PGADMIN_DEFAULT_EMAIL: 'admin@culkibo.local',
        PGADMIN_DEFAULT_PASSWORD: '{{secret.PGADMIN_DEFAULT_PASSWORD}}',
        PGADMIN_CONFIG_ENHANCED_COOKIE_PROTECTION: 'True',
        PGADMIN_CONFIG_PROXY_X_FOR_COUNT: '1',
        PGADMIN_CONFIG_PROXY_X_PROTO_COUNT: '1',
        PGADMIN_CONFIG_PROXY_X_HOST_COUNT: '1'
      },
      volumes: [{ name: 'data', path: '/var/lib/pgadmin' }],
      readiness: { path: '/misc/ping', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con `admin@culkibo.local` y PGADMIN_DEFAULT_PASSWORD de «Credenciales».',
      'Registra tus servidores PostgreSQL desde Object → Register → Server.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'cloudbeaver',
    name: 'CloudBeaver',
    category: 'datos',
    summary: 'Cliente SQL web multi-motor del equipo de DBeaver para PostgreSQL, MySQL, MariaDB y más.',
    description:
      'Interfaz web ligera para consultar, editar tablas y exportar datos en múltiples motores SQL ' +
      'desde un único panel protegido por cuentas.',
    website: 'https://dbeaver.com/cloudbeaver',
    licence: 'Apache-2.0',
    tags: ['sql', 'dbeaver', 'postgresql', 'mysql', 'cliente'],
    database: null,
    secrets: {},
    app: {
      image: 'dbeaver/cloudbeaver:26.0.0',
      port: 8978,
      memoryMb: 1024,
      cpus: 1,
      env: {
        CB_SERVER_NAME: 'Culkibo CloudBeaver',
        CB_SERVER_URL: '{{url}}'
      },
      volumes: [{ name: 'workspace', path: '/opt/cloudbeaver/workspace' }],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} de inmediato y completa el asistente inicial para crear la cuenta de administración.',
      'Desactiva el acceso anónimo en el asistente si el servicio está publicado en un dominio público.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'hasura',
    name: 'Hasura GraphQL Engine',
    category: 'datos',
    summary: 'API GraphQL y REST instantánea con suscripciones en tiempo real sobre PostgreSQL.',
    description:
      'Genera consultas, mutaciones, permisos por fila y disparadores de eventos directamente desde ' +
      'tu esquema PostgreSQL, protegido con secreto de administración.',
    website: 'https://hasura.io',
    licence: 'Apache-2.0',
    tags: ['graphql', 'api', 'postgresql', 'realtime', 'baas'],
    database: { engine: 'postgres', dbName: 'hasura', username: 'hasura', memoryMb: 512 },
    secrets: {
      HASURA_GRAPHQL_ADMIN_SECRET: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'hasura/graphql-engine:v2.45.13',
      port: 8080,
      memoryMb: 768,
      cpus: 1,
      env: {
        HASURA_GRAPHQL_METADATA_DATABASE_URL: '{{db.url}}',
        HASURA_GRAPHQL_DATABASE_URL: '{{db.url}}',
        HASURA_GRAPHQL_ENABLE_CONSOLE: 'true',
        HASURA_GRAPHQL_DEV_MODE: 'false',
        HASURA_GRAPHQL_ENABLED_LOG_TYPES: 'startup, http-log, webhook-log, websocket-log, query-log',
        HASURA_GRAPHQL_ADMIN_SECRET: '{{secret.HASURA_GRAPHQL_ADMIN_SECRET}}',
        HASURA_GRAPHQL_ENABLE_TELEMETRY: 'false'
      },
      volumes: [],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}}/console e introduce HASURA_GRAPHQL_ADMIN_SECRET desde «Credenciales».',
      'En producción, considera poner `HASURA_GRAPHQL_ENABLE_CONSOLE=false` tras configurar tus metadatos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'typesense',
    name: 'Typesense',
    category: 'datos',
    summary: 'Motor de búsqueda instantánea en C++ con tolerancia a erratas, facetas y búsqueda vectorial.',
    description:
      'Alternativa rápida en memoria a Algolia y Elasticsearch que combina búsqueda full-text, ' +
      'sinónimos, geolocalización y embeddings con clave API obligatoria.',
    website: 'https://typesense.org',
    licence: 'GPLv3',
    tags: ['busqueda', 'algolia', 'vectores', 'fulltext'],
    database: null,
    secrets: {
      TYPESENSE_API_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'typesense/typesense:30.1',
      port: 8108,
      memoryMb: 1024,
      cpus: 1,
      env: {
        TYPESENSE_DATA_DIR: '/data',
        TYPESENSE_API_KEY: '{{secret.TYPESENSE_API_KEY}}',
        TYPESENSE_ENABLE_CORS: 'true'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Copia TYPESENSE_API_KEY en «Credenciales» y pásala en la cabecera `X-TYPESENSE-API-KEY`.',
      'Crea claves con permisos limitados de búsqueda antes de usarlas en navegadores.'
    ],
    notes: [
      'Typesense mantiene los índices en RAM: amplía la memoria si indexas millones de documentos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'influxdb',
    name: 'InfluxDB 2',
    category: 'datos',
    summary: 'Base de datos de series temporales para telemetría IoT, sensores y métricas en tiempo real.',
    description:
      'Almacena millones de puntos por segundo con lenguaje Flux, tareas programadas y paneles ' +
      'integrados, inicializada de forma segura con usuario y token de administración aleatorios.',
    website: 'https://www.influxdata.com',
    licence: 'MIT',
    tags: ['tsdb', 'iot', 'metricas', 'sensores', 'series temporales'],
    database: null,
    secrets: {
      DOCKER_INFLUXDB_INIT_PASSWORD: { bytes: 18, encoding: 'base64url' },
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'influxdb:2.7.11',
      port: 8086,
      memoryMb: 1024,
      cpus: 1,
      env: {
        DOCKER_INFLUXDB_INIT_MODE: 'setup',
        DOCKER_INFLUXDB_INIT_USERNAME: 'admin',
        DOCKER_INFLUXDB_INIT_PASSWORD: '{{secret.DOCKER_INFLUXDB_INIT_PASSWORD}}',
        DOCKER_INFLUXDB_INIT_ORG: 'culkibo',
        DOCKER_INFLUXDB_INIT_BUCKET: 'metrics',
        DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: '{{secret.DOCKER_INFLUXDB_INIT_ADMIN_TOKEN}}'
      },
      volumes: [
        { name: 'data', path: '/var/lib/influxdb2' },
        { name: 'config', path: '/etc/influxdb2' }
      ],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Entra en {{url}} como «admin» con DOCKER_INFLUXDB_INIT_PASSWORD desde «Credenciales».',
      'Usa DOCKER_INFLUXDB_INIT_ADMIN_TOKEN para autenticar clientes Telegraf o llamadas API.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'couchdb',
    name: 'Apache CouchDB',
    category: 'datos',
    summary: 'Base de datos documental JSON con API HTTP y replicación offline-first (PouchDB, Obsidian).',
    description:
      'Sincroniza documentos bidireccionalmente entre dispositivos, apps móviles y servidores mediante ' +
      'HTTP nativo, ideal para Obsidian LiveSync y apps local-first.',
    website: 'https://couchdb.apache.org',
    licence: 'Apache-2.0',
    tags: ['nosql', 'documentos', 'pouchdb', 'obsidian', 'offline'],
    database: null,
    secrets: {
      COUCHDB_PASSWORD: { bytes: 24, encoding: 'base64url' },
      COUCHDB_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'couchdb:3.5.3',
      port: 5984,
      memoryMb: 768,
      cpus: 1,
      env: {
        COUCHDB_USER: 'admin',
        COUCHDB_PASSWORD: '{{secret.COUCHDB_PASSWORD}}',
        COUCHDB_SECRET: '{{secret.COUCHDB_SECRET}}'
      },
      volumes: [
        { name: 'data', path: '/opt/couchdb/data' },
        { name: 'config', path: '/opt/couchdb/etc/local.d' }
      ],
      readiness: { path: '/_up', expect: [200] }
    },
    nextSteps: [
      'Abre la consola Fauxton en {{url}}/_utils con usuario «admin» y COUCHDB_PASSWORD de «Credenciales».',
      'Crea las bases `_users` y `_replicator` desde el panel si vas a sincronizar clientes PouchDB.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'bytebase',
    name: 'Bytebase',
    category: 'datos',
    summary: 'Control de cambios SQL, revisiones de migraciones y auditoría de esquemas para equipos.',
    description:
      'Aplica flujo tipo GitLab a tus bases de datos: revisión de DDL, comprobación automática de ' +
      'reglas SQL, ejecución escalonada e historial de cambios.',
    website: 'https://www.bytebase.com',
    licence: 'Apache-2.0 (edición comunitaria)',
    tags: ['sql', 'migraciones', 'devops', 'esquemas', 'auditoria'],
    database: null,
    secrets: {},
    app: {
      image: 'bytebase/bytebase:3.25.0',
      port: 8080,
      memoryMb: 1024,
      cpus: 1,
      env: {
        EXTERNAL_URL: '{{url}}'
      },
      command: ['--data', '/var/opt/bytebase', '--port', '8080'],
      volumes: [{ name: 'data', path: '/var/opt/bytebase' }],
      readiness: { path: '/healthz', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea la primera cuenta de propietario del espacio de trabajo.',
      'Conecta tus instancias de PostgreSQL, MySQL o MariaDB para revisar cambios de esquema.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'postgrest',
    name: 'PostgREST',
    category: 'datos',
    summary: 'Convierte directamente cualquier base de datos PostgreSQL en una API REST rápida con JWT.',
    description:
      'Servidor ligero en Haskell que expone tablas, vistas y funciones SQL como endpoints REST con ' +
      'especificación OpenAPI automática y seguridad basada en roles de PostgreSQL.',
    website: 'https://postgrest.org',
    licence: 'MIT',
    tags: ['postgresql', 'rest', 'api', 'jwt', 'openapi'],
    database: { engine: 'postgres', dbName: 'app', username: 'postgrest', memoryMb: 512 },
    secrets: {
      PGRST_JWT_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'postgrest/postgrest:v16.2',
      port: 3000,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        PGRST_DB_URI: '{{db.url}}',
        PGRST_DB_SCHEMAS: 'public',
        PGRST_DB_ANON_ROLE: '{{db.user}}',
        PGRST_JWT_SECRET: '{{secret.PGRST_JWT_SECRET}}',
        PGRST_OPENAPI_SERVER_PROXY_URI: '{{url}}'
      },
      volumes: [],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Consulta {{url}} para obtener el esquema OpenAPI generado desde PostgreSQL.',
      'Crea roles SQL dedicados con permisos mínimos y firma tus JWT con PGRST_JWT_SECRET.'
    ],
    notes: [
      'Inicialmente usa el rol de base de datos como anónimo para arrancar: crea un rol restringido antes de exponer tablas sensibles.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'surrealdb',
    name: 'SurrealDB',
    category: 'datos',
    summary: 'Base de datos multimodelo en Rust: relacional, documentos, grafos y vectores en un solo motor.',
    description:
      'Ofrece consultas SurrealQL, suscripciones en vivo por WebSocket y almacenamiento RocksDB ' +
      'persistente en disco con credenciales root aleatorias.',
    website: 'https://surrealdb.com',
    licence: 'BSL 1.1 (código a la vista; cambia a Apache-2.0 tras 4 años)',
    tags: ['rust', 'grafos', 'vectores', 'realtime', 'nosql'],
    database: null,
    secrets: {
      SURREAL_PASS: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'surrealdb/surrealdb:v4.0.1',
      port: 8000,
      memoryMb: 768,
      cpus: 1,
      env: {
        SURREAL_USER: 'root',
        SURREAL_PASS: '{{secret.SURREAL_PASS}}',
        SURREAL_BIND: '0.0.0.0:8000'
      },
      command: ['start', '--log', 'info', 'rocksdb:/data/surreal.db'],
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Conecta con Surrealist o el CLI de SurrealDB a {{url}} usando usuario «root» y SURREAL_PASS.',
      'Define usuarios a nivel de namespace y base de datos para tus aplicaciones.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // F. Desarrollo y DevTools (9 nuevas → 11 en total)
  // -------------------------------------------------------------------------
  {
    id: 'forgejo',
    name: 'Forgejo',
    category: 'desarrollo',
    summary: 'Forja Git comunitaria y ligera (bifurcación libre de Gitea) con PostgreSQL y CI Actions.',
    description:
      'Hospeda repositorios Git, revisiones de código, registro de paquetes y automatizaciones CI/CD ' +
      'bajo gobernanza comunitaria sin telemetría ni bloqueos comerciales.',
    website: 'https://forgejo.org',
    licence: 'GPLv3+',
    tags: ['git', 'repositorios', 'ci', 'forja', 'codigo'],
    database: { engine: 'postgres', dbName: 'forgejo', username: 'forgejo', memoryMb: 512 },
    secrets: {
      FORGEJO_SECRET_KEY: { bytes: 32, encoding: 'base64url' },
      FORGEJO_INTERNAL_TOKEN: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'codeberg.org/forgejo/forgejo:17.0.2',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        USER_UID: '1000',
        USER_GID: '1000',
        FORGEJO__database__DB_TYPE: 'postgres',
        FORGEJO__database__HOST: '{{db.host}}:{{db.port}}',
        FORGEJO__database__NAME: '{{db.name}}',
        FORGEJO__database__USER: '{{db.user}}',
        FORGEJO__database__PASSWD: '{{db.password}}',
        FORGEJO__server__DOMAIN: '{{domain}}',
        FORGEJO__server__ROOT_URL: '{{url}}/',
        FORGEJO__server__DISABLE_SSH: 'true',
        FORGEJO__security__INSTALL_LOCK: 'true',
        FORGEJO__security__SECRET_KEY: '{{secret.FORGEJO_SECRET_KEY}}',
        FORGEJO__security__INTERNAL_TOKEN: '{{secret.FORGEJO_INTERNAL_TOKEN}}',
        FORGEJO__service__DISABLE_REGISTRATION: 'false'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/api/v1/version', expect: [200, 302] }
    },
    nextSteps: [
      'Registra la primera cuenta en {{url}}: se convertirá automáticamente en administradora.',
      'Después cierra el registro abierto fijando `FORGEJO__service__DISABLE_REGISTRATION=true`.'
    ],
    notes: [
      'El servidor SSH interno viene desactivado para no colisionar con el puerto 22 del host; se clona por HTTPS.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'code-server',
    name: 'code-server (VS Code)',
    category: 'desarrollo',
    summary: 'Visual Studio Code completo en tu navegador para programar desde cualquier dispositivo.',
    description:
      'Entorno remoto de VS Code con terminal integrada, extensiones Open VSX y espacio de trabajo ' +
      'persistente protegido con contraseña aleatoria.',
    website: 'https://coder.com',
    licence: 'MIT',
    tags: ['ide', 'vscode', 'editor', 'remoto'],
    database: null,
    secrets: {
      PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'codercom/code-server:4.146.0',
      port: 8080,
      memoryMb: 2048,
      cpus: 2,
      env: {
        PASSWORD: '{{secret.PASSWORD}}',
        DEFAULT_WORKSPACE: '/home/coder/project'
      },
      volumes: [
        { name: 'config', path: '/home/coder/.config' },
        { name: 'workspace', path: '/home/coder/project' }
      ],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} e introduce la contraseña PASSWORD desde «Credenciales».',
      'Tus proyectos y extensiones se guardan en los volúmenes persistentes `/home/coder/project` y `.config`.'
    ],
    notes: [
      'Sirve siempre code-server detrás de HTTPS para habilitar portapapeles, WebSockets y extensiones modernas.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'verdaccio',
    name: 'Verdaccio',
    category: 'desarrollo',
    summary: 'Registro privado y caché proxy de paquetes npm con cero configuración compleja.',
    description:
      'Publica librerías JavaScript/TypeScript internas y acelera los `npm install` de tus ' +
      'despliegues cacheando paquetes de npmjs en tu propio servidor.',
    website: 'https://verdaccio.org',
    licence: 'MIT',
    tags: ['npm', 'paquetes', 'registro', 'nodejs', 'cache'],
    database: null,
    secrets: {},
    app: {
      image: 'verdaccio/verdaccio:7.1.0',
      port: 4873,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        VERDACCIO_PORT: '4873',
        VERDACCIO_PUBLIC_URL: '{{url}}'
      },
      volumes: [
        { name: 'storage', path: '/verdaccio/storage' },
        { name: 'conf', path: '/verdaccio/conf' }
      ],
      readiness: { path: '/-/ping', expect: [200] }
    },
    nextSteps: [
      'Crea tu primer usuario con `npm adduser --registry {{url}}`.',
      'Desactiva el alta libre en `/verdaccio/conf/config.yaml` (`max_users: -1`) cuando hayas creado tus cuentas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'docker-registry',
    name: 'Docker Registry',
    category: 'desarrollo',
    summary: 'Registro privado de imágenes OCI/Docker v2 para almacenar y desplegar tus propios builds.',
    description:
      'Implementación oficial de CNCF Distribution para alojar imágenes de contenedores privadas con ' +
      'borrado de manifiestos habilitado y secreto HTTP aleatorio.',
    website: 'https://distribution.github.io/distribution',
    licence: 'Apache-2.0',
    tags: ['docker', 'oci', 'imagenes', 'registro', 'contenedores'],
    database: null,
    secrets: {
      REGISTRY_HTTP_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'registry:2.8.3',
      port: 5000,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY: '/var/lib/registry',
        REGISTRY_STORAGE_DELETE_ENABLED: 'true',
        REGISTRY_HTTP_SECRET: '{{secret.REGISTRY_HTTP_SECRET}}',
        REGISTRY_HTTP_ADDR: '0.0.0.0:5000'
      },
      volumes: [{ name: 'data', path: '/var/lib/registry' }],
      readiness: { path: '/v2/', expect: [200, 401] }
    },
    nextSteps: [
      'Activa Basic Auth en el dominio de Culkibo antes de hacer `docker login` y `docker push`.',
      'Ejecuta periódicamente `registry garbage-collect` dentro del contenedor para liberar espacio de etiquetas borradas.'
    ],
    notes: [
      'El registro no trae autenticación propia activada por defecto: protégelo siempre con Basic Auth HTTPS en Culkibo.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'onedev',
    name: 'OneDev',
    category: 'desarrollo',
    summary: 'Servidor Git todo-en-uno con CI/CD, tableros kanban, búsqueda de símbolos y paquetes.',
    description:
      'Alternativa ligera a GitLab escrita en Java que unifica repositorios, incidencias, revisiones ' +
      'y pipelines sobre PostgreSQL con contraseña inicial generada.',
    website: 'https://onedev.io',
    licence: 'MIT',
    tags: ['git', 'ci', 'kanban', 'gitlab', 'devops'],
    database: { engine: 'postgres', dbName: 'onedev', username: 'onedev', memoryMb: 512 },
    secrets: {
      ONEDEV_INITIAL_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: '1dev/server:17.2',
      port: 6610,
      memoryMb: 2048,
      cpus: 2,
      env: {
        hibernate_dialect: 'io.onedev.server.persistence.PostgreSQLDialect',
        hibernate_connection_driver_class: 'org.postgresql.Driver',
        hibernate_connection_url: 'jdbc:postgresql://{{db.host}}:{{db.port}}/{{db.name}}',
        hibernate_connection_username: '{{db.user}}',
        hibernate_connection_password: '{{db.password}}',
        initial_user: 'admin',
        initial_password: '{{secret.ONEDEV_INITIAL_PASSWORD}}',
        initial_email: 'admin@culkibo.local',
        initial_server_url: '{{url}}'
      },
      volumes: [{ name: 'data', path: '/opt/onedev' }],
      readiness: { path: '/~health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con ONEDEV_INITIAL_PASSWORD desde «Credenciales».',
      'Actualiza el correo del administrador y configura tu primer proyecto Git.'
    ],
    notes: [
      'Requiere al menos 2 GB de RAM para la JVM y tarda entre 1 y 2 minutos en completar la primera inicialización.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'sonarqube',
    name: 'SonarQube Community',
    category: 'desarrollo',
    summary: 'Análisis estático continuo de calidad de código, deuda técnica y vulnerabilidades.',
    description:
      'Inspecciona más de 30 lenguajes buscando bugs, puntos calientes de seguridad y cobertura de ' +
      'pruebas, respaldado por PostgreSQL aislado.',
    website: 'https://www.sonarsource.com/products/sonarqube',
    licence: 'LGPLv3 (edición comunitaria)',
    tags: ['calidad', 'sast', 'seguridad', 'codigo', 'ci'],
    database: { engine: 'postgres', dbName: 'sonarqube', username: 'sonarqube', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'sonarqube:2026.5-lta-community',
      port: 9000,
      memoryMb: 3072,
      cpus: 2,
      env: {
        SONAR_JDBC_URL: 'jdbc:postgresql://{{db.host}}:{{db.port}}/{{db.name}}',
        SONAR_JDBC_USERNAME: '{{db.user}}',
        SONAR_JDBC_PASSWORD: '{{db.password}}',
        SONAR_WEB_JAVAOPTS: '-Xmx1024m -Xms256m',
        SONAR_CE_JAVAOPTS: '-Xmx1024m -Xms256m',
        SONAR_SEARCH_JAVAOPTS: '-Xmx512m -Xms512m'
      },
      volumes: [
        { name: 'data', path: '/opt/sonarqube/data' },
        { name: 'extensions', path: '/opt/sonarqube/extensions' },
        { name: 'logs', path: '/opt/sonarqube/logs' }
      ],
      readiness: { path: '/api/system/status', expect: [200], timeoutMs: 300000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con el usuario inicial de SonarQube (`admin` / `admin`) y cambia la contraseña inmediatamente.',
      'Genera un token en My Account → Security para lanzar `sonar-scanner` desde tu CI.'
    ],
    notes: [
      'Elasticsearch interno exige que el host Linux tenga `sysctl -w vm.max_map_count=262144` (y en `/etc/sysctl.conf` para persistir).',
      'Necesita al menos 3 GB de RAM dedicada y tarda hasta 3-5 minutos en su primer arranque.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'hoppscotch',
    name: 'Hoppscotch',
    category: 'desarrollo',
    summary: 'Cliente API colaborativo en el navegador para REST, GraphQL, WebSocket y SSE.',
    description:
      'Alternativa libre y rápida a Postman con colecciones compartidas por equipo, entornos ' +
      'sincronizados y panel de administración sobre PostgreSQL.',
    website: 'https://hoppscotch.io',
    licence: 'MIT',
    tags: ['api', 'postman', 'rest', 'graphql', 'websocket'],
    database: { engine: 'postgres', dbName: 'hoppscotch', username: 'hoppscotch', memoryMb: 512 },
    secrets: {
      JWT_SECRET: { bytes: 32, encoding: 'hex' },
      SESSION_SECRET: { bytes: 32, encoding: 'hex' },
      // Hoppscotch exige exactamente 32 caracteres (16 bytes en hex).
      DATA_ENCRYPTION_KEY: { bytes: 16, encoding: 'hex' }
    },
    app: {
      image: 'hoppscotch/hoppscotch:2026.10.0',
      port: 80,
      memoryMb: 1536,
      cpus: 1,
      env: {
        ENABLE_SUBPATH_BASED_ACCESS: 'true',
        DATABASE_URL: '{{db.url}}',
        JWT_SECRET: '{{secret.JWT_SECRET}}',
        SESSION_SECRET: '{{secret.SESSION_SECRET}}',
        DATA_ENCRYPTION_KEY: '{{secret.DATA_ENCRYPTION_KEY}}',
        REDIRECT_URL: '{{url}}',
        WHITELISTED_ORIGINS: '{{url}}',
        VITE_BASE_URL: '{{url}}',
        VITE_SHORTCODE_BASE_URL: '{{url}}',
        VITE_ADMIN_URL: '{{url}}/admin',
        VITE_BACKEND_GQL_URL: '{{url}}/backend/graphql',
        VITE_BACKEND_WS_URL: '{{wsProtocol}}://{{domain}}/backend/graphql',
        VITE_BACKEND_API_URL: '{{url}}/backend/v1',
        ALLOW_SECURE_COOKIES: '{{isHttps}}'
      },
      volumes: [],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/admin para completar la configuración inicial y crear la cuenta administradora.',
      'Configura un proveedor OAuth (GitHub/Google) o SMTP en variables de entorno para invitar al equipo.'
    ],
    notes: [
      'Configurado en modo subpath (`ENABLE_SUBPATH_BASED_ACCESS=true`) para funcionar bajo un único dominio HTTPS.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'unleash',
    name: 'Unleash',
    category: 'desarrollo',
    summary: 'Gestión de feature flags, despliegues graduales y pruebas A/B para tus aplicaciones.',
    description:
      'Activa o desactiva funcionalidades en producción sin redesplegar, segmenta por porcentaje o ' +
      'usuarios y conecta SDKs oficiales en Node, Python, Go, Java y frontend.',
    website: 'https://www.getunleash.io',
    licence: 'Apache-2.0',
    tags: ['feature-flags', 'ab-testing', 'despliegues', 'devops'],
    database: { engine: 'postgres', dbName: 'unleash', username: 'unleash', memoryMb: 512 },
    secrets: {
      INIT_ADMIN_API_TOKENS: { bytes: 24, encoding: 'hex' }
    },
    app: {
      image: 'unleashorg/unleash-server:8.3.1',
      port: 4242,
      memoryMb: 512,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        DATABASE_SSL: 'false',
        UNLEASH_URL: '{{url}}',
        INIT_ADMIN_API_TOKENS: '*:*.{{secret.INIT_ADMIN_API_TOKENS}}',
        CHECK_VERSION: 'false'
      },
      volumes: [],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con las credenciales por defecto de Unleash (`admin` / `unleash4all`) y cámbialas de inmediato.',
      'Crea un token de cliente para tus SDKs o usa el token de administración generado en «Credenciales».'
    ],
    notes: [
      'La contraseña inicial la crea Unleash al inicializar la BD: cámbiala nada más entrar.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'woodpecker',
    name: 'Woodpecker CI',
    category: 'desarrollo',
    summary: 'Motor CI/CD ligero basado en contenedores con integración para GitHub, GitLab, Gitea y Forgejo.',
    description:
      'Ejecuta pipelines declarativos en `.woodpecker.yml` con consumo mínimo de memoria y secreto ' +
      'compartido generado para conectar agentes remotos por gRPC.',
    website: 'https://woodpecker-ci.org',
    licence: 'Apache-2.0',
    tags: ['ci', 'cd', 'pipelines', 'git', 'devops'],
    database: { engine: 'postgres', dbName: 'woodpecker', username: 'woodpecker', memoryMb: 512 },
    secrets: {
      WOODPECKER_AGENT_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'woodpeckerci/woodpecker-server:v3.20.1-alpine',
      port: 8000,
      extraPorts: [{ containerPort: 9000, label: 'gRPC Agentes' }],
      memoryMb: 512,
      cpus: 1,
      env: {
        WOODPECKER_HOST: '{{url}}',
        WOODPECKER_OPEN: 'false',
        WOODPECKER_AGENT_SECRET: '{{secret.WOODPECKER_AGENT_SECRET}}',
        WOODPECKER_DATABASE_DRIVER: 'postgres',
        WOODPECKER_DATABASE_DATASOURCE: '{{db.url}}'
      },
      volumes: [{ name: 'data', path: '/var/lib/woodpecker' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Configura tu forja OAuth (p. ej. `WOODPECKER_GITHUB=true`, `WOODPECKER_GITEA=true` o `WOODPECKER_FORGEJO=true`) en las variables de entorno.',
      'Conecta uno o varios `woodpecker-agent` usando WOODPECKER_AGENT_SECRET desde «Credenciales».'
    ],
    notes: [
      'Esta plantilla despliega sólo el servidor sin exponer el socket de Docker del host; los agentes de ejecución se conectan de forma aislada.'
    ]
  },

  // -------------------------------------------------------------------------
  // G. Seguridad e identidad (5 nuevas → 6 en total)
  // -------------------------------------------------------------------------
  {
    id: 'authentik',
    name: 'Authentik',
    category: 'seguridad',
    summary: 'Proveedor de identidad SSO (OIDC, SAML, LDAP, Proxy Auth) con flujos flexibles y passkeys.',
    description:
      'Centraliza el inicio de sesión único y el doble factor (WebAuthn/TOTP) de todas tus apps ' +
      'internas, con servidor web, worker en segundo plano, PostgreSQL y Valkey aislados.',
    website: 'https://goauthentik.io',
    licence: 'MIT (con cláusula de marca registrada)',
    tags: ['sso', 'oidc', 'saml', 'identidad', '2fa'],
    database: { engine: 'postgres', dbName: 'authentik', username: 'authentik', memoryMb: 512 },
    secrets: {
      AUTHENTIK_SECRET_KEY: { bytes: 32, encoding: 'base64url' }
    },
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'worker',
        image: 'ghcr.io/goauthentik/server:2026.8.5',
        memoryMb: 1024,
        cpus: 1,
        dependsOn: ['valkey'],
        startAfterApp: true,
        coupledWithApp: true,
        command: ['worker'],
        env: {
          AUTHENTIK_SECRET_KEY: '{{secret.AUTHENTIK_SECRET_KEY}}',
          AUTHENTIK_REDIS__HOST: '{{sidecar.valkey.host}}',
          AUTHENTIK_POSTGRESQL__HOST: '{{db.host}}',
          AUTHENTIK_POSTGRESQL__PORT: '{{db.port}}',
          AUTHENTIK_POSTGRESQL__USER: '{{db.user}}',
          AUTHENTIK_POSTGRESQL__NAME: '{{db.name}}',
          AUTHENTIK_POSTGRESQL__PASSWORD: '{{db.password}}',
          AUTHENTIK_ERROR_REPORTING__ENABLED: 'false'
        },
        volumes: []
      }
    ],
    app: {
      image: 'ghcr.io/goauthentik/server:2026.8.5',
      port: 9000,
      memoryMb: 1536,
      cpus: 1,
      command: ['server'],
      env: {
        AUTHENTIK_SECRET_KEY: '{{secret.AUTHENTIK_SECRET_KEY}}',
        AUTHENTIK_REDIS__HOST: '{{sidecar.valkey.host}}',
        AUTHENTIK_POSTGRESQL__HOST: '{{db.host}}',
        AUTHENTIK_POSTGRESQL__PORT: '{{db.port}}',
        AUTHENTIK_POSTGRESQL__USER: '{{db.user}}',
        AUTHENTIK_POSTGRESQL__NAME: '{{db.name}}',
        AUTHENTIK_POSTGRESQL__PASSWORD: '{{db.password}}',
        AUTHENTIK_ERROR_REPORTING__ENABLED: 'false'
      },
      volumes: [
        { name: 'media', path: '/media' },
        { name: 'templates', path: '/templates' }
      ],
      readiness: { path: '/-/health/live/', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/if/flow/initial-setup/ de inmediato para fijar la contraseña de `akadmin`.',
      'Crea tus proveedores OIDC/OAuth2 o SAML desde la interfaz de administración.'
    ],
    notes: [
      'Servidor + worker + PostgreSQL + Valkey superan los 3 GB totales: asegúrate de contar con RAM libre suficiente.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'keycloak',
    name: 'Keycloak',
    category: 'seguridad',
    summary: 'Servidor estándar empresarial de gestión de identidad y acceso (OIDC, OAuth 2.0, SAML 2.0).',
    description:
      'Gestiona reinos multi-tenant, federación LDAP/AD, inicio de sesión social y control de ' +
      'acceso por roles con PostgreSQL y cabeceras `xforwarded` preconfiguradas.',
    website: 'https://www.keycloak.org',
    licence: 'Apache-2.0',
    tags: ['sso', 'oauth2', 'oidc', 'saml', 'identidad'],
    database: { engine: 'postgres', dbName: 'keycloak', username: 'keycloak', memoryMb: 512 },
    secrets: {
      KC_BOOTSTRAP_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'quay.io/keycloak/keycloak:26.1.3',
      port: 8080,
      memoryMb: 1536,
      cpus: 2,
      command: ['start'],
      env: {
        KC_DB: 'postgres',
        KC_DB_URL: 'jdbc:postgresql://{{db.host}}:{{db.port}}/{{db.name}}',
        KC_DB_USERNAME: '{{db.user}}',
        KC_DB_PASSWORD: '{{db.password}}',
        KC_HOSTNAME: '{{url}}',
        KC_PROXY_HEADERS: 'xforwarded',
        KC_HTTP_ENABLED: 'true',
        KC_HEALTH_ENABLED: 'true',
        // Keycloak 25+ mueve /health/ready al puerto 9000 si no se unifica explícitamente.
        KC_HTTP_MANAGEMENT_PORT: '8080',
        KC_BOOTSTRAP_ADMIN_USERNAME: 'admin',
        KC_BOOTSTRAP_ADMIN_PASSWORD: '{{secret.KC_BOOTSTRAP_ADMIN_PASSWORD}}'
      },
      volumes: [],
      readiness: { path: '/health/ready', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}}/admin e inicia sesión con «admin» y KC_BOOTSTRAP_ADMIN_PASSWORD desde «Credenciales».',
      'Crea un nuevo Realm para tus aplicaciones en lugar de usar el reino `master`.'
    ],
    notes: [
      'Arranca en modo producción detrás de Caddy con TLS; requiere un dominio HTTPS asignado para iniciar sesión en la consola.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'pocket-id',
    name: 'Pocket ID',
    category: 'seguridad',
    summary: 'Proveedor OIDC minimalista basado exclusivamente en passkeys (WebAuthn), sin contraseñas.',
    description:
      'Autentica tus servicios autohospedados con biometría o llaves FIDO2 en un binario ligero con ' +
      'SQLite embebido y clave de cifrado generada.',
    website: 'https://pocket-id.org',
    licence: 'BSD-2-Clause',
    tags: ['oidc', 'passkeys', 'webauthn', 'sso', 'ligero'],
    database: null,
    secrets: {
      ENCRYPTION_KEY: { bytes: 32, encoding: 'base64' }
    },
    app: {
      image: 'ghcr.io/pocket-id/pocket-id:v2.10.0',
      port: 1411,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        APP_URL: '{{url}}',
        TRUST_PROXY: 'true',
        ENCRYPTION_KEY: '{{secret.ENCRYPTION_KEY}}'
      },
      volumes: [{ name: 'data', path: '/app/data' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}}/setup para registrar tu primera cuenta administradora con una passkey.',
      'Asegúrate de usar un dominio HTTPS: WebAuthn no funciona sobre HTTP plano salvo en localhost.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'infisical',
    name: 'Infisical',
    category: 'seguridad',
    summary: 'Gestor centralizado de secretos, variables de entorno y certificados por proyecto y entorno.',
    description:
      'Versiona secretos de desarrollo, staging y producción con cifrado de extremo a extremo, ' +
      'auditoría e inyección automática mediante CLI o SDKs.',
    website: 'https://infisical.com',
    licence: 'MIT (edición comunitaria)',
    tags: ['secretos', 'boveda', 'env', 'devops', 'seguridad'],
    database: { engine: 'postgres', dbName: 'infisical', username: 'infisical', memoryMb: 512 },
    secrets: {
      // Infisical exige clave de 16 bytes codificada en 32 caracteres hex.
      ENCRYPTION_KEY: { bytes: 16, encoding: 'hex' },
      AUTH_SECRET: { bytes: 32, encoding: 'base64' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'infisical/infisical:v0.167.13',
      port: 8080,
      memoryMb: 1536,
      cpus: 1,
      env: {
        ENCRYPTION_KEY: '{{secret.ENCRYPTION_KEY}}',
        AUTH_SECRET: '{{secret.AUTH_SECRET}}',
        DB_CONNECTION_URI: '{{db.url}}',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379',
        SITE_URL: '{{url}}',
        TELEMETRY_ENABLED: 'false'
      },
      volumes: [],
      readiness: { path: '/api/status', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea la primera cuenta administradora de la instancia.',
      'Guarda ENCRYPTION_KEY en tu gestor de contraseñas: si se pierde, no podrás descifrar los secretos almacenados.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'privatebin',
    name: 'PrivateBin',
    category: 'seguridad',
    summary: 'Compartición efímera de texto y contraseñas cifrada en el navegador (conocimiento cero).',
    description:
      'El servidor jamás ve el contenido ni la clave: el cifrado AES-256-GCM ocurre en el navegador ' +
      'y la nota se autodestruye al leerse o caducar.',
    website: 'https://privatebin.info',
    licence: 'zlib',
    tags: ['pastebin', 'cifrado', 'privacidad', 'efimero'],
    database: null,
    secrets: {},
    app: {
      image: 'privatebin/nginx-fpm-alpine:1.5.1',
      port: 8080,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        TZ: '{{tz}}'
      },
      volumes: [{ name: 'data', path: '/srv/data' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y comparte tu primer mensaje cifrado con caducidad o «quemar tras leer».',
      'Asigna un dominio HTTPS para que la Web Crypto API del navegador funcione en todos los clientes.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // H. Contenido y CMS (5 nuevas → 9 en total)
  // -------------------------------------------------------------------------
  {
    id: 'drupal',
    name: 'Drupal',
    category: 'contenido',
    summary: 'CMS modular y plataforma de contenidos empresariales en PHP sobre PostgreSQL.',
    description:
      'Arquitectura estructurada de tipos de contenido, taxonomías, multilingüismo y permisos ' +
      'granulares con volúmenes persistentes para sitios, módulos y temas.',
    website: 'https://www.drupal.org',
    licence: 'GPLv2+',
    tags: ['cms', 'php', 'web', 'editorial'],
    database: { engine: 'postgres', dbName: 'drupal', username: 'drupal', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'drupal:11.4-apache',
      port: 80,
      memoryMb: 1024,
      cpus: 1,
      env: {
        DRUPAL_DB_HOST: '{{db.host}}',
        DRUPAL_DB_PORT: '{{db.port}}',
        DRUPAL_DB_NAME: '{{db.name}}',
        DRUPAL_DB_USER: '{{db.user}}',
        DRUPAL_DB_PASSWORD: '{{db.password}}'
      },
      volumes: [
        { name: 'sites', path: '/var/www/html/sites' },
        { name: 'modules', path: '/var/www/html/modules' },
        { name: 'themes', path: '/var/www/html/themes' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para ejecutar el instalador web de Drupal.',
      'Introduce las credenciales de PostgreSQL que figuran en Bases de datos → credenciales (host `postgres`).'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'joomla',
    name: 'Joomla',
    category: 'contenido',
    summary: 'Gestor de contenidos web maduro con multilingüismo nativo y gestión avanzada de usuarios.',
    description:
      'Crea portales corporativos, intranets y sitios multilingües respaldados por MariaDB aislada ' +
      'y contraseña de administración generada.',
    website: 'https://www.joomla.org',
    licence: 'GPLv2+',
    tags: ['cms', 'php', 'web', 'portal'],
    database: { engine: 'mariadb', dbName: 'joomla', username: 'joomla', memoryMb: 512 },
    secrets: {
      JOOMLA_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'joomla:5.4-apache',
      port: 80,
      memoryMb: 1024,
      cpus: 1,
      env: {
        JOOMLA_DB_HOST: '{{db.host}}',
        JOOMLA_DB_USER: '{{db.user}}',
        JOOMLA_DB_PASSWORD: '{{db.password}}',
        JOOMLA_DB_NAME: '{{db.name}}',
        JOOMLA_ADMIN_USER: 'admin',
        JOOMLA_ADMIN_USERNAME: 'admin',
        JOOMLA_ADMIN_PASSWORD: '{{secret.JOOMLA_ADMIN_PASSWORD}}',
        JOOMLA_ADMIN_EMAIL: 'admin@culkibo.local'
      },
      volumes: [{ name: 'data', path: '/var/www/html' }],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/administrator e inicia sesión con «admin» y JOOMLA_ADMIN_PASSWORD desde «Credenciales».',
      'Actualiza el correo del superusuario y configura tus idiomas o plantillas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'halo',
    name: 'Halo',
    category: 'contenido',
    summary: 'Plataforma moderna de publicación y blogs con editor enriquecido, temas y plugins.',
    description:
      'CMS rápido con arquitectura de plugins, mercado de temas y soporte Markdown respaldado por ' +
      'PostgreSQL reactivo (R2DBC).',
    website: 'https://www.halo.run',
    licence: 'GPLv3',
    tags: ['blog', 'cms', 'publicacion', 'temas'],
    database: { engine: 'postgres', dbName: 'halo', username: 'halo', memoryMb: 512 },
    secrets: {
      HALO_SUPER_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'halohub/halo:2.27.0',
      port: 8090,
      memoryMb: 1024,
      cpus: 1,
      env: {
        SPRING_R2DBC_URL: 'r2dbc:pool:postgresql://{{db.host}}:{{db.port}}/{{db.name}}',
        SPRING_R2DBC_USERNAME: '{{db.user}}',
        SPRING_R2DBC_PASSWORD: '{{db.password}}',
        SPRING_SQL_INIT_PLATFORM: 'postgresql',
        HALO_EXTERNAL_URL: '{{url}}/',
        HALO_SECURITY_INITIALIZER_SUPERADMINUSERNAME: 'admin',
        HALO_SECURITY_INITIALIZER_SUPERADMINPASSWORD: '{{secret.HALO_SUPER_ADMIN_PASSWORD}}'
      },
      volumes: [{ name: 'data', path: '/root/.halo2' }],
      readiness: { path: '/actuator/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Entra en {{url}}/console con usuario «admin» y HALO_SUPER_ADMIN_PASSWORD desde «Credenciales».',
      'Elige un tema desde el panel y publica tu primera entrada.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'freshrss',
    name: 'FreshRSS',
    category: 'contenido',
    summary: 'Agregador y lector RSS/Atom rapidísimo con API compatible con apps móviles.',
    description:
      'Sigue blogs, boletines y canales de noticias sin algoritmos, con actualización programada ' +
      'cada 30 minutos, filtros y base PostgreSQL.',
    website: 'https://freshrss.org',
    licence: 'AGPLv3',
    tags: ['rss', 'atom', 'lector', 'noticias'],
    database: { engine: 'postgres', dbName: 'freshrss', username: 'freshrss', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'freshrss/freshrss:1.26.0',
      port: 80,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        TZ: '{{tz}}',
        CRON_MIN: '3,33',
        TRUSTED_PROXY: '127.0.0.1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16',
        FRESHRSS_INSTALL:
          '--api-enabled --base-url {{url}} --db-type pgsql --db-host {{db.host}}:{{db.port}} ' +
          '--db-base {{db.name}} --db-user {{db.user}} --db-password {{db.password}} ' +
          '--default-user admin --language es'
      },
      volumes: [
        { name: 'data', path: '/var/www/FreshRSS/data' },
        { name: 'extensions', path: '/var/www/FreshRSS/extensions' }
      ],
      readiness: { path: '/i/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}} y completa la creación de la cuenta inicial de administración.',
      'Importa tu fichero OPML desde Gestión de suscripciones.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'prestashop',
    name: 'PrestaShop',
    category: 'contenido',
    summary: 'Plataforma completa de comercio electrónico con catálogo, pedidos, impuestos y pasarelas.',
    description:
      'Tienda online autohospedada en español lista para producción con MariaDB aislada, SSL ' +
      'habilitado e instalación automática inicial.',
    website: 'https://prestashop.com',
    licence: 'OSL-3.0 / AFL-3.0',
    tags: ['ecommerce', 'tienda', 'ventas', 'php'],
    database: { engine: 'mariadb', dbName: 'prestashop', username: 'prestashop', memoryMb: 512 },
    secrets: {
      PS_ADMIN_PASSWD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'prestashop/prestashop:8.2-apache',
      port: 80,
      memoryMb: 1536,
      cpus: 1,
      env: {
        DB_SERVER: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_NAME: '{{db.name}}',
        DB_USER: '{{db.user}}',
        DB_PASSWD: '{{db.password}}',
        PS_DOMAIN: '{{domain}}',
        PS_ENABLE_SSL: '1',
        PS_INSTALL_AUTO: '1',
        PS_LANGUAGE: 'es',
        PS_COUNTRY: 'es',
        ADMIN_MAIL: 'admin@culkibo.local',
        ADMIN_PASSWD: '{{secret.PS_ADMIN_PASSWD}}'
      },
      volumes: [{ name: 'html', path: '/var/www/html' }],
      readiness: { path: '/', expect: [200, 301, 302], timeoutMs: 240000 }
    },
    nextSteps: [
      'Consulta los registros del primer arranque para ver la ruta aleatoria del panel de administración (`/admin...`).',
      'Inicia sesión con `admin@culkibo.local` y PS_ADMIN_PASSWD desde «Credenciales».'
    ],
    notes: [
      'La primera instalación automática tarda entre 2 y 4 minutos en descomprimir y poblar la tienda.'
    ]
  },

  // -------------------------------------------------------------------------
  // I. Documentación y wikis (6 nuevas → 6 en total)
  // -------------------------------------------------------------------------
  {
    id: 'docmost',
    name: 'Docmost',
    category: 'docs',
    summary: 'Wiki colaborativa en tiempo real con diagramas, espacios y búsqueda (alternativa a Notion/Confluence).',
    description:
      'Edición simultánea por varios miembros, comentarios, diagramas Draw.io/Mermaid y gestión de ' +
      'espacios sobre PostgreSQL y Valkey aislados.',
    website: 'https://docmost.com',
    licence: 'AGPLv3',
    tags: ['wiki', 'notion', 'confluence', 'documentacion', 'colaboracion'],
    database: { engine: 'postgres', dbName: 'docmost', username: 'docmost', memoryMb: 512 },
    secrets: {
      APP_SECRET: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'docmost/docmost:0.98.0',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        APP_URL: '{{url}}',
        APP_SECRET: '{{secret.APP_SECRET}}',
        DATABASE_URL: '{{db.url}}?schema=public',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379'
      },
      volumes: [{ name: 'storage', path: '/app/data/storage' }],
      readiness: { path: '/api/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para crear tu espacio de trabajo y la primera cuenta de administración.',
      'Configura SMTP en las variables de entorno si quieres enviar invitaciones por correo.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'bookstack',
    name: 'BookStack',
    category: 'docs',
    summary: 'Base de conocimiento organizada en estantes, libros y capítulos, rápida y muy intuitiva.',
    description:
      'Wiki estructurada con editor visual o Markdown, búsqueda completa, exportación a PDF y ' +
      'permisos por rol sobre MariaDB aislada.',
    website: 'https://www.bookstackapp.com',
    licence: 'MIT',
    tags: ['wiki', 'documentacion', 'manuales', 'conocimiento'],
    database: { engine: 'mariadb', dbName: 'bookstack', username: 'bookstack', memoryMb: 512 },
    secrets: {
      APP_KEY: { bytes: 32, encoding: 'base64' }
    },
    app: {
      image: 'lscr.io/linuxserver/bookstack:version-v26.09.3',
      port: 80,
      memoryMb: 768,
      cpus: 1,
      env: {
        PUID: '1000',
        PGID: '1000',
        TZ: '{{tz}}',
        APP_URL: '{{url}}',
        APP_KEY: 'base64:{{secret.APP_KEY}}',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_USERNAME: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        DB_DATABASE: '{{db.name}}'
      },
      volumes: [{ name: 'config', path: '/config' }],
      readiness: { path: '/login', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}}/login con el acceso inicial de BookStack (`admin@admin.com` / `password`) y cambia ambos de inmediato.',
      'Conserva APP_KEY: Laravel la utiliza para cifrar sesiones y ajustes sensibles.'
    ],
    notes: [
      'La contraseña inicial es fija por diseño del proyecto: cámbiala nada más entrar.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'wikijs',
    name: 'Wiki.js',
    category: 'docs',
    summary: 'Wiki moderna en Node.js con sincronización Git, múltiples editores y búsqueda integrada.',
    description:
      'Soporta Markdown, HTML, diagramas y respaldo automático en repositorios Git, con historial ' +
      'de versiones almacenado en PostgreSQL.',
    website: 'https://js.wiki',
    licence: 'AGPLv3',
    tags: ['wiki', 'markdown', 'git', 'documentacion'],
    database: { engine: 'postgres', dbName: 'wikijs', username: 'wikijs', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'ghcr.io/requarks/wiki:2.5.317',
      port: 3000,
      memoryMb: 768,
      cpus: 1,
      env: {
        DB_TYPE: 'postgres',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_USER: '{{db.user}}',
        DB_PASS: '{{db.password}}',
        DB_NAME: '{{db.name}}'
      },
      volumes: [],
      readiness: { path: '/healthz', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para completar el asistente inicial y fijar tu cuenta administradora.',
      'Activa el idioma español en Administración → Idiomas tras terminar el asistente.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'hedgedoc',
    name: 'HedgeDoc',
    category: 'docs',
    summary: 'Notas y presentaciones Markdown colaborativas en tiempo real para equipos técnicos.',
    description:
      'Edita actas de reunión, especificaciones técnicas y diapositivas Reveal.js en directo con ' +
      'vista dividida, diagramas y respaldo en PostgreSQL.',
    website: 'https://hedgedoc.org',
    licence: 'AGPLv3',
    tags: ['markdown', 'notas', 'colaboracion', 'documentacion'],
    database: { engine: 'postgres', dbName: 'hedgedoc', username: 'hedgedoc', memoryMb: 512 },
    secrets: {
      CMD_SESSION_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'quay.io/hedgedoc/hedgedoc:1.12.2',
      port: 3000,
      memoryMb: 512,
      cpus: 1,
      env: {
        CMD_DB_URL: '{{db.url}}',
        CMD_DOMAIN: '{{domain}}',
        CMD_PROTOCOL_USESSL: '{{isHttps}}',
        CMD_URL_ADDPORT: 'false',
        CMD_SESSION_SECRET: '{{secret.CMD_SESSION_SECRET}}',
        CMD_ALLOW_ANONYMOUS: 'false',
        CMD_ALLOW_ANONYMOUS_EDITS: 'false'
      },
      volumes: [{ name: 'uploads', path: '/hedgedoc/public/uploads' }],
      readiness: { path: '/_health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y registra tu primera cuenta para empezar a crear notas colaborativas.',
      'La edición anónima viene desactivada por seguridad; puedes permitir usuarios locales o conectar OAuth2.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'memos',
    name: 'Memos',
    category: 'docs',
    summary: 'Cuaderno rápido de notas en Markdown tipo microblog privado en un solo binario Go.',
    description:
      'Captura ideas, fragmentos de código, etiquetas y adjuntos en milisegundos con SQLite ' +
      'embebido y consumo mínimo de memoria.',
    website: 'https://usememos.com',
    licence: 'MIT',
    tags: ['notas', 'markdown', 'diario', 'ligero', 'go'],
    database: null,
    secrets: {},
    app: {
      image: 'neosmemo/memos:0.22.2',
      port: 5230,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        MEMOS_MODE: 'prod',
        MEMOS_PORT: '5230'
      },
      volumes: [{ name: 'data', path: '/var/opt/memos' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y crea la cuenta de propietario: una vez creada podrás desactivar nuevos registros en Ajustes.',
      'Conecta apps móviles compatibles o su API REST con un token personal.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'dokuwiki',
    name: 'DokuWiki',
    category: 'docs',
    summary: 'Wiki clásica sin base de datos basada en ficheros de texto plano, estable y ultra ligera.',
    description:
      'Almacena todas las páginas, revisiones y adjuntos como archivos legibles en disco sin ' +
      'necesitar motor SQL, ideal para documentación duradera en VPS pequeños.',
    website: 'https://www.dokuwiki.org',
    licence: 'GPLv2',
    tags: ['wiki', 'documentacion', 'texto plano', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'lscr.io/linuxserver/dokuwiki:2026-07-14c-ls333',
      port: 80,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        PUID: '1000',
        PGID: '1000',
        TZ: '{{tz}}'
      },
      volumes: [{ name: 'config', path: '/config' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}}/install.php para ejecutar el asistente inicial, habilitar ACL y crear el superusuario.',
      'Borra o desactiva `install.php` en cuanto finalice la instalación (el asistente te avisa).'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // J. Productividad y CRM (8 nuevas → 10 en total)
  // -------------------------------------------------------------------------
  {
    id: 'vikunja',
    name: 'Vikunja',
    category: 'productividad',
    summary: 'Gestor de tareas y proyectos con listas, kanban, diagrama Gantt y sincronización CalDAV.',
    description:
      'Alternativa libre a Todoist y Trello escrita en Go, con equipos, etiquetas, fechas límite y ' +
      'PostgreSQL aislado.',
    website: 'https://vikunja.io',
    licence: 'AGPLv3',
    tags: ['tareas', 'kanban', 'gantt', 'caldav', 'proyectos'],
    database: { engine: 'postgres', dbName: 'vikunja', username: 'vikunja', memoryMb: 512 },
    secrets: {
      VIKUNJA_SERVICE_JWTSECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'vikunja/vikunja:0.24.6',
      port: 3456,
      memoryMb: 512,
      cpus: 1,
      env: {
        VIKUNJA_SERVICE_PUBLICURL: '{{url}}',
        VIKUNJA_SERVICE_JWTSECRET: '{{secret.VIKUNJA_SERVICE_JWTSECRET}}',
        VIKUNJA_DATABASE_TYPE: 'postgres',
        VIKUNJA_DATABASE_HOST: '{{db.host}}:{{db.port}}',
        VIKUNJA_DATABASE_USER: '{{db.user}}',
        VIKUNJA_DATABASE_PASSWORD: '{{db.password}}',
        VIKUNJA_DATABASE_DATABASE: '{{db.name}}'
      },
      volumes: [{ name: 'files', path: '/app/vikunja/files' }],
      readiness: { path: '/api/v1/info', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y crea tu primera cuenta de usuario.',
      'Si es uso privado, añade `VIKUNJA_SERVICE_ENABLEREGISTRATION=false` tras crear tus cuentas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'planka',
    name: 'Planka',
    category: 'productividad',
    summary: 'Tableros kanban en tiempo real limpios y rápidos para equipos (alternativa libre a Trello).',
    description:
      'Organiza proyectos, tarjetas, listas de comprobación, adjuntos y comentarios en directo ' +
      'sobre PostgreSQL.',
    website: 'https://planka.app',
    licence: 'AGPLv3',
    tags: ['kanban', 'trello', 'proyectos', 'tableros'],
    database: { engine: 'postgres', dbName: 'planka', username: 'planka', memoryMb: 512 },
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/plankanban/planka:2.0.0',
      port: 1337,
      memoryMb: 768,
      cpus: 1,
      env: {
        BASE_URL: '{{url}}',
        DATABASE_URL: '{{db.url}}',
        SECRET_KEY: '{{secret.SECRET_KEY}}',
        TRUST_PROXY: 'true'
      },
      volumes: [
        { name: 'avatars', path: '/app/public/user-avatars' },
        { name: 'attachments', path: '/app/private/attachments' },
        { name: 'backgrounds', path: '/app/public/background-images' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea la cuenta administradora en la pantalla de bienvenida inicial.',
      'Crea tu primer proyecto y añade a los miembros del equipo desde Administración.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'espocrm',
    name: 'EspoCRM',
    category: 'productividad',
    summary: 'CRM completo para ventas, clientes, oportunidades, calendario y correo corporativo.',
    description:
      'Gestiona cuentas, contactos, embudos comerciales y automatizaciones de ventas en un CRM ' +
      'rápido respaldado por MariaDB.',
    website: 'https://www.espocrm.com',
    licence: 'GPLv3',
    tags: ['crm', 'ventas', 'clientes', 'negocio'],
    database: { engine: 'mariadb', dbName: 'espocrm', username: 'espocrm', memoryMb: 512 },
    secrets: {
      ESPOCRM_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'espocrm/espocrm:9.1.8',
      port: 80,
      memoryMb: 1024,
      cpus: 1,
      env: {
        ESPOCRM_DATABASE_PLATFORM: 'Mysql',
        ESPOCRM_DATABASE_HOST: '{{db.host}}',
        ESPOCRM_DATABASE_PORT: '{{db.port}}',
        ESPOCRM_DATABASE_NAME: '{{db.name}}',
        ESPOCRM_DATABASE_USER: '{{db.user}}',
        ESPOCRM_DATABASE_PASSWORD: '{{db.password}}',
        ESPOCRM_ADMIN_USERNAME: 'admin',
        ESPOCRM_ADMIN_PASSWORD: '{{secret.ESPOCRM_ADMIN_PASSWORD}}',
        ESPOCRM_SITE_URL: '{{url}}'
      },
      volumes: [{ name: 'data', path: '/var/www/html' }],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con ESPOCRM_ADMIN_PASSWORD desde «Credenciales».',
      'Cambia el idioma a español en Preferencias y configura tu servidor SMTP/IMAP.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'paperless-ngx',
    name: 'Paperless-ngx',
    category: 'productividad',
    summary: 'Archivo digital inteligente con OCR automático en español/inglés para facturas y contratos.',
    description:
      'Escanea o sube PDFs e imágenes, extrae el texto mediante OCR, clasifica automáticamente por ' +
      'etiquetas y remitentes y busca en segundos sobre PostgreSQL y Valkey.',
    website: 'https://docs.paperless-ngx.com',
    licence: 'GPLv3',
    tags: ['ocr', 'documentos', 'facturas', 'archivo', 'pdf'],
    database: { engine: 'postgres', dbName: 'paperless', username: 'paperless', memoryMb: 512 },
    secrets: {
      PAPERLESS_SECRET_KEY: { bytes: 32, encoding: 'base64url' },
      PAPERLESS_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'ghcr.io/paperless-ngx/paperless-ngx:3.1.3',
      port: 8000,
      memoryMb: 1536,
      cpus: 2,
      env: {
        PAPERLESS_REDIS: 'redis://{{sidecar.valkey.host}}:6379',
        PAPERLESS_DBHOST: '{{db.host}}',
        PAPERLESS_DBPORT: '{{db.port}}',
        PAPERLESS_DBNAME: '{{db.name}}',
        PAPERLESS_DBUSER: '{{db.user}}',
        PAPERLESS_DBPASS: '{{db.password}}',
        PAPERLESS_SECRET_KEY: '{{secret.PAPERLESS_SECRET_KEY}}',
        PAPERLESS_URL: '{{url}}',
        PAPERLESS_TIME_ZONE: '{{tz}}',
        PAPERLESS_OCR_LANGUAGE: 'spa+eng',
        PAPERLESS_ADMIN_USER: 'admin',
        PAPERLESS_ADMIN_PASSWORD: '{{secret.PAPERLESS_ADMIN_PASSWORD}}',
        PAPERLESS_ADMIN_MAIL: 'admin@culkibo.local'
      },
      volumes: [
        { name: 'data', path: '/usr/src/paperless/data' },
        { name: 'media', path: '/usr/src/paperless/media' },
        { name: 'consume', path: '/usr/src/paperless/consume' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 240000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con PAPERLESS_ADMIN_PASSWORD desde «Credenciales».',
      'Arrastra tu primera factura o contrato para probar la indexación OCR automática en español e inglés.'
    ],
    notes: [
      'El procesamiento OCR consume CPU durante picos de ingesta; 2 vCPU y 1,5 GB de RAM son el mínimo cómodo.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'kimai',
    name: 'Kimai',
    category: 'productividad',
    summary: 'Control horario, registro de horas por cliente/proyecto y generación de facturas.',
    description:
      'Registra tiempos de equipos y freelancers, calcula presupuestos por tarifa, exporta partes ' +
      'a Excel/PDF y emite facturas desde una interfaz web sobre MariaDB.',
    website: 'https://www.kimai.org',
    licence: 'AGPLv3',
    tags: ['tiempo', 'facturacion', 'proyectos', 'freelance', 'horas'],
    database: { engine: 'mariadb', dbName: 'kimai', username: 'kimai', memoryMb: 512 },
    secrets: {
      APP_SECRET: { bytes: 32, encoding: 'hex' },
      ADMINPASS: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'kimai/kimai2:2.72.1',
      port: 8001,
      memoryMb: 1024,
      cpus: 1,
      env: {
        APP_ENV: 'prod',
        APP_SECRET: '{{secret.APP_SECRET}}',
        DATABASE_URL: 'mysql://{{db.user}}:{{db.password}}@{{db.host}}:{{db.port}}/{{db.name}}?charset=utf8mb4&serverVersion=11.4.0-MariaDB',
        TRUSTED_HOSTS: '.*',
        ADMINMAIL: 'admin@culkibo.local',
        ADMINPASS: '{{secret.ADMINPASS}}'
      },
      volumes: [
        { name: 'data', path: '/opt/kimai/var/data' },
        { name: 'plugins', path: '/opt/kimai/var/plugins' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Entra en {{url}} con `admin@culkibo.local` y ADMINPASS desde «Credenciales».',
      'Crea tus primeros clientes, proyectos y actividades antes de invitar al equipo.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'formbricks',
    name: 'Formbricks',
    category: 'productividad',
    summary: 'Encuestas, formularios condicionales y feedback in-app (alternativa libre a Typeform).',
    description:
      'Crea formularios con lógica condicional, encuestas NPS dentro de tu web o app y webhooks de ' +
      'respuestas sobre PostgreSQL con claves de cifrado generadas.',
    website: 'https://formbricks.com',
    licence: 'AGPLv3',
    tags: ['formularios', 'encuestas', 'typeform', 'feedback'],
    database: { engine: 'postgres', dbName: 'formbricks', username: 'formbricks', memoryMb: 512 },
    secrets: {
      NEXTAUTH_SECRET: { bytes: 32, encoding: 'hex' },
      ENCRYPTION_KEY: { bytes: 32, encoding: 'hex' },
      CRON_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/formbricks/formbricks:v2.6.0',
      port: 3000,
      memoryMb: 1536,
      cpus: 1,
      env: {
        WEBAPP_URL: '{{url}}',
        NEXTAUTH_URL: '{{url}}',
        DATABASE_URL: '{{db.url}}',
        NEXTAUTH_SECRET: '{{secret.NEXTAUTH_SECRET}}',
        ENCRYPTION_KEY: '{{secret.ENCRYPTION_KEY}}',
        CRON_SECRET: '{{secret.CRON_SECRET}}',
        TELEMETRY_DISABLED: '1'
      },
      volumes: [{ name: 'uploads', path: '/home/nextjs/apps/web/uploads' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y crea tu primera cuenta administradora.',
      'Guarda ENCRYPTION_KEY: cifra las credenciales de integraciones almacenadas en la base de datos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'twenty',
    name: 'Twenty CRM',
    category: 'productividad',
    summary: 'CRM moderno de código abierto con objetos personalizados, vistas rápidas y API GraphQL.',
    description:
      'Alternativa moderna a Salesforce y HubSpot con diseño tipo Linear/Notion, flujos de trabajo ' +
      'en segundo plano, Valkey y PostgreSQL aislados.',
    website: 'https://twenty.com',
    licence: 'AGPLv3',
    tags: ['crm', 'ventas', 'hubspot', 'graphql', 'equipos'],
    database: { engine: 'postgres', dbName: 'twenty', username: 'twenty', memoryMb: 512 },
    secrets: {
      APP_SECRET: { bytes: 32, encoding: 'base64' }
    },
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'worker',
        image: 'twentycrm/twenty:v2.38.1',
        memoryMb: 1024,
        cpus: 1,
        dependsOn: ['valkey'],
        startAfterApp: true,
        coupledWithApp: true,
        command: ['yarn', 'worker:prod'],
        env: {
          PG_DATABASE_URL: '{{db.url}}',
          REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379',
          SERVER_URL: '{{url}}',
          APP_SECRET: '{{secret.APP_SECRET}}',
          STORAGE_TYPE: 'local',
          DISABLE_DB_MIGRATIONS: 'true',
          DISABLE_CRON_JOBS_REGISTRATION: 'true'
        },
        volumes: []
      }
    ],
    app: {
      image: 'twentycrm/twenty:v2.38.1',
      port: 3000,
      memoryMb: 2048,
      cpus: 2,
      env: {
        NODE_PORT: '3000',
        PG_DATABASE_URL: '{{db.url}}',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379',
        SERVER_URL: '{{url}}',
        APP_SECRET: '{{secret.APP_SECRET}}',
        STORAGE_TYPE: 'local'
      },
      volumes: [{ name: 'storage', path: '/app/packages/twenty-server/.local-storage' }],
      readiness: { path: '/healthz', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}} para crear tu cuenta y espacio de trabajo comercial.',
      'El primer arranque ejecuta migraciones de esquema: espera entre 1 y 2 minutos.'
    ],
    notes: [
      'Twenty (servidor + worker + PostgreSQL + Valkey) necesita cerca de 4 GB de RAM total en el host.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'baserow',
    name: 'Baserow',
    category: 'productividad',
    summary: 'Base de datos colaborativa sin código y constructor de apps internas (alternativa a Airtable).',
    description:
      'Crea tablas relacionales, formularios, vistas kanban/calendario y portales de datos en una ' +
      'imagen autocontenida con persistencia íntegra en volumen.',
    website: 'https://baserow.io',
    licence: 'MIT (edición comunitaria)',
    tags: ['airtable', 'tablas', 'sin codigo', 'formularios'],
    database: null,
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'baserow/baserow:2.4.3',
      port: 80,
      memoryMb: 2048,
      cpus: 2,
      env: {
        BASEROW_PUBLIC_URL: '{{url}}',
        SECRET_KEY: '{{secret.SECRET_KEY}}',
        BASEROW_CADDY_ADDRESSES: ':80'
      },
      volumes: [{ name: 'data', path: '/baserow/data' }],
      readiness: { path: '/api/_health/', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar la cuenta inicial de administración.',
      'Puedes desactivar nuevos registros públicos desde Panel de administración → Ajustes.'
    ],
    notes: [
      'La imagen todo-en-uno de Baserow incluye su propio PostgreSQL y Redis internos dentro del volumen `/baserow/data` y necesita 2 GB de RAM.'
    ]
  },

  // -------------------------------------------------------------------------
  // K. Multimedia y archivos (6 nuevas → 6 en total)
  // -------------------------------------------------------------------------
  {
    id: 'nextcloud',
    name: 'Nextcloud',
    category: 'media',
    summary: 'Nube privada completa: archivos, sincronización, calendarios CalDAV, contactos y fotos.',
    description:
      'Alternativa autohospedada a Google Drive y Dropbox con PostgreSQL, caché Valkey para bloqueos ' +
      'de archivos y límite de subida PHP ampliado a 2 GB.',
    website: 'https://nextcloud.com',
    licence: 'AGPLv3',
    tags: ['nube', 'archivos', 'drive', 'caldav', 'sincronizacion'],
    database: { engine: 'postgres', dbName: 'nextcloud', username: 'nextcloud', memoryMb: 512 },
    secrets: {
      NEXTCLOUD_ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'nextcloud:31.0.5-apache',
      port: 80,
      memoryMb: 1536,
      cpus: 2,
      env: {
        POSTGRES_HOST: '{{db.host}}:{{db.port}}',
        POSTGRES_DB: '{{db.name}}',
        POSTGRES_USER: '{{db.user}}',
        POSTGRES_PASSWORD: '{{db.password}}',
        REDIS_HOST: '{{sidecar.valkey.host}}',
        NEXTCLOUD_ADMIN_USER: 'admin',
        NEXTCLOUD_ADMIN_PASSWORD: '{{secret.NEXTCLOUD_ADMIN_PASSWORD}}',
        NEXTCLOUD_TRUSTED_DOMAINS: '{{host}}',
        OVERWRITECLIURL: '{{url}}',
        OVERWRITEPROTOCOL: '{{protocol}}'
      },
      files: [
        {
          name: 'culkibo-uploads.ini',
          path: '/usr/local/etc/php/conf.d/culkibo-uploads.ini',
          content:
            'memory_limit = 512M\n' +
            'upload_max_filesize = 2G\n' +
            'post_max_size = 2G\n' +
            'max_execution_time = 600\n'
        }
      ],
      volumes: [{ name: 'html', path: '/var/www/html' }],
      readiness: { path: '/status.php', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con NEXTCLOUD_ADMIN_PASSWORD desde «Credenciales».',
      'Instala las aplicaciones de escritorio y móvil de Nextcloud apuntando a tu dominio HTTPS.'
    ],
    notes: [
      'La primera inicialización descomprime Nextcloud e inicializa PostgreSQL: puede tardar 1-3 minutos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'immich',
    name: 'Immich',
    category: 'media',
    summary: 'Copia automática de fotos y vídeos con búsqueda inteligente (alternativa a Google Fotos).',
    description:
      'Sincroniza el carrete del móvil en calidad original, agrupa caras y busca por descripción con ' +
      'PostgreSQL VectorChord, Valkey y contenedor dedicado de Machine Learning.',
    website: 'https://immich.app',
    licence: 'AGPLv3',
    tags: ['fotos', 'videos', 'galeria', 'movil', 'ia'],
    database: {
      engine: 'postgres',
      image: 'ghcr.io/immich-app/postgres:16-vectorchord1.1.1',
      dbName: 'immich',
      username: 'immich',
      memoryMb: 1024
    },
    secrets: {},
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'ml',
        image: 'ghcr.io/immich-app/immich-machine-learning:v1.125.0',
        memoryMb: 2048,
        cpus: 2,
        coupledWithApp: true,
        coupledTagOnly: true,
        env: {},
        volumes: [{ name: 'cache', path: '/cache' }],
        readiness: { type: 'tcp', port: 3003, timeoutMs: 60000 }
      }
    ],
    app: {
      image: 'ghcr.io/immich-app/immich-server:v1.125.0',
      port: 2283,
      memoryMb: 2048,
      cpus: 2,
      env: {
        DB_HOSTNAME: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_USERNAME: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        DB_DATABASE_NAME: '{{db.name}}',
        REDIS_HOSTNAME: '{{sidecar.valkey.host}}',
        IMMICH_MACHINE_LEARNING_URL: 'http://{{sidecar.ml.host}}:3003',
        UPLOAD_LOCATION: '/usr/src/app/upload'
      },
      volumes: [{ name: 'uploads', path: '/usr/src/app/upload' }],
      readiness: { path: '/api/server/ping', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}} para crear la cuenta administradora de Immich.',
      'Conecta las apps oficiales de iOS y Android indicando {{url}}/api como servidor.'
    ],
    notes: [
      'Immich completo (servidor + ML + PostgreSQL VectorChord + Valkey) requiere al menos 6 GB de RAM en el VPS.',
      'Actualiza siempre `immich-server` y `immich-machine-learning` juntos y revisa las notas de versión antes de subir de versión.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'filebrowser',
    name: 'File Browser',
    category: 'media',
    summary: 'Gestor de archivos web ultraligero para subir, previsualizar y compartir carpetas.',
    description:
      'Interfaz limpia en Go con visor de imágenes, texto y vídeo, enlaces compartidos con caducidad ' +
      'y gestión de usuarios en menos de 50 MB de RAM.',
    website: 'https://filebrowser.org',
    licence: 'Apache-2.0',
    tags: ['archivos', 'gestor', 'compartir', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'filebrowser/filebrowser:v2.32.0',
      port: 80,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        FB_PORT: '80',
        FB_ROOT: '/srv',
        FB_DATABASE: '/database/filebrowser.db'
      },
      volumes: [
        { name: 'srv', path: '/srv' },
        { name: 'database', path: '/database' },
        { name: 'config', path: '/config' }
      ],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Revisa los registros del contenedor en el primer arranque para obtener la contraseña aleatoria de «admin» y cámbiala al entrar.',
      'Abre {{url}} para empezar a organizar y compartir archivos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'jellyfin',
    name: 'Jellyfin',
    category: 'media',
    summary: 'Servidor multimedia libre para películas, series y música sin suscripciones ni telemetría.',
    description:
      'Reproduce tu biblioteca en TV, móvil y navegador con metadatos automáticos, subtítulos, ' +
      'perfiles familiares y control parental.',
    website: 'https://jellyfin.org',
    licence: 'GPLv2',
    tags: ['video', 'peliculas', 'series', 'streaming', 'multimedia'],
    database: null,
    secrets: {},
    app: {
      image: 'jellyfin/jellyfin:10.10.3',
      port: 8096,
      memoryMb: 2048,
      cpus: 2,
      env: {
        JELLYFIN_PublishedServerUrl: '{{url}}',
        TZ: '{{tz}}'
      },
      volumes: [
        { name: 'config', path: '/config' },
        { name: 'cache', path: '/cache' },
        { name: 'media', path: '/media' }
      ],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} de inmediato para completar el asistente y crear la cuenta administradora.',
      'Añade tus carpetas dentro del volumen `/media` para indexar bibliotecas.'
    ],
    notes: [
      'Sin GPU dedicada, la transcodificación de vídeo 4K por CPU consume muchos recursos: prioriza reproducción directa.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'navidrome',
    name: 'Navidrome',
    category: 'media',
    summary: 'Servidor privado de música en streaming compatible con clientes Subsonic y OpenSubsonic.',
    description:
      'Escucha tu colección FLAC/MP3 desde navegador o apps móviles (Symfonium, Feishin, Amperfy) ' +
      'con listas inteligentes, scrobbling y bajo consumo de RAM.',
    website: 'https://www.navidrome.org',
    licence: 'GPLv3',
    tags: ['musica', 'audio', 'streaming', 'subsonic'],
    database: null,
    secrets: {},
    app: {
      image: 'deluan/navidrome:0.55.0',
      port: 4533,
      memoryMb: 512,
      cpus: 1,
      env: {
        ND_DATAFOLDER: '/data',
        ND_MUSICFOLDER: '/music',
        ND_LOGLEVEL: 'info',
        ND_SCANSCHEDULE: '1h'
      },
      volumes: [
        { name: 'data', path: '/data' },
        { name: 'music', path: '/music' }
      ],
      readiness: { path: '/ping', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para crear tu cuenta de administrador en el primer arranque.',
      'Copia tu biblioteca de música en el volumen `/music`; Navidrome la escaneará automáticamente.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'audiobookshelf',
    name: 'Audiobookshelf',
    category: 'media',
    summary: 'Servidor privado de audiolibros y podcasts con sincronización de progreso entre dispositivos.',
    description:
      'Gestiona bibliotecas de audiolibros, descarga episodios de podcasts automáticamente y ' +
      'sincroniza el punto exacto de escucha con sus apps oficiales de iOS y Android.',
    website: 'https://www.audiobookshelf.org',
    licence: 'GPLv3',
    tags: ['audiolibros', 'podcasts', 'audio', 'streaming'],
    database: null,
    secrets: {},
    app: {
      image: 'ghcr.io/advplyr/audiobookshelf:v2.17.0',
      port: 80,
      memoryMb: 512,
      cpus: 1,
      env: {
        TZ: '{{tz}}'
      },
      volumes: [
        { name: 'config', path: '/config' },
        { name: 'metadata', path: '/metadata' },
        { name: 'audiobooks', path: '/audiobooks' },
        { name: 'podcasts', path: '/podcasts' }
      ],
      readiness: { path: '/healthcheck', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para crear el usuario raíz (`root`) y definir tus bibliotecas.',
      'Sube audiolibros al volumen `/audiobooks` o suscríbete a feeds RSS de podcasts.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  // L. Mensajería y notificaciones (5 nuevas → 5 en total)
  // -------------------------------------------------------------------------
  {
    id: 'mattermost',
    name: 'Mattermost Team Edition',
    category: 'mensajeria',
    summary: 'Chat de equipo por canales, hilos, búsqueda e integraciones (alternativa libre a Slack).',
    description:
      'Comunicación corporativa segura con webhooks entrantes/salientes, bots, apps de escritorio y ' +
      'móvil respaldada por PostgreSQL aislado.',
    website: 'https://mattermost.com',
    licence: 'MIT (Team Edition)',
    tags: ['chat', 'slack', 'equipo', 'canales', 'mensajeria'],
    database: { engine: 'postgres', dbName: 'mattermost', username: 'mattermost', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'mattermost/mattermost-team-edition:10.5.10',
      port: 8065,
      memoryMb: 1536,
      cpus: 1,
      env: {
        MM_SQLSETTINGS_DRIVERNAME: 'postgres',
        MM_SQLSETTINGS_DATASOURCE: 'postgres://{{db.user}}:{{db.password}}@{{db.host}}:{{db.port}}/{{db.name}}?sslmode=disable&connect_timeout=10',
        MM_SERVICESETTINGS_SITEURL: '{{url}}',
        MM_SERVICESETTINGS_LISTENADDRESS: ':8065',
        MM_BLEVESETTINGS_INDEXDIR: '/mattermost/data/bleve-indexes'
      },
      volumes: [
        { name: 'config', path: '/mattermost/config' },
        { name: 'data', path: '/mattermost/data' },
        { name: 'logs', path: '/mattermost/logs' },
        { name: 'plugins', path: '/mattermost/plugins' }
      ],
      readiness: { path: '/api/v4/system/ping', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para crear la primera cuenta de administrador del sistema y tu equipo inicial.',
      'Configura SMTP en la Consola del Sistema para enviar invitaciones y notificaciones.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'chatwoot',
    name: 'Chatwoot',
    category: 'mensajeria',
    summary: 'Bandeja omnicanal de soporte al cliente: chat en vivo, correo, WhatsApp, Telegram e Instagram.',
    description:
      'Centraliza la atención al cliente con asignaciones por equipo, respuestas rápidas, bot API ' +
      'y widget incrustable sobre PostgreSQL, Valkey y worker Sidekiq.',
    website: 'https://www.chatwoot.com',
    licence: 'MIT (edición comunitaria)',
    tags: ['soporte', 'atencion al cliente', 'chat', 'omnicanal', 'helpdesk'],
    database: { engine: 'postgres', dbName: 'chatwoot', username: 'chatwoot', memoryMb: 512 },
    secrets: {
      SECRET_KEY_BASE: { bytes: 64, encoding: 'hex' }
    },
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'worker',
        image: 'chatwoot/chatwoot:v4.20.0-ce',
        memoryMb: 1024,
        cpus: 1,
        dependsOn: ['valkey'],
        startAfterApp: true,
        coupledWithApp: true,
        command: ['bundle', 'exec', 'sidekiq', '-C', 'config/sidekiq.yml'],
        env: {
          RAILS_ENV: 'production',
          NODE_ENV: 'production',
          INSTALLATION_ENV: 'docker',
          FRONTEND_URL: '{{url}}',
          SECRET_KEY_BASE: '{{secret.SECRET_KEY_BASE}}',
          POSTGRES_HOST: '{{db.host}}',
          POSTGRES_PORT: '{{db.port}}',
          POSTGRES_DATABASE: '{{db.name}}',
          POSTGRES_USERNAME: '{{db.user}}',
          POSTGRES_PASSWORD: '{{db.password}}',
          REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379'
        },
        volumes: []
      }
    ],
    app: {
      image: 'chatwoot/chatwoot:v4.20.0-ce',
      port: 3000,
      memoryMb: 1536,
      cpus: 1,
      command: [
        'sh', '-c',
        'bundle exec rails db:chatwoot_prepare && exec bundle exec rails s -p 3000 -b 0.0.0.0'
      ],
      env: {
        RAILS_ENV: 'production',
        NODE_ENV: 'production',
        INSTALLATION_ENV: 'docker',
        FRONTEND_URL: '{{url}}',
        SECRET_KEY_BASE: '{{secret.SECRET_KEY_BASE}}',
        POSTGRES_HOST: '{{db.host}}',
        POSTGRES_PORT: '{{db.port}}',
        POSTGRES_DATABASE: '{{db.name}}',
        POSTGRES_USERNAME: '{{db.user}}',
        POSTGRES_PASSWORD: '{{db.password}}',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379',
        ENABLE_ACCOUNT_SIGNUP: 'false'
      },
      volumes: [{ name: 'storage', path: '/app/storage' }],
      readiness: { path: '/api', expect: [200, 302], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}}/installation/onboarding para crear la cuenta administradora inicial.',
      'Configura SMTP en las variables de entorno para enviar correos a clientes e invitar agentes.'
    ],
    notes: [
      'El primer arranque ejecuta `db:chatwoot_prepare`: puede tardar entre 1 y 3 minutos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'ntfy',
    name: 'ntfy',
    category: 'mensajeria',
    summary: 'Servidor HTTP pub-sub de notificaciones push instantáneas a móvil y escritorio con un simple curl.',
    description:
      'Envía alertas desde scripts, crons, webhooks o Culkibo a tu teléfono mediante peticiones PUT/POST ' +
      'con autenticación por defecto cerrada (`deny-all`).',
    website: 'https://ntfy.sh',
    licence: 'Apache-2.0 / GPLv2',
    tags: ['notificaciones', 'push', 'alertas', 'pubsub', 'webhook'],
    database: null,
    secrets: {},
    app: {
      image: 'binwiederhier/ntfy:v2.11.0',
      port: 80,
      memoryMb: 256,
      cpus: 0.5,
      command: ['serve'],
      env: {
        TZ: '{{tz}}',
        NTFY_BASE_URL: '{{url}}',
        NTFY_BEHIND_PROXY: 'true',
        NTFY_CACHE_FILE: '/var/cache/ntfy/cache.db',
        NTFY_AUTH_FILE: '/etc/ntfy/user.db',
        NTFY_AUTH_DEFAULT_ACCESS: 'deny-all'
      },
      volumes: [
        { name: 'cache', path: '/var/cache/ntfy' },
        { name: 'etc', path: '/etc/ntfy' }
      ],
      readiness: { path: '/v1/health', expect: [200] }
    },
    nextSteps: [
      'Crea tu usuario administrador dentro del contenedor con `ntfy user add --role=admin admin`.',
      'Conecta las apps móviles de ntfy a {{url}} y genera tokens por tema para tus alertas.'
    ],
    notes: [
      'Viene cerrado por defecto (`deny-all`) para que nadie externo publique ni lea tus temas.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'gotify',
    name: 'Gotify',
    category: 'mensajeria',
    summary: 'Servidor minimalista de notificaciones push con tokens por aplicación y WebSockets.',
    description:
      'Recibe mensajes en tiempo real mediante API REST sencilla y reenvíalos al navegador o a la ' +
      'app de Android con registro público desactivado.',
    website: 'https://gotify.net',
    licence: 'MIT',
    tags: ['notificaciones', 'push', 'alertas', 'api', 'ligero'],
    database: null,
    secrets: {
      GOTIFY_DEFAULTUSER_PASS: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'gotify/server:2.6.1',
      port: 80,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        TZ: '{{tz}}',
        GOTIFY_DEFAULTUSER_NAME: 'admin',
        GOTIFY_DEFAULTUSER_PASS: '{{secret.GOTIFY_DEFAULTUSER_PASS}}',
        GOTIFY_REGISTRATION: 'false'
      },
      volumes: [{ name: 'data', path: '/app/data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con GOTIFY_DEFAULTUSER_PASS desde «Credenciales».',
      'Crea una aplicación en Gotify para obtener su token y enviar notificaciones por HTTP POST.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'matrix-conduit',
    name: 'Matrix Conduit',
    category: 'mensajeria',
    summary: 'Servidor doméstico Matrix escrito en Rust: mensajería cifrada de extremo a extremo y federada.',
    description:
      'Compatible con Element y cualquier cliente Matrix con una fracción de la memoria de Synapse, ' +
      'almacenamiento RocksDB y registro protegido por token de invitación.',
    website: 'https://conduit.rs',
    licence: 'Apache-2.0',
    tags: ['matrix', 'chat', 'cifrado', 'federado', 'rust'],
    database: null,
    secrets: {
      CONDUIT_REGISTRATION_TOKEN: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'matrixconduit/matrix-conduit:v0.10.10',
      port: 6167,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        CONDUIT_SERVER_NAME: '{{host}}',
        CONDUIT_DATABASE_PATH: '/var/lib/matrix-conduit/',
        CONDUIT_DATABASE_BACKEND: 'rocksdb',
        CONDUIT_PORT: '6167',
        CONDUIT_ADDRESS: '0.0.0.0',
        CONDUIT_ALLOW_REGISTRATION: 'true',
        CONDUIT_REGISTRATION_TOKEN: '{{secret.CONDUIT_REGISTRATION_TOKEN}}',
        CONDUIT_ALLOW_FEDERATION: 'true',
        CONDUIT_TRUSTED_SERVERS: '["matrix.org"]'
      },
      volumes: [{ name: 'data', path: '/var/lib/matrix-conduit' }],
      readiness: { path: '/_matrix/client/versions', expect: [200] }
    },
    nextSteps: [
      'Conecta Element (web, escritorio o móvil) indicando {{url}} como servidor doméstico.',
      'Usa CONDUIT_REGISTRATION_TOKEN desde «Credenciales» para dar de alta tu primera cuenta (será administradora).'
    ],
    notes: [
      'Asigna un dominio HTTPS antes de federar: el nombre del servidor Matrix (`CONDUIT_SERVER_NAME`) no puede cambiarse una vez creados los usuarios.'
    ]
  },

  // -------------------------------------------------------------------------
  // M. Expansión 2025–2026: 40 plantillas top de alta demanda (100 → 140)
  // -------------------------------------------------------------------------

  // --- AI / LLM (+7) -------------------------------------------------------
  {
    id: 'langfuse',
    name: 'Langfuse',
    category: 'ia',
    summary: 'Observabilidad open-source para LLMs: trazas, prompts, evaluaciones y coste por token.',
    description:
      'Registra cada llamada a agentes y modelos de lenguaje con latencia, costes, versionado de ' +
      'prompts y datasets de evaluación sobre PostgreSQL, ClickHouse y Valkey aislados.',
    website: 'https://langfuse.com',
    licence: 'MIT (edición OSS)',
    tags: ['llm', 'observabilidad', 'trazas', 'prompts', 'agentes', 'ia'],
    database: { engine: 'postgres', dbName: 'langfuse', username: 'langfuse', memoryMb: 512 },
    secrets: {
      NEXTAUTH_SECRET: { bytes: 32, encoding: 'hex' },
      SALT: { bytes: 32, encoding: 'hex' },
      ENCRYPTION_KEY: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [
      makeValkeySidecar(256),
      makeClickhouseSidecar(1536)
    ],
    app: {
      image: 'langfuse/langfuse:3.55.0',
      port: 3000,
      memoryMb: 1536,
      cpus: 2,
      env: {
        DATABASE_URL: '{{db.url}}',
        NEXTAUTH_URL: '{{url}}',
        NEXTAUTH_SECRET: '{{secret.NEXTAUTH_SECRET}}',
        SALT: '{{secret.SALT}}',
        ENCRYPTION_KEY: '{{secret.ENCRYPTION_KEY}}',
        REDIS_HOST: '{{sidecar.valkey.host}}',
        REDIS_PORT: '6379',
        CLICKHOUSE_URL: 'http://{{sidecar.clickhouse.host}}:8123',
        CLICKHOUSE_MIGRATION_URL: 'clickhouse://{{sidecar.clickhouse.host}}:9000',
        CLICKHOUSE_USER: 'default',
        CLICKHOUSE_CLUSTER_ENABLED: 'false',
        TELEMETRY_ENABLED: 'false'
      },
      volumes: [{ name: 'data', path: '/app/data' }],
      readiness: { path: '/api/public/health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar tu organización y generar tus claves pública y secreta de proyecto.',
      'Conecta tus SDKs de OpenAI, LangChain o Anthropic apuntando `LANGFUSE_HOST` a {{url}}.'
    ],
    notes: [
      'Langfuse v3 con ClickHouse, PostgreSQL y Valkey necesita al menos 4 GB de RAM libre.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'dify',
    name: 'Dify',
    category: 'ia',
    summary: 'Constructor visual de aplicaciones LLM, pipelines RAG y agentes con API lista para producción.',
    description:
      'Diseña flujos agénticos, bases de conocimiento RAG y asistentes multi-modelo desde una ' +
      'interfaz visual completa con API, worker Celery, PostgreSQL y Valkey aislados.',
    website: 'https://dify.ai',
    licence: 'Apache-2.0 (con cláusula Dify Open Source)',
    tags: ['llm', 'rag', 'agentes', 'flujos', 'ia', 'workflows'],
    database: { engine: 'postgres', dbName: 'dify', username: 'dify', memoryMb: 512 },
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [
      makeValkeySidecar(256),
      {
        name: 'api',
        image: 'langgenius/dify-api:1.3.1',
        memoryMb: 1536,
        cpus: 1,
        dependsOn: ['valkey'],
        coupledWithApp: true,
        coupledTagOnly: true,
        env: {
          MODE: 'api',
          SECRET_KEY: '{{secret.SECRET_KEY}}',
          CONSOLE_WEB_URL: '{{url}}',
          APP_WEB_URL: '{{url}}',
          DB_USERNAME: '{{db.user}}',
          DB_PASSWORD: '{{db.password}}',
          DB_HOST: '{{db.host}}',
          DB_PORT: '{{db.port}}',
          DB_DATABASE: '{{db.name}}',
          REDIS_HOST: '{{sidecar.valkey.host}}',
          REDIS_PORT: '6379',
          CELERY_BROKER_URL: 'redis://{{sidecar.valkey.host}}:6379/1',
          MIGRATION_ENABLED: 'true',
          STORAGE_TYPE: 'opendal',
          OPENDAL_SCHEME: 'fs',
          OPENDAL_FS_ROOT: 'storage'
        },
        volumes: [{ name: 'storage', path: '/app/api/storage' }],
        readiness: { type: 'tcp', port: 5001, timeoutMs: 120000 }
      },
      {
        name: 'worker',
        image: 'langgenius/dify-api:1.3.1',
        memoryMb: 1024,
        cpus: 1,
        dependsOn: ['valkey', 'api'],
        startAfterApp: true,
        coupledWithApp: true,
        coupledTagOnly: true,
        env: {
          MODE: 'worker',
          SECRET_KEY: '{{secret.SECRET_KEY}}',
          DB_USERNAME: '{{db.user}}',
          DB_PASSWORD: '{{db.password}}',
          DB_HOST: '{{db.host}}',
          DB_PORT: '{{db.port}}',
          DB_DATABASE: '{{db.name}}',
          REDIS_HOST: '{{sidecar.valkey.host}}',
          REDIS_PORT: '6379',
          CELERY_BROKER_URL: 'redis://{{sidecar.valkey.host}}:6379/1',
          STORAGE_TYPE: 'opendal',
          OPENDAL_SCHEME: 'fs',
          OPENDAL_FS_ROOT: 'storage'
        },
        volumes: []
      }
    ],
    app: {
      image: 'langgenius/dify-web:1.3.1',
      port: 3000,
      memoryMb: 512,
      cpus: 1,
      env: {
        CONSOLE_API_URL: 'http://{{sidecar.api.host}}:5001',
        APP_API_URL: 'http://{{sidecar.api.host}}:5001',
        EDITION: 'SELF_HOSTED',
        NEXT_TELEMETRY_DISABLED: '1'
      },
      volumes: [{ name: 'cache', path: '/app/web/.next/cache' }],
      readiness: { path: '/', expect: [200, 302, 307], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/install para configurar la cuenta administradora de Dify.',
      'Añade tus proveedores de modelos (OpenAI, Anthropic, Ollama o LiteLLM) en Ajustes → Proveedores.'
    ],
    notes: [
      'Stack completo (web + api + worker + PostgreSQL + Valkey) requiere al menos 4 GB de RAM.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'librechat',
    name: 'LibreChat',
    category: 'ia',
    summary: 'Interfaz de chat IA multi-proveedor estilo ChatGPT con asistentes, artefactos y MCP.',
    description:
      'Unifica OpenAI, Anthropic, Gemini, Ollama y endpoints OpenAI-compatibles en una sola web ' +
      'con historial persistente en MongoDB, búsqueda y control de cuentas.',
    website: 'https://www.librechat.ai',
    licence: 'MIT',
    tags: ['chat', 'llm', 'chatgpt', 'mcp', 'ollama', 'ia'],
    database: { engine: 'mongodb', dbName: 'librechat', username: 'librechat', memoryMb: 512 },
    secrets: {
      JWT_SECRET: { bytes: 32, encoding: 'hex' },
      JWT_REFRESH_SECRET: { bytes: 32, encoding: 'hex' },
      CREDS_KEY: { bytes: 32, encoding: 'hex' },
      CREDS_IV: { bytes: 16, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/danny-avila/librechat:v0.7.7',
      port: 3080,
      memoryMb: 1024,
      cpus: 1,
      env: {
        HOST: '0.0.0.0',
        PORT: '3080',
        DOMAIN_CLIENT: '{{url}}',
        DOMAIN_SERVER: '{{url}}',
        MONGO_URI: '{{db.url}}',
        JWT_SECRET: '{{secret.JWT_SECRET}}',
        JWT_REFRESH_SECRET: '{{secret.JWT_REFRESH_SECRET}}',
        CREDS_KEY: '{{secret.CREDS_KEY}}',
        CREDS_IV: '{{secret.CREDS_IV}}',
        ALLOW_EMAIL_LOGIN: 'true',
        ALLOW_REGISTRATION: 'true',
        NO_INDEX: 'true'
      },
      volumes: [
        { name: 'images', path: '/app/client/public/images' },
        { name: 'uploads', path: '/app/uploads' },
        { name: 'logs', path: '/app/api/logs' }
      ],
      readiness: { path: '/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Crea tu cuenta en {{url}} y luego desactiva el registro (`ALLOW_REGISTRATION=false`) en Variables.',
      'Añade tus claves (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) en Variables para activar proveedores.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'lobechat',
    name: 'LobeChat',
    category: 'ia',
    summary: 'Cliente IA moderno con mercado de plugins, artefactos, visión, voz y soporte MCP.',
    description:
      'Interfaz de última generación para conversar con decenas de proveedores LLM con base de ' +
      'datos PostgreSQL para sincronizar sesiones, agentes personalizados y memoria.',
    website: 'https://lobehub.com',
    licence: 'Apache-2.0 (con cláusula LobeHub)',
    tags: ['chat', 'llm', 'plugins', 'mcp', 'agentes', 'ia'],
    database: { engine: 'postgres', dbName: 'lobechat', username: 'lobechat', memoryMb: 512 },
    secrets: {
      KEY_VAULTS_SECRET: { bytes: 32, encoding: 'base64' },
      NEXT_AUTH_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'lobehub/lobe-chat-database:1.84.12',
      port: 3210,
      memoryMb: 1024,
      cpus: 1,
      env: {
        APP_URL: '{{url}}',
        DATABASE_URL: '{{db.url}}',
        DATABASE_DRIVER: 'node',
        KEY_VAULTS_SECRET: '{{secret.KEY_VAULTS_SECRET}}',
        NEXT_AUTH_SECRET: '{{secret.NEXT_AUTH_SECRET}}',
        NEXTAUTH_URL: '{{url}}/api/auth',
        NEXT_PUBLIC_SERVICE_MODE: 'server'
      },
      volumes: [{ name: 'cache', path: '/app/.next/cache' }],
      readiness: { path: '/', expect: [200, 302, 307], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y configura tus proveedores de modelos o conecta un proveedor OIDC en Variables.',
      'Activa servidores MCP o plugins directamente desde el menú de extensiones.'
    ],
    notes: [
      'Configura un proveedor de autenticación (Authentik, Keycloak o Pocket ID) en Variables para uso multiusuario.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'langflow',
    name: 'Langflow',
    category: 'ia',
    summary: 'Editor visual low-code en Python para diseñar agentes IA, cadenas RAG y APIs MCP.',
    description:
      'Arrastra componentes de LangChain, modelos locales o en la nube y bases vectoriales para ' +
      'prototipar y servir flujos de IA como endpoints REST o servidores MCP.',
    website: 'https://www.langflow.org',
    licence: 'MIT',
    tags: ['agentes', 'rag', 'python', 'visual', 'mcp', 'ia'],
    database: { engine: 'postgres', dbName: 'langflow', username: 'langflow', memoryMb: 512 },
    secrets: {
      LANGFLOW_SUPERUSER_PASSWORD: { bytes: 18, encoding: 'base64url' },
      LANGFLOW_SECRET_KEY: { bytes: 32, encoding: 'base64url' }
    },
    app: {
      image: 'langflowai/langflow:1.3.4',
      port: 7860,
      memoryMb: 2048,
      cpus: 2,
      env: {
        LANGFLOW_DATABASE_URL: '{{db.url}}',
        LANGFLOW_CONFIG_DIR: '/app/langflow',
        LANGFLOW_AUTO_LOGIN: 'false',
        LANGFLOW_SUPERUSER: 'admin',
        LANGFLOW_SUPERUSER_PASSWORD: '{{secret.LANGFLOW_SUPERUSER_PASSWORD}}',
        LANGFLOW_SECRET_KEY: '{{secret.LANGFLOW_SECRET_KEY}}',
        DO_NOT_TRACK: 'true'
      },
      volumes: [{ name: 'data', path: '/app/langflow' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con `LANGFLOW_SUPERUSER_PASSWORD` desde «Credenciales».',
      'Crea un flujo desde plantilla y publícalo como API REST o endpoint MCP.'
    ],
    notes: [
      'El primer arranque migra el esquema Python/FastAPI y requiere al menos 2 GB de RAM.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'perplexica',
    name: 'Perplexica',
    category: 'ia',
    summary: 'Motor de búsqueda con IA autohospedado (alternativa a Perplexity) con SearXNG integrado.',
    description:
      'Combina búsqueda web privada en tiempo real mediante un auxiliar SearXNG aislado con ' +
      'modelos locales (Ollama) o en la nube para responder con citas verificables.',
    website: 'https://github.com/ItzCrazyKns/Perplexica',
    licence: 'MIT',
    tags: ['busqueda', 'perplexity', 'searxng', 'rag', 'ia'],
    database: null,
    secrets: {
      SEARXNG_SECRET: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [
      {
        name: 'searxng',
        image: 'searxng/searxng:2026.11.18-b867c56a5',
        memoryMb: 512,
        cpus: 0.5,
        env: {
          SEARXNG_SECRET: '{{secret.SEARXNG_SECRET}}'
        },
        volumes: [{ name: 'config', path: '/etc/searxng' }],
        readiness: { type: 'tcp', port: 8080, timeoutMs: 45000 }
      }
    ],
    app: {
      image: 'itzcrazykns1337/perplexica:1.10.2',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        SEARXNG_API_URL: 'http://{{sidecar.searxng.host}}:8080'
      },
      volumes: [
        { name: 'data', path: '/home/perplexica/data' },
        { name: 'uploads', path: '/home/perplexica/uploads' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} y configura tu proveedor de chat y embeddings (Ollama, OpenAI, Groq o Anthropic) en Ajustes.',
      'Activa el formato JSON en SearXNG si personalizas `settings.yml`.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'milvus',
    name: 'Milvus',
    category: 'ia',
    summary: 'Base de datos vectorial de alto rendimiento para búsqueda semántica y RAG a escala.',
    description:
      'Despliegue standalone autocontenido con etcd embebido y almacenamiento local en volumen, ' +
      'exponiendo salud HTTP en 9091 y API vectorial gRPC en el puerto auxiliar 19530.',
    website: 'https://milvus.io',
    licence: 'Apache-2.0',
    tags: ['vectores', 'embeddings', 'rag', 'ia', 'busqueda'],
    database: null,
    secrets: {},
    app: {
      image: 'milvusdb/milvus:v2.5.10',
      port: 9091,
      extraPorts: [{ containerPort: 19530, label: 'gRPC API' }],
      memoryMb: 2048,
      cpus: 2,
      command: ['milvus', 'run', 'standalone'],
      env: {
        ETCD_USE_EMBED: 'true',
        ETCD_DATA_DIR: '/var/lib/milvus/etcd',
        COMMON_STORAGETYPE: 'local',
        DEPLOY_MODE: 'STANDALONE'
      },
      volumes: [{ name: 'data', path: '/var/lib/milvus' }],
      readiness: { path: '/healthz', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Conecta tus clientes pymilvus o LangChain al puerto auxiliar gRPC (19530) en `127.0.0.1`.',
      'Consulta métricas Prometheus y estado en {{url}}/metrics y {{url}}/healthz.'
    ],
    notes: [
      'Configurado en modo standalone con etcd embebido y almacenamiento local para reducir complejidad y RAM.'
    ]
  },

  // --- Auth / IAM & Seguridad (+7) -----------------------------------------
  {
    id: 'authelia',
    name: 'Authelia',
    category: 'seguridad',
    summary: 'Servidor ligero de autenticación 2FA/Passkeys y SSO (OIDC + Forward Auth) para tu proxy.',
    description:
      'Protege cualquier servicio web con inicio de sesión único, TOTP, llaves WebAuthn y reglas ' +
      'de acceso granulares sobre PostgreSQL y Valkey en una fracción de memoria.',
    website: 'https://www.authelia.com',
    licence: 'Apache-2.0',
    tags: ['sso', '2fa', 'oidc', 'passkeys', 'forward-auth', 'seguridad'],
    database: { engine: 'postgres', dbName: 'authelia', username: 'authelia', memoryMb: 256 },
    secrets: {
      AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET: { bytes: 32, encoding: 'hex' },
      AUTHELIA_SESSION_SECRET: { bytes: 32, encoding: 'hex' },
      AUTHELIA_STORAGE_ENCRYPTION_KEY: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [makeValkeySidecar(128)],
    app: {
      image: 'authelia/authelia:4.39.1',
      port: 9091,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        TZ: '{{tz}}',
        AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET: '{{secret.AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET}}',
        AUTHELIA_SESSION_SECRET: '{{secret.AUTHELIA_SESSION_SECRET}}',
        AUTHELIA_STORAGE_ENCRYPTION_KEY: '{{secret.AUTHELIA_STORAGE_ENCRYPTION_KEY}}',
        AUTHELIA_STORAGE_POSTGRES_ADDRESS: 'tcp://{{db.host}}:{{db.port}}',
        AUTHELIA_STORAGE_POSTGRES_DATABASE: '{{db.name}}',
        AUTHELIA_STORAGE_POSTGRES_USERNAME: '{{db.user}}',
        AUTHELIA_STORAGE_POSTGRES_PASSWORD: '{{db.password}}',
        AUTHELIA_SESSION_REDIS_HOST: '{{sidecar.valkey.host}}',
        AUTHELIA_SESSION_REDIS_PORT: '6379'
      },
      files: [
        {
          name: 'configuration.yml',
          path: '/config/configuration.yml',
          content:
            'theme: auto\n' +
            'server:\n' +
            '  address: tcp://:9091\n' +
            'log:\n' +
            '  level: info\n' +
            'authentication_backend:\n' +
            '  file:\n' +
            '    path: /data/users_database.yml\n' +
            'access_control:\n' +
            '  default_policy: two_factor\n' +
            'session:\n' +
            '  cookies:\n' +
            '    - domain: localhost\n' +
            '      authelia_url: http://localhost:9091\n' +
            'notifier:\n' +
            '  filesystem:\n' +
            '    filename: /data/notification.txt\n'
        }
      ],
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/api/health', expect: [200] }
    },
    nextSteps: [
      'Crea tu archivo `/data/users_database.yml` dentro del volumen (usando `authelia crypto hash generate argon2`).',
      'Asigna un dominio HTTPS y ajusta `session.cookies` si proteges múltiples subdominios.'
    ],
    notes: [
      'Los secretos criptográficos se inyectan exclusivamente por variables de entorno (nunca en texto plano en `configuration.yml`).'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'zitadel',
    name: 'Zitadel',
    category: 'seguridad',
    summary: 'Plataforma IAM cloud-native en Go con OIDC, SAML 2.0, Passkeys, multitenancy y auditoría.',
    description:
      'Alternativa moderna y ultraligera a Auth0 y Keycloak con trazabilidad completa de eventos, ' +
      'organizaciones aisladas y APIs gRPC/REST sobre PostgreSQL.',
    website: 'https://zitadel.com',
    licence: 'Apache-2.0',
    tags: ['iam', 'oidc', 'saml', 'sso', 'passkeys', 'auth0'],
    database: { engine: 'postgres', dbName: 'zitadel', username: 'zitadel', memoryMb: 512 },
    secrets: {
      // Zitadel exige exactamente 32 caracteres para su clave maestra.
      ZITADEL_MASTERKEY: { bytes: 16, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/zitadel/zitadel:v2.71.6',
      port: 8080,
      memoryMb: 512,
      cpus: 1,
      command: ['start-from-init', '--masterkeyFromEnv'],
      env: {
        ZITADEL_MASTERKEY: '{{secret.ZITADEL_MASTERKEY}}',
        ZITADEL_EXTERNALDOMAIN: '{{host}}',
        ZITADEL_EXTERNALPORT: '443',
        ZITADEL_EXTERNALSECURE: '{{isHttps}}',
        ZITADEL_TLS_ENABLED: 'false',
        ZITADEL_DATABASE_POSTGRES_HOST: '{{db.host}}',
        ZITADEL_DATABASE_POSTGRES_PORT: '{{db.port}}',
        ZITADEL_DATABASE_POSTGRES_DATABASE: '{{db.name}}',
        ZITADEL_DATABASE_POSTGRES_USER_USERNAME: '{{db.user}}',
        ZITADEL_DATABASE_POSTGRES_USER_PASSWORD: '{{db.password}}',
        ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE: 'disable',
        ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME: '{{db.user}}',
        ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD: '{{db.password}}',
        ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE: 'disable'
      },
      volumes: [],
      readiness: { path: '/debug/healthz', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}}/ui/console e inicia sesión con el usuario inicial (`zitadel-admin@zitadel.<dominio>` / `Password1!`) y cámbiala de inmediato.',
      'Asigna un dominio HTTPS antes de emitir tokens OIDC en producción.'
    ],
    notes: [
      'Zitadel vincula su dominio externo al inicializar la base de datos: recomienda instalarlo directamente con dominio.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'logto',
    name: 'Logto',
    category: 'seguridad',
    summary: 'Infraestructura de identidad moderna (alternativa a Clerk/Auth0) con SDKs y consola web.',
    description:
      'Autenticación lista para apps web y móviles con login social, magic links, RBAC, MFA, ' +
      'organizaciones B2B y consola de administración en el puerto auxiliar 3002.',
    website: 'https://logto.io',
    licence: 'MPL-2.0',
    tags: ['auth', 'oidc', 'clerk', 'auth0', 'rbac', 'identidad'],
    database: { engine: 'postgres', dbName: 'logto', username: 'logto', memoryMb: 512 },
    secrets: {},
    app: {
      image: 'svhd/logto:1.27.0',
      port: 3001,
      extraPorts: [{ containerPort: 3002, label: 'Admin Console' }],
      memoryMb: 1024,
      cpus: 1,
      command: ['sh', '-c', 'npm run cli db seed -- --swe && npm start'],
      env: {
        TRUST_PROXY_HEADER: '1',
        DB_URL: '{{db.url}}',
        ENDPOINT: '{{url}}',
        ADMIN_ENDPOINT: 'http://127.0.0.1:3002'
      },
      volumes: [],
      readiness: { path: '/api/status', expect: [200, 204], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre la consola de administración (puerto auxiliar 3002) para crear tu cuenta administradora.',
      'Registra tu primera aplicación OIDC y copia el `App ID` en tu frontend o backend.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'twofauth',
    name: '2FAuth',
    category: 'seguridad',
    summary: 'Gestor web autohospedado para códigos 2FA (TOTP/HOTP) con escáner QR y Passkeys.',
    description:
      'Alternativa privada a Authy y Google Authenticator accesible desde cualquier navegador o ' +
      'PWA móvil, con base de datos SQLite cifrada mediante `APP_KEY` única.',
    website: 'https://docs.2fauth.app',
    licence: 'AGPLv3',
    tags: ['2fauth', '2fa', 'totp', 'otp', 'mfa', 'seguridad'],
    database: null,
    secrets: {
      APP_KEY: { bytes: 16, encoding: 'hex' }
    },
    app: {
      image: '2fauth/2fauth:5.4.3',
      port: 8000,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        APP_NAME: '2FAuth',
        APP_ENV: 'production',
        APP_DEBUG: 'false',
        APP_URL: '{{url}}',
        APP_KEY: '{{secret.APP_KEY}}',
        IS_DEMO_APP: 'false',
        TRUSTED_PROXIES: '*',
        AUTHENTICATION_GUARD: 'web-guard'
      },
      volumes: [{ name: 'data', path: '/2fauth' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}} para registrar tu cuenta administradora y desactivar registros adicionales.',
      'Guarda una copia de `APP_KEY` desde «Credenciales»: sin ella no se pueden descifrar los secretos TOTP.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'headscale',
    name: 'Headscale',
    category: 'seguridad',
    summary: 'Servidor de control autohospedado y open-source compatible con clientes oficiales Tailscale.',
    description:
      'Coordina tu propia red mesh WireGuard privada sin depender del plano de control en la nube ' +
      'de Tailscale ni abrir puertos peligrosos en tus nodos internos.',
    website: 'https://headscale.net',
    licence: 'BSD-3-Clause',
    tags: ['vpn', 'tailscale', 'wireguard', 'mesh', 'red', 'seguridad'],
    database: null,
    secrets: {},
    app: {
      image: 'headscale/headscale:0.25.1',
      port: 8080,
      memoryMb: 256,
      cpus: 0.5,
      command: ['serve'],
      env: {
        TZ: '{{tz}}'
      },
      files: [
        {
          name: 'config.yaml',
          path: '/etc/headscale/config.yaml',
          content:
            'server_url: http://127.0.0.1:8080\n' +
            'listen_addr: 0.0.0.0:8080\n' +
            'metrics_listen_addr: 127.0.0.1:9090\n' +
            'noise:\n' +
            '  private_key_path: /var/lib/headscale/noise_private.key\n' +
            'prefixes:\n' +
            '  v4: 100.64.0.0/10\n' +
            '  v6: fd7a:115c:a1e0::/48\n' +
            'derp:\n' +
            '  server:\n' +
            '    enabled: false\n' +
            '  urls:\n' +
            '    - https://controlplane.tailscale.com/derpmap/default\n' +
            '  auto_update_enabled: true\n' +
            '  update_frequency: 24h\n' +
            'database:\n' +
            '  type: sqlite\n' +
            '  sqlite:\n' +
            '    path: /var/lib/headscale/db.sqlite\n' +
            'dns:\n' +
            '  magic_dns: true\n' +
            '  base_domain: culkibo.internal\n'
        }
      ],
      volumes: [{ name: 'data', path: '/var/lib/headscale' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Crea tu primer usuario dentro del contenedor con `headscale users create mi-red`.',
      'Asigna un dominio HTTPS y actualiza `server_url` o pasa `HEADSCALE_SERVER_URL={{url}}` en Variables.'
    ],
    notes: [
      'Headscale actúa únicamente como plano de control HTTP/HTTPS (no necesita privilegios NET_ADMIN ni `docker.sock`).'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'guacamole',
    name: 'Apache Guacamole',
    category: 'seguridad',
    summary: 'Pasarela de escritorio remoto sin cliente (RDP, VNC y SSH) directamente desde el navegador.',
    description:
      'Accede de forma centralizada y auditada a servidores Linux y escritorios Windows vía HTML5 ' +
      'con el demonio `guacd` y autenticación persistente en PostgreSQL.',
    website: 'https://guacamole.apache.org',
    licence: 'Apache-2.0',
    tags: ['rdp', 'vnc', 'ssh', 'escritorio remoto', 'bastion', 'seguridad'],
    database: { engine: 'postgres', dbName: 'guacamole', username: 'guacamole', memoryMb: 512 },
    secrets: {},
    sidecars: [
      {
        name: 'guacd',
        image: 'guacamole/guacd:1.5.5',
        memoryMb: 512,
        cpus: 1,
        coupledWithApp: true,
        coupledTagOnly: true,
        env: {},
        volumes: [],
        readiness: { type: 'tcp', port: 4822, timeoutMs: 30000 }
      }
    ],
    app: {
      image: 'guacamole/guacamole:1.5.5',
      port: 8080,
      memoryMb: 1024,
      cpus: 1,
      env: {
        GUACD_HOSTNAME: '{{sidecar.guacd.host}}',
        GUACD_PORT: '4822',
        POSTGRESQL_HOSTNAME: '{{db.host}}',
        POSTGRESQL_PORT: '{{db.port}}',
        POSTGRESQL_DATABASE: '{{db.name}}',
        POSTGRESQL_USER: '{{db.user}}',
        POSTGRESQL_PASSWORD: '{{db.password}}',
        POSTGRESQL_AUTO_CREATE_ACCOUNTS: 'true'
      },
      volumes: [{ name: 'home', path: '/etc/guacamole' }],
      readiness: { path: '/guacamole/', expect: [200, 302], timeoutMs: 180000 }
    },
    nextSteps: [
      'Inicializa el esquema SQL de Guacamole en la BD gestionada (`initdb.sh --postgresql`) si es el primer arranque.',
      'Abre {{url}}/guacamole/ e inicia sesión con `guacadmin` / `guacadmin`, cambiando la contraseña al instante.'
    ],
    notes: [
      'Cambia la contraseña por defecto `guacadmin` y activa TOTP antes de exponer Guacamole en internet.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'adguard-home',
    name: 'AdGuard Home',
    category: 'seguridad',
    summary: 'Bloqueador DNS de anuncios y rastreadores con soporte DoH/DoT y panel de estadísticas.',
    description:
      'Filtra dominios maliciosos, telemetría y publicidad con listas personalizables, reescrituras ' +
      'DNS locales y panel web protegido.',
    website: 'https://adguard.com/en/adguard-home/overview.html',
    licence: 'GPLv3',
    tags: ['dns', 'adblock', 'privacidad', 'doh', 'red', 'seguridad'],
    database: null,
    secrets: {},
    app: {
      image: 'adguard/adguardhome:v0.107.59',
      port: 3000,
      extraPorts: [{ containerPort: 80, label: 'Panel Web (post-setup)' }],
      memoryMb: 256,
      cpus: 0.5,
      env: {
        TZ: '{{tz}}'
      },
      volumes: [
        { name: 'work', path: '/opt/adguardhome/work' },
        { name: 'conf', path: '/opt/adguardhome/conf' }
      ],
      readiness: { path: '/', expect: [200, 302, 307] }
    },
    nextSteps: [
      'Abre {{url}} para completar el asistente inicial en el puerto 3000 y fijar tu usuario y contraseña.',
      'Usa DNS-over-HTTPS (DoH) detrás de Caddy para filtrar tráfico de forma cifrada sin exponer el puerto 53 abierto.'
    ],
    notes: [
      'Por seguridad Culkibo publica los puertos solo en `127.0.0.1`: para clientes externos usa DoH tras tu dominio HTTPS.'
    ]
  },

  // --- Productividad, Documentación y Finanzas (+10) -----------------------
  {
    id: 'outline',
    name: 'Outline',
    category: 'docs',
    summary: 'Base de conocimiento y wiki colaborativa ultrarrápida para equipos (alternativa a Notion).',
    description:
      'Editor en tiempo real con Markdown, colecciones jerárquicas, búsqueda instantánea, ' +
      'comentarios y SSO sobre PostgreSQL y Valkey.',
    website: 'https://www.getoutline.com',
    licence: 'BSL 1.1 (código fuente disponible)',
    tags: ['wiki', 'notion', 'confluence', 'documentacion', 'equipos'],
    database: { engine: 'postgres', dbName: 'outline', username: 'outline', memoryMb: 512 },
    secrets: {
      SECRET_KEY: { bytes: 32, encoding: 'hex' },
      UTILS_SECRET: { bytes: 32, encoding: 'hex' }
    },
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'docker.getoutline.com/outlinewiki/outline:0.82.0',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        NODE_ENV: 'production',
        URL: '{{url}}',
        PORT: '3000',
        SECRET_KEY: '{{secret.SECRET_KEY}}',
        UTILS_SECRET: '{{secret.UTILS_SECRET}}',
        DATABASE_URL: '{{db.url}}',
        PGSSLMODE: 'disable',
        REDIS_URL: 'redis://{{sidecar.valkey.host}}:6379',
        FILE_STORAGE: 'local',
        FILE_STORAGE_LOCAL_ROOT_DIR: '/var/lib/outline/data',
        FILE_STORAGE_UPLOAD_MAX_SIZE: '26214400',
        FORCE_HTTPS: '{{isHttps}}',
        DEFAULT_LANGUAGE: 'es_ES'
      },
      volumes: [{ name: 'data', path: '/var/lib/outline/data' }],
      readiness: { path: '/_health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Configura un proveedor OIDC (Authentik, Keycloak, Pocket ID o Google) en Variables: Outline requiere SSO para iniciar sesión.',
      'Abre {{url}} tras guardar tus variables OIDC.'
    ],
    notes: [
      'Outline no incluye login local con contraseña por diseño: conéctalo a Authentik, Keycloak o Pocket ID desde el catálogo.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'affine',
    name: 'AFFiNE',
    category: 'docs',
    summary: 'Espacio de trabajo local-first que une documentos, pizarras infinitas y bases de datos.',
    description:
      'Alternativa open-source a Notion y Miro con edición colaborativa offline-first, modo pizarra ' +
      'Edgeless y almacenamiento persistente sobre PostgreSQL y Valkey.',
    website: 'https://affine.pro',
    licence: 'MIT (edición comunitaria)',
    tags: ['notion', 'miro', 'pizarra', 'documentos', 'workspace'],
    database: { engine: 'postgres', dbName: 'affine', username: 'affine', memoryMb: 512 },
    secrets: {},
    sidecars: [makeValkeySidecar(256)],
    app: {
      image: 'ghcr.io/toeverything/affine:0.20.4',
      port: 3010,
      memoryMb: 1536,
      cpus: 2,
      env: {
        NODE_ENV: 'production',
        AFFINE_SERVER_EXTERNAL_URL: '{{url}}',
        DATABASE_URL: '{{db.url}}',
        REDIS_SERVER_HOST: '{{sidecar.valkey.host}}',
        REDIS_SERVER_PORT: '6379',
        AFFINE_INDEXER_ENABLED: 'false'
      },
      volumes: [
        { name: 'storage', path: '/root/.affine/storage' },
        { name: 'config', path: '/root/.affine/config' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}}/admin/setup en el primer arranque para crear la cuenta administradora.',
      'Conecta los clientes de escritorio de AFFiNE a tu instancia en {{url}}.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'calcom',
    name: 'Cal.com',
    category: 'productividad',
    summary: 'Infraestructura abierta de reservas y agendas (alternativa autohospedada a Calendly).',
    description:
      'Publica enlaces de reserva sincronizados con Google Calendar, CalDAV o Outlook, con reglas ' +
      'de disponibilidad, zonas horarias y flujos automatizados sobre PostgreSQL.',
    website: 'https://cal.com',
    licence: 'AGPLv3',
    tags: ['calendario', 'reservas', 'calendly', 'citas', 'productividad'],
    database: { engine: 'postgres', dbName: 'calcom', username: 'calcom', memoryMb: 512 },
    secrets: {
      NEXTAUTH_SECRET: { bytes: 32, encoding: 'base64' },
      CALENDSO_ENCRYPTION_KEY: { bytes: 24, encoding: 'base64' }
    },
    app: {
      image: 'calcom/cal.com:v5.1.10',
      port: 3000,
      memoryMb: 2048,
      cpus: 2,
      env: {
        DATABASE_URL: '{{db.url}}',
        DATABASE_DIRECT_URL: '{{db.url}}',
        NEXT_PUBLIC_WEBAPP_URL: '{{url}}',
        NEXTAUTH_URL: '{{url}}',
        NEXTAUTH_SECRET: '{{secret.NEXTAUTH_SECRET}}',
        CALENDSO_ENCRYPTION_KEY: '{{secret.CALENDSO_ENCRYPTION_KEY}}',
        NEXT_PUBLIC_LICENSE_CONSENT: 'agree',
        CALCOM_TELEMETRY_DISABLED: '1'
      },
      volumes: [],
      readiness: { path: '/api/health', expect: [200], timeoutMs: 240000 }
    },
    nextSteps: [
      'Abre {{url}}/auth/setup para completar la configuración inicial y crear tu cuenta.',
      'Configura SMTP (`EMAIL_SERVER_HOST`, `EMAIL_FROM`) en Variables para enviar confirmaciones de reserva.'
    ],
    notes: [
      'El primer arranque aplica migraciones Prisma y compila recursos: requiere 2 GB de RAM y 1–3 minutos.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'docuseal',
    name: 'DocuSeal',
    category: 'productividad',
    summary: 'Firma electrónica de documentos y formularios PDF (alternativa abierta a DocuSign).',
    description:
      'Crea plantillas PDF arrastrando campos de firma, envía contratos a múltiples firmantes con ' +
      'registro de auditoría y almacena los documentos firmados en tu servidor.',
    website: 'https://www.docuseal.com',
    licence: 'AGPLv3',
    tags: ['firma', 'pdf', 'contratos', 'docusign', 'documentos'],
    database: { engine: 'postgres', dbName: 'docuseal', username: 'docuseal', memoryMb: 512 },
    secrets: {
      SECRET_KEY_BASE: { bytes: 64, encoding: 'hex' }
    },
    app: {
      image: 'docuseal/docuseal:2.0.2',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        SECRET_KEY_BASE: '{{secret.SECRET_KEY_BASE}}',
        FORCE_SSL: '{{isHttps}}'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/up', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar tu cuenta de administración y subir tu primera plantilla PDF.',
      'Configura SMTP dentro de Ajustes → Correo para enviar solicitudes de firma automáticamente.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'actual-budget',
    name: 'Actual Budget',
    category: 'productividad',
    summary: 'Finanzas personales local-first con presupuesto por sobres y sincronización cifrada.',
    description:
      'Alternativa rápida y privada a YNAB con soporte de importación bancaria, informes de flujo ' +
      'de caja y cifrado extremo a extremo en menos de 256 MB de RAM.',
    website: 'https://actualbudget.org',
    licence: 'MIT',
    tags: ['finanzas', 'presupuesto', 'ynab', 'contabilidad', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'actualbudget/actual-server:25.4.0',
      port: 5006,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        ACTUAL_PORT: '5006',
        ACTUAL_DATA_DIR: '/data'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}} bajo HTTPS para establecer la contraseña inicial del servidor.',
      'Crea tu primer presupuesto o importa tu historial desde YNAB/CSV.'
    ],
    notes: [
      'Actual Budget usa SharedArrayBuffer en el navegador: requiere dominio HTTPS para funcionar fuera de `127.0.0.1`.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'firefly-iii',
    name: 'Firefly III',
    category: 'productividad',
    summary: 'Gestor completo de finanzas personales por partida doble con reglas, metas e informes.',
    description:
      'Controla cuentas bancarias, tarjetas, presupuestos recurrentes, facturas y etiquetas con ' +
      'API REST completa sobre MariaDB aislada.',
    website: 'https://www.firefly-iii.org',
    licence: 'AGPLv3',
    tags: ['finanzas', 'gastos', 'banca', 'presupuesto', 'contabilidad'],
    database: { engine: 'mariadb', dbName: 'firefly', username: 'firefly', memoryMb: 512 },
    secrets: {
      // Firefly III exige exactamente 32 caracteres para APP_KEY.
      APP_KEY: { bytes: 16, encoding: 'hex' }
    },
    app: {
      image: 'fireflyiii/core:version-6.2.10',
      port: 8080,
      memoryMb: 512,
      cpus: 1,
      env: {
        APP_ENV: 'production',
        APP_DEBUG: 'false',
        APP_URL: '{{url}}',
        APP_KEY: '{{secret.APP_KEY}}',
        TZ: '{{tz}}',
        DEFAULT_LANGUAGE: 'es_ES',
        DB_CONNECTION: 'mysql',
        DB_HOST: '{{db.host}}',
        DB_PORT: '{{db.port}}',
        DB_DATABASE: '{{db.name}}',
        DB_USERNAME: '{{db.user}}',
        DB_PASSWORD: '{{db.password}}',
        TRUSTED_PROXIES: '**'
      },
      volumes: [{ name: 'upload', path: '/var/www/html/storage/upload' }],
      readiness: { path: '/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar tu primera cuenta de propietario.',
      'Guarda `APP_KEY` desde «Credenciales» junto a tus copias de seguridad.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'karakeep',
    name: 'Karakeep',
    category: 'productividad',
    summary: 'Gestor de marcadores, notas y capturas web con auto-etiquetado IA y búsqueda instantánea.',
    description:
      'Anteriormente Hoarder: guarda enlaces, imágenes y notas rápidas con archivado automático ' +
      'de páginas, búsqueda full-text con Meilisearch y apps móviles oficiales.',
    website: 'https://karakeep.app',
    licence: 'AGPLv3',
    tags: ['marcadores', 'bookmarks', 'hoarder', 'read-later', 'ia'],
    database: null,
    secrets: {
      NEXTAUTH_SECRET: { bytes: 32, encoding: 'base64url' },
      MEILI_MASTER_KEY: { bytes: 24, encoding: 'base64url' }
    },
    sidecars: [
      {
        name: 'meilisearch',
        image: 'getmeili/meilisearch:v1.13.3',
        memoryMb: 512,
        cpus: 0.5,
        env: {
          MEILI_NO_ANALYTICS: 'true',
          MEILI_MASTER_KEY: '{{secret.MEILI_MASTER_KEY}}'
        },
        volumes: [{ name: 'data', path: '/meili_data' }],
        readiness: { type: 'tcp', port: 7700, timeoutMs: 30000 }
      }
    ],
    app: {
      image: 'ghcr.io/karakeep-app/karakeep:0.24.1',
      port: 3000,
      memoryMb: 1024,
      cpus: 1,
      env: {
        NEXTAUTH_URL: '{{url}}',
        NEXTAUTH_SECRET: '{{secret.NEXTAUTH_SECRET}}',
        MEILI_ADDR: 'http://{{sidecar.meilisearch.host}}:7700',
        MEILI_MASTER_KEY: '{{secret.MEILI_MASTER_KEY}}',
        DATA_DIR: '/data',
        DISABLE_NEW_RELEASE_CHECK: 'true'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/api/health', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Abre {{url}} para crear tu cuenta y luego añade `DISABLE_SIGNUPS=true` en Variables si es uso privado.',
      'Opcionalmente añade `OPENAI_API_KEY` u `OLLAMA_BASE_URL` en Variables para auto-etiquetado por IA.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'linkwarden',
    name: 'Linkwarden',
    category: 'productividad',
    summary: 'Gestor colaborativo de marcadores que archiva capturas y copias permanentes de cada web.',
    description:
      'Preserva artículos, PDFs y páginas completas contra enlaces rotos, organízalos por ' +
      'colecciones compartidas y sincronízalos con su extensión de navegador sobre PostgreSQL.',
    website: 'https://linkwarden.app',
    licence: 'AGPLv3',
    tags: ['marcadores', 'archivo', 'bookmarks', 'colecciones', 'productividad'],
    database: { engine: 'postgres', dbName: 'linkwarden', username: 'linkwarden', memoryMb: 512 },
    secrets: {
      NEXTAUTH_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'ghcr.io/linkwarden/linkwarden:v2.9.3',
      port: 3000,
      memoryMb: 1536,
      cpus: 1,
      env: {
        DATABASE_URL: '{{db.url}}',
        NEXTAUTH_URL: '{{url}}/api/v1/auth',
        NEXTAUTH_SECRET: '{{secret.NEXTAUTH_SECRET}}'
      },
      volumes: [{ name: 'data', path: '/data/data' }],
      readiness: { path: '/', expect: [200, 302, 307], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar tu primera cuenta y crear colecciones.',
      'Instala la extensión de Linkwarden en tu navegador apuntando a {{url}}.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'linkding',
    name: 'Linkding',
    category: 'productividad',
    summary: 'Gestor minimalista de marcadores con instantáneas HTML, etiquetas y consumo mínimo.',
    description:
      'Guarda miles de enlaces con búsqueda instantánea, importación desde Pocket o navegadores ' +
      'y API REST en menos de 256 MB de RAM con SQLite integrado.',
    website: 'https://linkding.link',
    licence: 'MIT',
    tags: ['marcadores', 'bookmarks', 'ligero', 'archivo'],
    database: null,
    secrets: {
      LD_SUPERUSER_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'sissbruecker/linkding:1.40.0',
      port: 9090,
      memoryMb: 256,
      cpus: 0.5,
      env: {
        LD_SUPERUSER_NAME: 'admin',
        LD_SUPERUSER_PASSWORD: '{{secret.LD_SUPERUSER_PASSWORD}}',
        LD_DISABLE_BACKGROUND_TASKS: 'False'
      },
      volumes: [{ name: 'data', path: '/etc/linkding/data' }],
      readiness: { path: '/health', expect: [200] }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con `LD_SUPERUSER_PASSWORD` desde «Credenciales».',
      'Instala la extensión de Linkding y configura tu token API desde Ajustes → Integraciones.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'grist',
    name: 'Grist',
    category: 'productividad',
    summary: 'Hoja de cálculo relacional con fórmulas Python, paneles interactivos y permisos por fila.',
    description:
      'Combina la agilidad de una hoja de cálculo con el rigor de una base de datos relacional ' +
      'y soporte nativo de fórmulas en Python sin dependencias externas.',
    website: 'https://www.getgrist.com',
    licence: 'Apache-2.0',
    tags: ['hojas de calculo', 'airtable', 'python', 'datos', 'tablas'],
    database: null,
    secrets: {
      GRIST_SESSION_SECRET: { bytes: 32, encoding: 'hex' }
    },
    app: {
      image: 'gristlabs/grist:1.4.2',
      port: 8484,
      memoryMb: 1024,
      cpus: 1,
      env: {
        APP_HOME_URL: '{{url}}',
        GRIST_SESSION_SECRET: '{{secret.GRIST_SESSION_SECRET}}',
        GRIST_DATA_DIR: '/persist/docs',
        GRIST_INST_DIR: '/persist',
        GRIST_SANDBOX_FLAVOR: 'unsandboxed',
        GRIST_TELEMETRY_LEVEL: 'off'
      },
      volumes: [{ name: 'persist', path: '/persist' }],
      readiness: { path: '/status', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Abre {{url}} para crear tu primer documento o importar archivos Excel/CSV.',
      'Conecta un proveedor OIDC en Variables si vas a compartir documentos en equipo.'
    ],
    notes: []
  },

  // --- DevTools, Dashboards e Infraestructura (+8) -------------------------
  {
    id: 'it-tools',
    name: 'IT-Tools',
    category: 'desarrollo',
    summary: 'Caja de herramientas web con más de 80 utilidades para desarrolladores (JWT, cron, regex, hashes).',
    description:
      'Colección ultraligera de conversores, generadores de claves, decodificadores JWT, pruebas ' +
      'regex y calculadoras de red ejecutándose 100% en local sin enviar datos a terceros.',
    website: 'https://it-tools.tech',
    licence: 'GPLv3',
    tags: ['utilidades', 'devtools', 'jwt', 'regex', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'corentinth/it-tools:2024.10.22-7ca5933',
      port: 80,
      memoryMb: 128,
      cpus: 0.25,
      env: {},
      volumes: [{ name: 'cache', path: '/var/cache/nginx' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para usar cualquiera de las utilidades directamente en el navegador.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'excalidraw',
    name: 'Excalidraw',
    category: 'desarrollo',
    summary: 'Pizarra virtual minimalista de diagramas de arquitectura con estilo trazado a mano.',
    description:
      'Diseña diagramas de sistemas, wireframes y esquemas técnicos en tu propio dominio con ' +
      'exportación SVG/PNG y privacidad total.',
    website: 'https://excalidraw.com',
    licence: 'MIT',
    tags: ['pizarra', 'diagramas', 'arquitectura', 'diseno', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'excalidraw/excalidraw:v0.18.0',
      port: 80,
      memoryMb: 128,
      cpus: 0.25,
      env: {},
      volumes: [{ name: 'cache', path: '/var/cache/nginx' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y guarda o exporta tus diagramas `.excalidraw` directamente en tu equipo.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'glance',
    name: 'Glance',
    category: 'monitorizacion',
    summary: 'Dashboard personal ultrarrápido con feeds RSS, estado de servicios, clima y marcadores.',
    description:
      'Página de inicio autohospedada escrita en Go que consume menos de 30 MB de RAM y agrega ' +
      'en un panel limpio tus servicios, fuentes RSS, repositorios y métricas sin `docker.sock`.',
    website: 'https://github.com/glanceapp/glance',
    licence: 'AGPLv3',
    tags: ['dashboard', 'homepage', 'rss', 'inicio', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'glanceapp/glance:v0.8.4',
      port: 8080,
      memoryMb: 128,
      cpus: 0.25,
      env: {
        TZ: '{{tz}}'
      },
      files: [
        {
          name: 'glance.yml',
          path: '/app/config/glance.yml',
          content:
            'pages:\n' +
            '  - name: Inicio\n' +
            '    columns:\n' +
            '      - size: full\n' +
            '        widgets:\n' +
            '          - type: clock\n' +
            '            hour-format: 24h\n' +
            '          - type: search\n' +
            '            autofocus: true\n' +
            '          - type: bookmarks\n' +
            '            groups:\n' +
            '              - title: Servicios\n' +
            '                links:\n' +
            '                  - title: Culkibo\n' +
            '                    url: http://127.0.0.1:3000\n'
        }
      ],
      volumes: [{ name: 'assets', path: '/app/assets' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para ver tu dashboard inicial.',
      'Personaliza `glance.yml` añadiendo widgets de monitorización HTTP, RSS, GitHub o marcadores.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'rabbitmq',
    name: 'RabbitMQ',
    category: 'datos',
    summary: 'Bróker de mensajes empresarial (AMQP, Streams y colas) con consola web de gestión.',
    description:
      'Desacopla microservicios y workers con colas duraderas, enrutamiento avanzado y consola ' +
      'web en el puerto principal (15672) más puerto AMQP auxiliar (5672).',
    website: 'https://www.rabbitmq.com',
    licence: 'MPL-2.0',
    tags: ['colas', 'amqp', 'mensajeria', 'broker', 'microservicios'],
    database: null,
    secrets: {
      RABBITMQ_DEFAULT_PASS: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'rabbitmq:4.0.9-management-alpine',
      port: 15672,
      extraPorts: [{ containerPort: 5672, label: 'AMQP' }],
      memoryMb: 512,
      cpus: 1,
      env: {
        RABBITMQ_DEFAULT_USER: 'culkibo',
        RABBITMQ_DEFAULT_PASS: '{{secret.RABBITMQ_DEFAULT_PASS}}'
      },
      volumes: [{ name: 'data', path: '/var/lib/rabbitmq' }],
      readiness: { path: '/', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Accede a la consola web en {{url}} con usuario «culkibo» y `RABBITMQ_DEFAULT_PASS` desde «Credenciales».',
      'Conecta tus productores/consumidores por AMQP usando el puerto auxiliar 5672.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'nats',
    name: 'NATS JetStream',
    category: 'datos',
    summary: 'Sistema de mensajería cloud-native ultrarrápido con persistencia JetStream y KV.',
    description:
      'Pub/sub, colas de trabajo, almacenamiento clave-valor y streams persistentes en un binario ' +
      'Go diminuto con endpoint HTTP de monitorización (8222) y puerto cliente 4222.',
    website: 'https://nats.io',
    licence: 'Apache-2.0',
    tags: ['mensajeria', 'pubsub', 'jetstream', 'colas', 'ligero'],
    database: null,
    secrets: {
      NATS_AUTH_TOKEN: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'nats:2.11.1-alpine',
      port: 8222,
      extraPorts: [{ containerPort: 4222, label: 'NATS Client' }],
      memoryMb: 256,
      cpus: 0.5,
      command: ['-c', '/etc/nats/nats.conf'],
      env: {
        NATS_AUTH_TOKEN: '{{secret.NATS_AUTH_TOKEN}}'
      },
      files: [
        {
          name: 'nats.conf',
          path: '/etc/nats/nats.conf',
          content:
            'port: 4222\n' +
            'http_port: 8222\n' +
            'jetstream {\n' +
            '  store_dir: /data\n' +
            '}\n' +
            'authorization {\n' +
            '  token: $NATS_AUTH_TOKEN\n' +
            '}\n'
        }
      ],
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/healthz', expect: [200] }
    },
    nextSteps: [
      'Consulta el estado y estadísticas JetStream en {{url}}/jsz y {{url}}/varz.',
      'Conecta tus clientes NATS al puerto auxiliar 4222 usando `NATS_AUTH_TOKEN` desde «Credenciales».'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'garage',
    name: 'Garage S3',
    category: 'datos',
    summary: 'Almacenamiento de objetos compatible con S3 escrito en Rust: ligero, libre y resiliente.',
    description:
      'Alternativa moderna y ultraligera a MinIO con licencia AGPLv3, bajo consumo de memoria ' +
      'y API S3 lista para copias de seguridad de Culkibo, adjuntos y activos estáticos.',
    website: 'https://garagehq.deuxfleurs.fr',
    licence: 'AGPLv3',
    tags: ['s3', 'objetos', 'rust', 'almacenamiento', 'copias', 'ligero'],
    database: null,
    secrets: {
      GARAGE_RPC_SECRET: { bytes: 32, encoding: 'hex' },
      GARAGE_ADMIN_TOKEN: { bytes: 24, encoding: 'base64url' }
    },
    app: {
      image: 'dxflrs/garage:v1.1.0',
      port: 3900,
      extraPorts: [{ containerPort: 3903, label: 'Admin API' }],
      memoryMb: 256,
      cpus: 0.5,
      env: {
        GARAGE_RPC_SECRET: '{{secret.GARAGE_RPC_SECRET}}',
        GARAGE_ADMIN_TOKEN: '{{secret.GARAGE_ADMIN_TOKEN}}'
      },
      files: [
        {
          name: 'garage.toml',
          path: '/etc/garage.toml',
          content:
            'metadata_dir = "/var/lib/garage/meta"\n' +
            'data_dir = "/var/lib/garage/data"\n' +
            'db_engine = "sqlite"\n' +
            'replication_factor = 1\n' +
            'rpc_bind_addr = "[::]:3901"\n' +
            'rpc_public_addr = "127.0.0.1:3901"\n' +
            '[s3_api]\n' +
            's3_region = "garage"\n' +
            'api_bind_addr = "[::]:3900"\n' +
            'root_domain = ".s3.garage.localhost"\n' +
            '[admin]\n' +
            'api_bind_addr = "[::]:3903"\n'
        }
      ],
      volumes: [
        { name: 'meta', path: '/var/lib/garage/meta' },
        { name: 'data', path: '/var/lib/garage/data' }
      ],
      readiness: { path: '/', expect: [200, 400, 403] }
    },
    nextSteps: [
      'Asigna el layout del nodo y crea tu primer bucket y clave S3 dentro del contenedor con `garage status`, `garage layout assign` y `garage key create`.',
      'Usa las claves generadas en Culkibo → Configuración → Almacenamiento de copias S3.'
    ],
    notes: [
      'Garage consume una fracción de la RAM de MinIO y mantiene licencia completamente abierta.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'backrest',
    name: 'Backrest',
    category: 'datos',
    summary: 'Interfaz web para copias de seguridad cifradas y deduplicadas con Restic.',
    description:
      'Programa snapshots incrementales de volúmenes y carpetas hacia S3, Backblaze B2, SFTP o ' +
      'discos locales con exploración de ficheros y restauración en un clic.',
    website: 'https://garethgeorge.github.io/backrest/',
    licence: 'GPLv3',
    tags: ['backups', 'restic', 'copias', 'cifrado', 's3'],
    database: null,
    secrets: {},
    app: {
      image: 'garethgeorge/backrest:v1.7.2',
      port: 9898,
      memoryMb: 512,
      cpus: 1,
      env: {
        TZ: '{{tz}}',
        BACKREST_DATA: '/data',
        BACKREST_CONFIG: '/config/config.json',
        XDG_CACHE_HOME: '/cache'
      },
      volumes: [
        { name: 'data', path: '/data' },
        { name: 'config', path: '/config' },
        { name: 'cache', path: '/cache' },
        { name: 'repos', path: '/repos' }
      ],
      readiness: { path: '/', expect: [200, 302] }
    },
    nextSteps: [
      'Abre {{url}} para completar el asistente inicial y activar la autenticación de Backrest.',
      'Añade tu repositorio Restic (S3, Garage, MinIO o SFTP) y crea un plan programado.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'adminer',
    name: 'Adminer',
    category: 'datos',
    summary: 'Cliente web ultraligero para administrar PostgreSQL, MySQL, MariaDB, SQLite y MongoDB.',
    description:
      'Alternativa rápida y minimalista a phpMyAdmin y pgAdmin en menos de 128 MB de RAM con ' +
      'editor SQL, exportación e importación de volcados.',
    website: 'https://www.adminer.org',
    licence: 'Apache-2.0 / GPLv2',
    tags: ['sql', 'postgres', 'mysql', 'mariadb', 'admin', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'adminer:5.2.1',
      port: 8080,
      memoryMb: 128,
      cpus: 0.5,
      env: {
        ADMINER_DESIGN: 'nette'
      },
      volumes: [{ name: 'plugins', path: '/var/www/html/plugins-enabled' }],
      readiness: { path: '/', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} e introduce las credenciales de tu base de datos.',
      'Mantén Adminer sin dominio público o detrás de SSO (Authelia/Authentik) en producción.'
    ],
    notes: []
  },

  // --- Multimedia, Libros y Sincronización (+5) ----------------------------
  {
    id: 'syncthing',
    name: 'Syncthing',
    category: 'media',
    summary: 'Sincronización continua de carpetas P2P cifrada entre servidores, ordenadores y móviles.',
    description:
      'Replica archivos en tiempo real sin nube intermediaria ni límites de tamaño, con ' +
      'versionado de ficheros, panel web (8384) y puerto de sincronización TCP (22000).',
    website: 'https://syncthing.net',
    licence: 'MPL-2.0',
    tags: ['sincronizacion', 'archivos', 'p2p', 'nube', 'backup'],
    database: null,
    secrets: {},
    app: {
      image: 'syncthing/syncthing:1.29.5',
      port: 8384,
      extraPorts: [{ containerPort: 22000, label: 'Sync TCP' }],
      memoryMb: 512,
      cpus: 1,
      env: {
        TZ: '{{tz}}',
        STGUIADDRESS: '0.0.0.0:8384'
      },
      volumes: [{ name: 'data', path: '/var/syncthing' }],
      readiness: { path: '/rest/noauth/health', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} y configura de inmediato usuario y contraseña en Acciones → Configuración → Interfaz.',
      'Vincula tus otros dispositivos intercambiando el ID de dispositivo.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'kavita',
    name: 'Kavita',
    category: 'media',
    summary: 'Servidor rápido de lectura para eBooks (EPUB/PDF), manga y cómics con soporte OPDS.',
    description:
      'Organiza bibliotecas personales de libros y cómics con progreso sincronizado, múltiples ' +
      'usuarios, lector web adaptable y soporte nativo para lectores móviles.',
    website: 'https://www.kavitareader.com',
    licence: 'GPLv3',
    tags: ['libros', 'ebooks', 'manga', 'comics', 'opds'],
    database: null,
    secrets: {},
    app: {
      image: 'jvmilazz0/kavita:0.8.5',
      port: 5000,
      memoryMb: 512,
      cpus: 1,
      env: {
        TZ: '{{tz}}'
      },
      volumes: [
        { name: 'config', path: '/kavita/config' },
        { name: 'library', path: '/books' }
      ],
      readiness: { path: '/api/health', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Abre {{url}} para crear tu cuenta administradora y añadir tu biblioteca en `/books`.',
      'Activa OPDS en Ajustes de usuario si lees desde apps externas.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'komga',
    name: 'Komga',
    category: 'media',
    summary: 'Servidor multimedia para cómics, manga y eBooks con metadatos, OPDS y API REST.',
    description:
      'Escanea colecciones CBZ/CBR/PDF/EPUB automáticamente, gestiona series y listas de lectura ' +
      'y ofrece compatibilidad con Mihon, Panels y lectores OPDS.',
    website: 'https://komga.org',
    licence: 'MIT',
    tags: ['comics', 'manga', 'ebooks', 'opds', 'biblioteca'],
    database: null,
    secrets: {},
    app: {
      image: 'gotson/komga:1.21.2',
      port: 25600,
      memoryMb: 1024,
      cpus: 1,
      env: {
        TZ: '{{tz}}',
        JAVA_TOOL_OPTIONS: '-Xmx768m'
      },
      volumes: [
        { name: 'config', path: '/config' },
        { name: 'data', path: '/data' }
      ],
      readiness: { path: '/actuator/health', expect: [200], timeoutMs: 180000 }
    },
    nextSteps: [
      'Abre {{url}} para registrar la cuenta inicial de administración.',
      'Apunta tu primera biblioteca a `/data` para indexar tus archivos.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'calibre-web',
    name: 'Calibre-Web',
    category: 'media',
    summary: 'Biblioteca web limpia para explorar, leer y enviar a Kindle/Kobo tu colección Calibre.',
    description:
      'Interfaz web ligera sobre una base `metadata.db` de Calibre con estanterías, descarga ' +
      'EPUB/PDF, sincronización Kobo y feed OPDS.',
    website: 'https://github.com/janeczku/calibre-web',
    licence: 'GPLv3',
    tags: ['libros', 'calibre', 'ebooks', 'kobo', 'kindle'],
    database: null,
    secrets: {},
    app: {
      image: 'lscr.io/linuxserver/calibre-web:0.6.24-ls300',
      port: 8083,
      memoryMb: 512,
      cpus: 0.5,
      env: {
        PUID: '1000',
        PGID: '1000',
        TZ: '{{tz}}'
      },
      volumes: [
        { name: 'config', path: '/config' },
        { name: 'books', path: '/books' }
      ],
      readiness: { path: '/', expect: [200, 302], timeoutMs: 120000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con `admin` / `admin123` y cambia la contraseña de inmediato.',
      'Coloca tu carpeta de biblioteca Calibre (`metadata.db`) en el volumen `/books`.'
    ],
    notes: [
      'La contraseña inicial la fija el proyecto (`admin123`): cámbiala en el primer inicio.'
    ]
  },

  // -------------------------------------------------------------------------
  {
    id: 'owncast',
    name: 'Owncast',
    category: 'media',
    summary: 'Servidor autohospedado de streaming en directo con chat integrado (alternativa a Twitch).',
    description:
      'Recibe tu emisión desde OBS vía RTMP (puerto auxiliar 1935) y sírvela por HLS en tu ' +
      'propio dominio con chat en vivo, federación ActivityPub y webhooks.',
    website: 'https://owncast.online',
    licence: 'MIT',
    tags: ['streaming', 'video', 'twitch', 'rtmp', 'obs', 'chat'],
    database: null,
    secrets: {},
    app: {
      image: 'owncast/owncast:0.2.2',
      port: 8080,
      extraPorts: [{ containerPort: 1935, label: 'RTMP Ingest' }],
      memoryMb: 1024,
      cpus: 2,
      env: {
        TZ: '{{tz}}'
      },
      volumes: [{ name: 'data', path: '/app/data' }],
      readiness: { path: '/api/status', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Abre {{url}}/admin e inicia sesión con `admin` / `abc123` (clave inicial de Owncast) y cámbiala de inmediato.',
      'Configura OBS apuntando a `rtmp://127.0.0.1:<puerto-1935>/live` con tu clave de emisión.'
    ],
    notes: [
      'Cambiar la clave de administración y emisión en `/admin` es imprescindible antes de publicar tu dominio.'
    ]
  },

  // --- Monitorización y RSS (+3) -------------------------------------------
  {
    id: 'openobserve',
    name: 'OpenObserve',
    category: 'monitorizacion',
    summary: 'Plataforma unificada en Rust de logs, métricas y trazas OTel (alternativa a Datadog/ELK).',
    description:
      'Ingiere telemetría OpenTelemetry, logs JSON y métricas Prometheus con búsqueda SQL/PromQL, ' +
      'alertas y paneles en un único binario Rust de altísima eficiencia.',
    website: 'https://openobserve.ai',
    licence: 'AGPLv3',
    tags: ['logs', 'metricas', 'trazas', 'otel', 'datadog', 'rust'],
    database: null,
    secrets: {
      ZO_ROOT_USER_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'public.ecr.aws/zinclabs/openobserve:v0.14.6',
      port: 5080,
      memoryMb: 1024,
      cpus: 1,
      env: {
        ZO_ROOT_USER_EMAIL: 'admin@culkibo.local',
        ZO_ROOT_USER_PASSWORD: '{{secret.ZO_ROOT_USER_PASSWORD}}',
        ZO_DATA_DIR: '/data',
        ZO_TELEMETRY: 'false'
      },
      volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/healthz', expect: [200], timeoutMs: 120000 }
    },
    nextSteps: [
      'Inicia sesión en {{url}} con `admin@culkibo.local` y `ZO_ROOT_USER_PASSWORD` desde «Credenciales».',
      'Copia las instrucciones de ingesta OpenTelemetry/Vector desde la pestaña Ingestion.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'alertmanager',
    name: 'Alertmanager',
    category: 'monitorizacion',
    summary: 'Enrutamiento, agrupación y silenciamiento de alertas de Prometheus hacia Slack, correo o webhooks.',
    description:
      'Deduplica alertas repetitivas, gestiona inhibiciones y ventanas de mantenimiento y entrega ' +
      'avisos fiables a tus canales de guardia en menos de 128 MB de RAM.',
    website: 'https://prometheus.io/docs/alerting/latest/alertmanager/',
    licence: 'Apache-2.0',
    tags: ['alertas', 'prometheus', 'guardias', 'webhooks', 'ligero'],
    database: null,
    secrets: {},
    app: {
      image: 'prom/alertmanager:v0.28.1',
      port: 9093,
      memoryMb: 128,
      cpus: 0.25,
      command: [
        '--config.file=/etc/alertmanager/alertmanager.yml',
        '--storage.path=/alertmanager'
      ],
      env: {},
      files: [
        {
          name: 'alertmanager.yml',
          path: '/etc/alertmanager/alertmanager.yml',
          content:
            'route:\n' +
            '  group_by: ["alertname"]\n' +
            '  group_wait: 30s\n' +
            '  group_interval: 5m\n' +
            '  repeat_interval: 4h\n' +
            '  receiver: "default"\n' +
            'receivers:\n' +
            '  - name: "default"\n'
        }
      ],
      volumes: [{ name: 'data', path: '/alertmanager' }],
      readiness: { path: '/-/healthy', expect: [200] }
    },
    nextSteps: [
      'Abre {{url}} para revisar alertas activas y gestionar silencios.',
      'Configura tus receptores (webhook, Telegram, Slack o SMTP) en `alertmanager.yml`.'
    ],
    notes: []
  },

  // -------------------------------------------------------------------------
  {
    id: 'miniflux',
    name: 'Miniflux',
    category: 'contenido',
    summary: 'Lector RSS/Atom minimalista en Go, rapidísimo y compatible con Fever y Google Reader API.',
    description:
      'Sigue cientos de blogs, newsletters y podcasts sin distracciones ni rastreadores, con ' +
      'migraciones automáticas sobre PostgreSQL y consumo mínimo.',
    website: 'https://miniflux.app',
    licence: 'Apache-2.0',
    tags: ['rss', 'atom', 'lector', 'noticias', 'ligero'],
    database: { engine: 'postgres', dbName: 'miniflux', username: 'miniflux', memoryMb: 256 },
    secrets: {
      ADMIN_PASSWORD: { bytes: 18, encoding: 'base64url' }
    },
    app: {
      image: 'miniflux/miniflux:2.2.7',
      port: 8080,
      memoryMb: 128,
      cpus: 0.25,
      env: {
        DATABASE_URL: '{{db.url}}',
        RUN_MIGRATIONS: '1',
        CREATE_ADMIN: '1',
        ADMIN_USERNAME: 'admin',
        ADMIN_PASSWORD: '{{secret.ADMIN_PASSWORD}}',
        BASE_URL: '{{url}}'
      },
      volumes: [],
      readiness: { path: '/healthcheck', expect: [200] }
    },
    nextSteps: [
      'Inicia sesión en {{url}} como «admin» con `ADMIN_PASSWORD` desde «Credenciales».',
      'Importa tu archivo OPML o conecta clientes móviles (Reeder, NetNewsWire) mediante la API Fever/Google Reader.'
    ],
    notes: []
  }
];

// ---------------------------------------------------------------------------
// Validación del formato
// ---------------------------------------------------------------------------

/**
 * Lista blanca para todo lo que acaba dentro de un nombre de contenedor, de
 * volumen o de red. Mismo criterio que `databaseManager`: si no encaja, se
 * rechaza; no se escapa ni se sanea.
 */
const ID_RE = /^[a-z][a-z0-9-]{1,31}$/;
const VOLUME_KEY_RE = /^[a-z][a-z0-9_]{0,31}$/;
const IMAGE_RE = /^[a-z0-9][a-z0-9._\-/]{0,190}:[a-zA-Z0-9._-]{1,128}$/;
const FLOATING_TAG_RE = /:(latest|stable|main|master|edge|nightly|release|dev|canary|lts|community)$/i;
const FILE_NAME_RE = /^[a-zA-Z0-9._-]+$/;
const SHM_SIZE_RE = /^\d+[mg]$/i;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,254}$/;

/**
 * Comprueba una plantilla entera y devuelve la lista de problemas.
 *
 * Es deliberadamente severo. El valor del catálogo no está en cuántas
 * plantillas hay, sino en que cada una haya pasado por aquí: imagen fijada
 * (nunca `latest` ni etiquetas móviles), límites de memoria y CPU, al menos un
 * volumen si el servicio guarda estado, sonda declarada y ningún secreto escrito a mano.
 * @param {any} tpl
 * @returns {string[]}
 */
function validateTemplate(tpl) {
  const problems = [];
  const fail = (msg) => problems.push(msg);

  if (!tpl || typeof tpl !== 'object') return ['La plantilla no es un objeto'];
  if (!ID_RE.test(String(tpl.id || ''))) fail(`id inválido: ${tpl.id}`);
  for (const field of ['name', 'summary', 'description', 'licence', 'website', 'category']) {
    if (!tpl[field] || typeof tpl[field] !== 'string') fail(`${tpl.id}: falta el campo ${field}`);
  }
  if (typeof tpl.website === 'string' && !/^https?:\/\//.test(tpl.website)) {
    fail(`${tpl.id}: website debe empezar por http:// o https://`);
  }
  if (!CATEGORIES.some((c) => c.id === tpl.category)) fail(`${tpl.id}: categoría desconocida «${tpl.category}»`);

  const app = tpl.app;
  if (!app || typeof app !== 'object') {
    fail(`${tpl.id}: falta el contenedor principal (app)`);
    return problems;
  }

  const appImage = String(app.image || '');
  if (!IMAGE_RE.test(appImage)) fail(`${tpl.id}: imagen inválida o sin etiqueta: ${app.image}`);
  if (FLOATING_TAG_RE.test(appImage)) {
    const tag = appImage.split(':').pop();
    fail(`${tpl.id}: la imagen usa la etiqueta móvil «${tag}» (como latest). Una etiqueta móvil convierte un reinicio en una actualización mayor no pedida.`);
  }
  if (!(Number.isInteger(app.port) && app.port > 0 && app.port < 65536)) fail(`${tpl.id}: puerto de aplicación inválido`);
  if (!(app.memoryMb >= 128)) fail(`${tpl.id}: falta el límite de memoria (mínimo 128 MB)`);
  if (!(app.cpus > 0)) fail(`${tpl.id}: falta el límite de CPU`);
  if (app.shmSize !== undefined && app.shmSize !== null && !SHM_SIZE_RE.test(String(app.shmSize))) {
    fail(`${tpl.id}: shmSize inválido «${app.shmSize}»`);
  }
  if (
    !app.readiness ||
    typeof app.readiness.path !== 'string' ||
    !app.readiness.path.startsWith('/') ||
    !Array.isArray(app.readiness.expect) ||
    app.readiness.expect.length === 0
  ) {
    fail(`${tpl.id}: falta la sonda de disponibilidad (readiness.path y readiness.expect)`);
  }

  if (app.extraPorts !== undefined && app.extraPorts !== null) {
    if (!Array.isArray(app.extraPorts)) {
      fail(`${tpl.id}: extraPorts debe ser una lista`);
    } else {
      const seenExtra = new Set();
      for (const ep of app.extraPorts) {
        const p = Number(ep && ep.containerPort);
        if (!Number.isInteger(p) || p <= 0 || p >= 65536) {
          fail(`${tpl.id}: puerto auxiliar inválido en extraPorts`);
        } else if (p === app.port) {
          fail(`${tpl.id}: extraPorts colisiona con app.port (${p})`);
        } else if (seenExtra.has(p)) {
          fail(`${tpl.id}: puerto auxiliar duplicado en extraPorts (${p})`);
        } else {
          seenExtra.add(p);
        }
      }
    }
  }

  // Estado persistente: si no hay base de datos gestionada, el servicio guarda
  // lo suyo en un volumen o lo pierde en el primer reinicio.
  const appVolumes = Array.isArray(app.volumes) ? app.volumes : [];
  if (!tpl.database && appVolumes.length === 0) {
    fail(`${tpl.id}: sin base de datos gestionada y sin volumen: los datos no sobrevivirían a un reinicio`);
  }

  const validateVolumeList = (vols, scope) => {
    for (const vol of vols || []) {
      if (!VOLUME_KEY_RE.test(String(vol.name || ''))) fail(`${tpl.id}: nombre de volumen inválido «${vol.name}» (${scope})`);
      const vPath = String(vol.path || '');
      if (!vPath.startsWith('/')) fail(`${tpl.id}: la ruta del volumen «${vol.name}» debe ser absoluta`);
      if (vPath.includes('docker.sock')) fail(`${tpl.id}: montaje prohibido de docker.sock en ${scope}`);
    }
  };
  const validateFileList = (files, scope) => {
    for (const file of files || []) {
      const fname = String(file.name || '');
      if (!FILE_NAME_RE.test(fname) || fname === '.' || fname === '..' || fname.includes('..')) {
        fail(`${tpl.id}: nombre de fichero inválido «${file.name}» (${scope})`);
      }
      const fPath = String(file.path || '');
      if (!fPath.startsWith('/')) fail(`${tpl.id}: el fichero «${file.name}» necesita una ruta absoluta`);
      if (fPath.includes('docker.sock')) fail(`${tpl.id}: montaje prohibido de docker.sock en fichero «${file.name}»`);
      if (typeof file.content !== 'string') fail(`${tpl.id}: el fichero «${file.name}» no tiene contenido de texto`);
      else if (file.content.includes('{{secret.')) fail(`${tpl.id}: el fichero «${file.name}» no puede incluir secretos en texto plano`);
    }
  };
  const validateEnvMap = (envMap, scope) => {
    for (const [k, v] of Object.entries(envMap || {})) {
      if (!ENV_KEY_RE.test(String(k))) fail(`${tpl.id}: clave de entorno inválida «${k}» (${scope})`);
      if (/[\r\n\0]/.test(String(v ?? ''))) fail(`${tpl.id}: valor de entorno «${k}» contiene saltos de línea o bytes nulos (${scope})`);
    }
  };

  validateVolumeList(appVolumes, 'app');
  validateFileList(app.files, 'app');
  validateEnvMap(app.env, 'app');

  if (tpl.database) {
    if (!['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb'].includes(tpl.database.engine)) {
      fail(`${tpl.id}: motor de base de datos desconocido «${tpl.database.engine}»`);
    }
    if (tpl.database.image) {
      const dbImg = String(tpl.database.image);
      if (!IMAGE_RE.test(dbImg)) fail(`${tpl.id}: imagen de base de datos inválida`);
      if (FLOATING_TAG_RE.test(dbImg)) {
        const tag = dbImg.split(':').pop();
        fail(`${tpl.id}: la imagen de base de datos usa la etiqueta móvil «${tag}» (como latest)`);
      }
    }
  }

  for (const [key, spec] of Object.entries(tpl.secrets || {})) {
    if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(key)) fail(`${tpl.id}: nombre de secreto inválido «${key}»`);
    if (!(spec.bytes >= 16)) fail(`${tpl.id}: el secreto ${key} pide menos de 16 bytes de entropía`);
    if (!['hex', 'base64', 'base64url'].includes(spec.encoding)) fail(`${tpl.id}: codificación desconocida en ${key}`);
  }

  const seenSidecars = new Set();
  for (const car of tpl.sidecars || []) {
    if (!VOLUME_KEY_RE.test(String(car.name || ''))) fail(`${tpl.id}: nombre de auxiliar inválido «${car.name}»`);
    if (seenSidecars.has(car.name)) fail(`${tpl.id}: auxiliar duplicado «${car.name}»`);
    seenSidecars.add(car.name);
    const carImage = String(car.image || '');
    if (!IMAGE_RE.test(carImage)) fail(`${tpl.id}: imagen inválida en el auxiliar «${car.name}»`);
    if (FLOATING_TAG_RE.test(carImage)) {
      const tag = carImage.split(':').pop();
      fail(`${tpl.id}: el auxiliar «${car.name}» usa la etiqueta móvil «${tag}» (como latest)`);
    }
    if (!(car.memoryMb >= 128)) fail(`${tpl.id}: el auxiliar «${car.name}» no declara límite de memoria`);
    if (!(car.cpus > 0)) fail(`${tpl.id}: el auxiliar «${car.name}» no declara límite de CPU`);
    validateVolumeList(car.volumes, `sidecar:${car.name}`);
    validateFileList(car.files, `sidecar:${car.name}`);
    validateEnvMap(car.env, `sidecar:${car.name}`);
    if (car.readiness) {
      const r = car.readiness;
      const validExec = r.type === 'exec' && Array.isArray(r.cmd) && r.cmd.length > 0 && r.cmd.every((a) => typeof a === 'string' && a.length > 0);
      const validTcp = r.type === 'tcp' && Number.isInteger(r.port) && r.port > 0 && r.port < 65536;
      if (!validExec && !validTcp) fail(`${tpl.id}: sonda de auxiliar inválida en «${car.name}»`);
    }
    if (car.dependsOn !== undefined && !Array.isArray(car.dependsOn)) {
      fail(`${tpl.id}: dependsOn debe ser una lista en «${car.name}»`);
    }
  }

  // Validar grafo de dependencias `dependsOn` entre auxiliares (referencias válidas y acíclico).
  const sidecarList = tpl.sidecars || [];
  const sidecarByName = new Map(sidecarList.map((c) => [c.name, c]));
  for (const car of sidecarList) {
    for (const dep of car.dependsOn || []) {
      if (dep === car.name) fail(`${tpl.id}: el auxiliar «${car.name}» no puede depender de sí mismo`);
      else if (!sidecarByName.has(dep)) fail(`${tpl.id}: el auxiliar «${car.name}» depende de «${dep}», que no existe`);
    }
  }
  const visitState = new Map();
  const hasCycle = (name) => {
    const state = visitState.get(name);
    if (state === 1) return true;
    if (state === 2) return false;
    visitState.set(name, 1);
    const car = sidecarByName.get(name);
    for (const dep of (car && car.dependsOn) || []) {
      if (sidecarByName.has(dep) && hasCycle(dep)) return true;
    }
    visitState.set(name, 2);
    return false;
  };
  for (const car of sidecarList) {
    if (hasCycle(car.name)) {
      fail(`${tpl.id}: dependencia circular en dependsOn del auxiliar «${car.name}»`);
      break;
    }
  }

  // Un secreto referenciado pero no declarado produciría una variable con el
  // texto «{{secret.X}}» dentro, y el servicio arrancaría con una contraseña
  // literal. Es un fallo silencioso: se caza aquí.
  const declared = new Set(Object.keys(tpl.secrets || {}));
  const appEnvBlob = JSON.stringify(app.env || {});
  const envBlobs = [appEnvBlob, ...sidecarList.map((c) => JSON.stringify(c.env || {}))];
  const usedBlob = envBlobs.join('');
  for (const blob of envBlobs) {
    for (const match of blob.matchAll(/\{\{secret\.([A-Z0-9_]+)\}\}/g)) {
      if (!declared.has(match[1])) fail(`${tpl.id}: usa el secreto «${match[1]}» sin declararlo`);
    }
  }
  // Y al revés: todo secreto declarado debe usarse en app.env o en algún auxiliar.
  for (const key of declared) {
    if (!usedBlob.includes(`{{secret.${key}}}`)) fail(`${tpl.id}: declara el secreto «${key}» y no lo usa en app.env ni en auxiliares`);
  }

  // Referencias a la base de datos sin base de datos declarada.
  if (!tpl.database && usedBlob.includes('{{db.')) {
    fail(`${tpl.id}: usa {{db.*}} pero no declara ninguna base de datos`);
  }

  const sidecarNames = new Set(sidecarList.map((c) => c.name));
  for (const match of usedBlob.matchAll(/\{\{sidecar\.([a-z0-9_]+)\.host\}\}/g)) {
    if (!sidecarNames.has(match[1])) fail(`${tpl.id}: referencia al auxiliar «${match[1]}», que no existe`);
  }

  // Verificar que no exista ningún marcador desconocido en ninguna variable.
  const SIMPLE_PLACEHOLDERS = new Set(['domain', 'host', 'protocol', 'wsProtocol', 'isHttps', 'url', 'tz', 'install.id']);
  const DB_FIELDS = new Set(['host', 'port', 'user', 'password', 'name', 'url']);
  for (const match of usedBlob.matchAll(/\{\{([a-zA-Z0-9_.]+)\}\}/g)) {
    const expr = match[1];
    if (SIMPLE_PLACEHOLDERS.has(expr)) continue;
    const parts = expr.split('.');
    if (parts[0] === 'secret' && parts.length === 2) continue;
    if (parts[0] === 'db' && parts.length === 2 && DB_FIELDS.has(parts[1])) continue;
    if (parts[0] === 'sidecar' && parts.length === 3 && parts[2] === 'host') continue;
    fail(`${tpl.id}: marcador desconocido «{{${expr}}}»`);
  }

  return problems;
}

/** Valida el catálogo entero. Lo usa la suite de pruebas y el arranque. */
function validateCatalog(templates = TEMPLATES) {
  const problems = [];
  const seen = new Set();
  for (const tpl of templates) {
    if (seen.has(tpl.id)) problems.push(`id duplicado: ${tpl.id}`);
    seen.add(tpl.id);
    problems.push(...validateTemplate(tpl));
  }
  return problems;
}

module.exports = {
  TEMPLATES,
  CATEGORIES,
  validateTemplate,
  validateCatalog,
  ID_RE,
  IMAGE_RE,
  FLOATING_TAG_RE,
  FILE_NAME_RE,
  SHM_SIZE_RE
};
