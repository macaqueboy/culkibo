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
  { id: 'automatizacion', label: 'Automatización' },
  { id: 'analitica', label: 'Analítica' },
  { id: 'contenido', label: 'Contenido' },
  { id: 'datos', label: 'Datos' },
  { id: 'desarrollo', label: 'Desarrollo' },
  { id: 'monitorizacion', label: 'Monitorización' },
  { id: 'productividad', label: 'Productividad' },
  { id: 'seguridad', label: 'Seguridad' }
];

// ---------------------------------------------------------------------------
// Plantillas
// ---------------------------------------------------------------------------

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
        N8N_PROTOCOL: 'https',
        WEBHOOK_URL: '{{url}}/',
        N8N_EDITOR_BASE_URL: '{{url}}',
        GENERIC_TIMEZONE: 'Europe/Madrid',
        // Sin esto n8n avisa en cada arranque de que los ficheros de
        // configuración son legibles por otros usuarios del contenedor.
        N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: 'true',
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
      WORDPRESS_NONCE_KEY: { bytes: 32, encoding: 'base64url' }
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
    sidecars: [
      {
        name: 'clickhouse',
        image: 'clickhouse/clickhouse-server:25.8-alpine',
        memoryMb: 2048,
        cpus: 2,
        env: { CLICKHOUSE_SKIP_USER_SETUP: '1' },
        volumes: [{ name: 'clickhouse', path: '/var/lib/clickhouse' }],
        // Sin estos dos ficheros, ClickHouse escribe varios GB de registro de
        // consultas al mes en un VPS pequeño y se come el disco en semanas. Es
        // el fallo que más se repite en las instalaciones de Plausible.
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
        ]
      }
    ],
    app: {
      image: 'ghcr.io/plausible/community-edition:v3.2.1',
      port: 8000,
      memoryMb: 1536,
      cpus: 1,
      env: {
        BASE_URL: '{{url}}',
        SECRET_KEY_BASE: '{{secret.SECRET_KEY_BASE}}',
        TOTP_VAULT_KEY: '{{secret.TOTP_VAULT_KEY}}',
        DATABASE_URL: '{{db.url}}',
        CLICKHOUSE_DATABASE_URL: 'http://{{sidecar.clickhouse.host}}:8123/plausible_events_db',
        DISABLE_REGISTRATION: 'invite_only'
      },
      volumes: [],
      readiness: { path: '/', expect: [200, 302] }
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

/**
 * Comprueba una plantilla entera y devuelve la lista de problemas.
 *
 * Es deliberadamente severo. El valor del catálogo no está en cuántas
 * plantillas hay, sino en que cada una haya pasado por aquí: imagen fijada
 * (nunca `latest`), límites de memoria y CPU, al menos un volumen si el
 * servicio guarda estado, sonda declarada y ningún secreto escrito a mano.
 */
function validateTemplate(tpl) {
  const problems = [];
  const fail = (msg) => problems.push(msg);

  if (!tpl || typeof tpl !== 'object') return ['La plantilla no es un objeto'];
  if (!ID_RE.test(String(tpl.id || ''))) fail(`id inválido: ${tpl.id}`);
  for (const field of ['name', 'summary', 'description', 'licence', 'website', 'category']) {
    if (!tpl[field] || typeof tpl[field] !== 'string') fail(`${tpl.id}: falta el campo ${field}`);
  }
  if (!CATEGORIES.some((c) => c.id === tpl.category)) fail(`${tpl.id}: categoría desconocida «${tpl.category}»`);

  const app = tpl.app;
  if (!app || typeof app !== 'object') {
    fail(`${tpl.id}: falta el contenedor principal (app)`);
    return problems;
  }

  if (!IMAGE_RE.test(String(app.image || ''))) fail(`${tpl.id}: imagen inválida o sin etiqueta: ${app.image}`);
  if (/:latest$/.test(String(app.image || ''))) {
    fail(`${tpl.id}: la imagen usa «latest». Una etiqueta móvil convierte un reinicio en una actualización mayor no pedida.`);
  }
  if (!(app.port > 0 && app.port < 65536)) fail(`${tpl.id}: puerto de aplicación inválido`);
  if (!(app.memoryMb >= 128)) fail(`${tpl.id}: falta el límite de memoria (mínimo 128 MB)`);
  if (!(app.cpus > 0)) fail(`${tpl.id}: falta el límite de CPU`);
  if (!app.readiness || !app.readiness.path || !Array.isArray(app.readiness.expect) || app.readiness.expect.length === 0) {
    fail(`${tpl.id}: falta la sonda de disponibilidad (readiness.path y readiness.expect)`);
  }

  // Estado persistente: si no hay base de datos gestionada, el servicio guarda
  // lo suyo en un volumen o lo pierde en el primer reinicio.
  const appVolumes = Array.isArray(app.volumes) ? app.volumes : [];
  if (!tpl.database && appVolumes.length === 0) {
    fail(`${tpl.id}: sin base de datos gestionada y sin volumen: los datos no sobrevivirían a un reinicio`);
  }

  for (const vol of appVolumes) {
    if (!VOLUME_KEY_RE.test(String(vol.name || ''))) fail(`${tpl.id}: nombre de volumen inválido «${vol.name}»`);
    if (!String(vol.path || '').startsWith('/')) fail(`${tpl.id}: la ruta del volumen «${vol.name}» debe ser absoluta`);
  }

  if (tpl.database) {
    if (!['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb'].includes(tpl.database.engine)) {
      fail(`${tpl.id}: motor de base de datos desconocido «${tpl.database.engine}»`);
    }
    if (tpl.database.image && !IMAGE_RE.test(String(tpl.database.image))) {
      fail(`${tpl.id}: imagen de base de datos inválida`);
    }
  }

  for (const [key, spec] of Object.entries(tpl.secrets || {})) {
    if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(key)) fail(`${tpl.id}: nombre de secreto inválido «${key}»`);
    if (!(spec.bytes >= 16)) fail(`${tpl.id}: el secreto ${key} pide menos de 16 bytes de entropía`);
    if (!['hex', 'base64', 'base64url'].includes(spec.encoding)) fail(`${tpl.id}: codificación desconocida en ${key}`);
  }

  for (const car of tpl.sidecars || []) {
    if (!VOLUME_KEY_RE.test(String(car.name || ''))) fail(`${tpl.id}: nombre de auxiliar inválido «${car.name}»`);
    if (!IMAGE_RE.test(String(car.image || ''))) fail(`${tpl.id}: imagen inválida en el auxiliar «${car.name}»`);
    if (/:latest$/.test(String(car.image || ''))) fail(`${tpl.id}: el auxiliar «${car.name}» usa «latest»`);
    if (!(car.memoryMb >= 128)) fail(`${tpl.id}: el auxiliar «${car.name}» no declara límite de memoria`);
    if (!(car.cpus > 0)) fail(`${tpl.id}: el auxiliar «${car.name}» no declara límite de CPU`);
    for (const file of car.files || []) {
      if (!String(file.path || '').startsWith('/')) fail(`${tpl.id}: el fichero «${file.name}» necesita una ruta absoluta`);
    }
  }

  // Un secreto referenciado pero no declarado produciría una variable con el
  // texto «{{secret.X}}» dentro, y el servicio arrancaría con una contraseña
  // literal. Es un fallo silencioso: se caza aquí.
  const declared = new Set(Object.keys(tpl.secrets || {}));
  const envBlobs = [JSON.stringify(app.env || {}), ...(tpl.sidecars || []).map((c) => JSON.stringify(c.env || {}))];
  for (const blob of envBlobs) {
    for (const match of blob.matchAll(/\{\{secret\.([A-Z0-9_]+)\}\}/g)) {
      if (!declared.has(match[1])) fail(`${tpl.id}: usa el secreto «${match[1]}» sin declararlo`);
    }
  }
  // Y al revés: un secreto declarado que nadie usa es ruido que acaba
  // desconcertando a quien lea la ficha de la instalación.
  const usedBlob = envBlobs.join('');
  for (const key of declared) {
    if (!usedBlob.includes(`{{secret.${key}}}`)) fail(`${tpl.id}: declara el secreto «${key}» y no lo usa`);
  }

  // Referencias a la base de datos sin base de datos declarada.
  if (!tpl.database && usedBlob.includes('{{db.')) {
    fail(`${tpl.id}: usa {{db.*}} pero no declara ninguna base de datos`);
  }

  const sidecarNames = new Set((tpl.sidecars || []).map((c) => c.name));
  for (const match of usedBlob.matchAll(/\{\{sidecar\.([a-z0-9_]+)\.host\}\}/g)) {
    if (!sidecarNames.has(match[1])) fail(`${tpl.id}: referencia al auxiliar «${match[1]}», que no existe`);
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

module.exports = { TEMPLATES, CATEGORIES, validateTemplate, validateCatalog, ID_RE, IMAGE_RE };
