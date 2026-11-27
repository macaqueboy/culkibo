# Guía Definitiva de Migración: Coolify v4 → Culkibo (Zero Downtime)

> **Culkibo v1.1.0** es el orquestador de aplicaciones y contenedores para la era de la IA: 0 dependencias de shell, Vault cifrado AES-256-GCM, ingress atómico en Caddy (<10 ms), control nativo por MCP y **bundles portátiles `.zip` autocontenidos**.

---

## 1. Matriz Completa de Paridad (Coolify v4 → Culkibo)

Culkibo ejecuta una migración **100% solo-lectura** sobre tu instancia Coolify v4 (nunca detiene ni modifica contenedores de origen) y calcula un **Parity Score determinista (0–100%)** antes de tocar un solo recurso:

| Recurso | Coolify v4 | Culkibo v1.1.0 | Fidelidad |
| :--- | :--- | :--- | :---: |
| **Proyectos y Entornos** | Projects / Environments | Proyectos jerárquicos + entornos aislados | 100% |
| **Aplicaciones** | Git, Nixpacks, Dockerfile, Docker Image, Compose | Build/Deploy nativo con `memoryMb`, `cpus`, hooks pre/post | 100% |
| **Servicios Multi-Contenedor** | Docker Compose Stacks (`services` + sub-apps) | Parser Compose + sub-dominios + traductor Magic Vars | 100% |
| **Bases de Datos (8 motores)** | PostgreSQL (pgvector/Timescale), MySQL, MariaDB, MongoDB, Redis, KeyDB, Dragonfly, ClickHouse | Motores gestionados (`postgres`, `pgvector`, `timescaledb`, `mysql`, `mariadb`, `mongodb`, `valkey`, `clickhouse`) aislados en red privada | 100% |
| **Magic Variables** | `${SERVICE_FQDN_*}`, `${SERVICE_PASSWORD_64_*}`, `${COOLIFY_*}` | Traducción automática a dominios y `${vault.*}` (AES-256-GCM) | 100% |
| **Etiquetas Traefik** | `traefik.http.routers.*`, `stripprefix`, `redirectregex`, `headers`, `forwardauth`, `basicauth`, `ipallowlist`, `ratelimit` | Traducción automática a reglas nativas de **Caddy Edge** (`pathRoutes`, `pathRedirects`, `cors`, `hstsPreload`, `forwardAuth`, `basicAuth`, `targetPort`) | 100% |
| **Scheduled Tasks** | Tareas programadas (`daily`, `hourly`, cron) | `cronManager` nativo (validado con `cronParser` + zero-shell `safeCommand`) | 100% |
| **Variables Compartidas & Preview** | Shared Envs, Build Envs, Preview Envs | Entornos separados + vista previa estrictamente redactada | 100% |
| **Volúmenes y File Mounts** | `local_persistent_volumes` / `local_file_volumes` | Volúmenes persistentes y montajes de archivos preservados | 100% |
| **Healthchecks** | `health_check_path` / `method` / `timeout` | Conversión automática a **Smoke Tests** post-despliegue | 100% |

---

## 2. Traducción Automática de Coolify v4 Magic Variables

El motor `coolifyMigrator.translateMagicVariables()` escanea tanto `environment_variables` como bloques `docker_compose` (decodificando Base64 si Coolify lo entrega codificado):

| Variable Mágica en Coolify v4 | Traducción en Culkibo | Notas de Seguridad |
| :--- | :--- | :--- |
| `${SERVICE_FQDN_<APP>}` / `${SERVICE_FQDN_<APP>_<PORT>}` | Hostname real resuelto (ej. `api.ejemplo.com`) o `${domain.<app>}` | Soporta sufijos de puerto `_3000`, `_8080` |
| `${SERVICE_URL_<APP>}` / `${SERVICE_URL_<APP>_<PORT>}` | URL completa con esquema (`https://api.ejemplo.com`) | Preserva esquema del FQDN original |
| `${SERVICE_PASSWORD_<NAME>}` | `${vault.SERVICE_PASSWORD_<NAME>}` | Secretos jamás en texto plano en dry-run |
| `${SERVICE_PASSWORD_64_<NAME>}` | `${vault.SERVICE_PASSWORD_64_<NAME>}` | Longitud 64 caracteres marcada en metadatos |
| `${SERVICE_USER_<NAME>}` | `${vault.SERVICE_USER_<NAME>}` | Almacenado en Vault AES-256-GCM |
| `${SERVICE_BASE64_<NAME>}` / `_64_` / `_128_` / `REALBASE64` | `${vault.SERVICE_BASE64_<NAME>}` | Auto-generable en destino si no se porta |
| `${COOLIFY_FQDN}` | Lista CSV de hostnames de la app | Sin esquema |
| `${COOLIFY_URL}` | URL principal (`https://<host>`) | Lista para callbacks OAuth / webhooks |
| `${COOLIFY_BRANCH}` | Rama Git configurada (`main`, etc.) | Inyectada en runtime y build |
| `${COOLIFY_CONTAINER_NAME}` | Slug de contenedor normalizado (`culkibo-<app>`) | Seguro para redes internas |

> **Privacidad en Dry-Run:** `planMigration()` y `previewMigration()` redactan toda credencial y variable sensible como `[REDACTED:sha256:...]`. Nunca se filtran secretos en logs ni en la interfaz previa.

---

## 3. Traductor Traefik → Caddy Edge Nativo

`coolifyMigrator.parseTraefikLabels()` decodifica `custom_labels` (texto plano o Base64) y etiquetas `labels:` de Docker Compose, aplicando las mismas guardias de seguridad de `caddyManager` / `domainManager`:

| Etiqueta Traefik v2/v3 | Campo Nativo en Culkibo (`domainManager`) | Validación de Seguridad |
| :--- | :--- | :--- |
| `traefik.http.routers.<r>.rule=Host(...) && PathPrefix(...)` | `hostname` + `pathRoutes[]` | RFC 1123 + bloqueo path traversal `..` |
| `traefik.http.services.<s>.loadbalancer.server.port` | `targetPort` (y `protocol: 'h2c'` si `scheme=h2c`) | Puerto entero 1..65535 |
| `traefik.http.middlewares.<m>.stripprefix.prefixes` | `pathRoutes[].stripPrefix` | Normalizado por router/prefix |
| `traefik.http.middlewares.<m>.redirectregex.*` | `canonicalRedirect` (`www_to_apex`/`apex_to_www`) o `pathRedirects[]` | **Guardia anti-ReDoS** (`validateSafeRedirectRegex`) |
| `traefik.http.middlewares.<m>.headers.accesscontrol*` | `cors` (`allowedOrigins`, `allowedMethods`, `allowedHeaders`, `allowCredentials`, `maxAge`) | Bloquea CORS inseguro `*` + `allowCredentials: true` |
| `traefik.http.middlewares.<m>.headers.sts*` | `hstsPreload` + `hstsMaxAge` | Acotado `0..63072000` s |
| `traefik.http.middlewares.<m>.headers.custom*headers.*` | `customHeaders.response` / `customHeaders.request` | Bloquea CRLF y cabeceras hop-by-hop |
| `traefik.http.middlewares.<m>.forwardauth.*` | `forwardAuth` (`upstream`, `uri`, `copyHeaders`) | **Guardia SSRF** (bloquea IMDS/metadatos cloud) |
| `traefik.http.middlewares.<m>.basicauth.users` | `basicAuth` (desescapa `$$` → `$`) | Preserva bcrypt `$2a$`/`$2b$`/`$2y$`; avisa en hashes APR1/SHA1 |
| `traefik.http.middlewares.<m>.ipallowlist.sourcerange` | `ipAllowlist[]` | Validación estricta IPv4/IPv6 CIDR |
| `traefik.http.middlewares.<m>.ratelimit.average` | `rateLimit` (`requests`, `windowSeconds`) | Acotado para Caddy |
| `traefik.http.middlewares.<m>.buffering.maxrequestbodybytes` | `maxBodySizeMb` | Conversión automática a MB |

---

## 4. Culkibo Portable Stack Bundle (`.zip` / `.ckb.gz`)

Con `server/services/bundleArchiver.js` (0 dependencias externas, escritor/lector PKZIP 2.0 en JS puro con CRC32 + `zlib`), puedes empaquetar, respaldar o mover un stack completo entre servidores en un único archivo `.zip` o `.ckb.gz`:

### Estructura del Bundle `.zip`
```text
mi-stack-ckb_xxx.zip
├── manifest.json           # Versión, bundleId, conteos y modo de Vault
├── checksums.json          # Integridad SHA-256 de todos los archivos
├── culkibo.yaml            # Manifiesto declarativo GitOps v1 (0 secretos en claro)
├── projects.json           # Proyectos sanitizados con referencias ${vault.*}
├── domains.json            # Dominios y políticas Caddy Edge (CORS, HSTS, ForwardAuth)
├── databases.json          # Topologías de bases de datos (sin contraseñas)
├── crons.json              # Tareas programadas
├── mcp-agent-config.json   # Config drop-in para Antigravity, Claude Code y Cursor
├── vault.enc.json          # Sobre cifrado AES-256-GCM + scrypt (si se indicó passphrase)
│   (o vault.redacted.json) # Huellas y claves requeridas sin secretos en claro
└── README-RESTORE.md       # Guía de restauración en 1 clic
```

### Defensas Integradas en `bundleArchiver.js`
- **Anti Path-Traversal & Symlinks**: rechaza `..`, rutas absolutas (`/etc/...`), unidades Windows (`C:\...`), bytes NUL y entradas symlink Unix (`0o120000`).
- **Anti Zip-Bomb / Gzip-Bomb**: valida número de entradas (máx. 200), tamaño por archivo (máx. 10 MB), tamaño total (máx. 50 MB), ratio de expansión (máx. 100:1) y `maxOutputLength` nativo en `zlib.inflateRawSync` / `zlib.gunzipSync`.
- **Anti-Polyglot & Integridad**: exige coincidencia exacta entre Local File Header y Central Directory, CRC32 por archivo y SHA-256 global (`checksums.json`).

---

## 5. Procedimiento de Migración Zero-Downtime (3 Pasos)

### Paso 1: Obtener Token API en Coolify v4 (o Exportación Offline / `.zip`)
1. En Coolify v4 ve a **Keys & Tokens → API Tokens → + Add New Token**.
2. Otorga permisos `read:all` y copia el token (`1|...`).
3. Abre Culkibo → **Importar → Coolify v4**, pega tu URL + Token (o selecciona **Exportación JSON** / **Bundle Portátil .zip**).

### Paso 2: Revisar la Cabina de Paridad (Pre-Flight)
1. Comprueba el **Parity Score (%)** y las 4 pestañas de inspección:
   - **Recursos**: selecciona proyectos, apps, bases de datos y stacks Compose.
   - **Magic Vars**: verifica las referencias `${vault.*}` y dominios traducidos.
   - **Traefik → Caddy**: revisa `pathRoutes`, `CORS`, `HSTS`, `forwardAuth`, `basicAuth` y puertos.
   - **Pre-Flight**: revisa avisos de secretos, puertos públicos de BDs o crons con sintaxis de shell.
2. Opcional: haz clic en **Exportar Bundle .zip** para guardar una copia portable antes de importar.
3. Pulsa **Migrar recursos (Zero-Downtime)**.

### Paso 3: Volcado de Datos, Verificación Pre-DNS y Cutover

#### Volcado de Bases de Datos (8 Motores)
```bash
# PostgreSQL / pgvector / TimescaleDB
docker exec -t <coolify_pg> pg_dump -U postgres -d <db> -F c -b -f /tmp/backup.dump
pg_restore -h 127.0.0.1 -p 5432 -U postgres -d <db> --no-owner --no-privileges /tmp/backup.dump

# MySQL / MariaDB
docker exec <coolify_mysql> mysqldump -u root -p --single-transaction --quick --set-gtid-purged=OFF <db> > backup.sql
mysql -h 127.0.0.1 -P 3306 -u root -p <db> < backup.sql

# Redis / KeyDB / Dragonfly → Valkey
docker exec <coolify_kv> redis-cli BGSAVE
# Copiar dump.rdb al volumen de Valkey en Culkibo

# MongoDB
docker exec <coolify_mongo> mongodump --archive=/tmp/mongo.archive --gzip
mongorestore --archive=/tmp/mongo.archive --gzip

# ClickHouse
docker exec <coolify_ch> clickhouse-client --query="BACKUP DATABASE default TO Disk('backups', 'migration.zip')"
```

#### Sincronización de Volúmenes Persistentes
```bash
rsync -avzP /var/lib/docker/volumes/<volumen_coolify>/_data/ root@<nuevo_vps>:/var/lib/culkibo/volumes/<volumen_culkibo>/
```

#### Verificación Pre-Cutover (`verifyMigratedStack`)
Antes de modificar tus registros DNS, verifica tus endpoints contra la IP del servidor Culkibo:
```bash
curl -fsS -I --resolve api.tudominio.com:443:<IP_CULKIBO> https://api.tudominio.com/health
```
Comprueba HTTP 200, cabeceras CORS/HSTS y latencia. Luego haz clic en **Migrar todos los dominios** (Cloudflare actualiza el registro `A` en <30 s con caída cero).

---

## 6. Red de Seguridad / Rollback Instantáneo

Si necesitas revertir tras el cutover:
1. Tu servidor Coolify original **nunca fue alterado** y sus contenedores siguen intactos.
2. En Cloudflare (o tu DNS), cambia de vuelta el registro `A` a la IP del VPS de Coolify (~30 segundos con proxy naranja activo).
3. Mantén Coolify en espera 24–48 h antes de apagar el VPS antiguo.
