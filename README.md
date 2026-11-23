# Culkibo

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js >=20](https://img.shields.io/badge/Node.js-%E2%89%A520-339933.svg)](package.json)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28%20(52%20tools)-18181b.svg)](#conectar-agentes-de-ia-mcp-2026-07-28)

**Orquestador cloud autohospedado, open-source y diseñado para la era de los agentes de IA.**  
Alternativa ultrarrápida, auditable y sin fricción frente a Coolify y Dokploy: Live Sync binario sub-20 ms (*The Forge*), despliegues inmutables sin cortes con **Caddy v2.11** (*The Citadel*), **multi-wildcard SSL persistente (ACME DNS-01 Cloudflare con `Dockerfile.caddy`) + subida criptográfica PEM / Cloudflare Origin CA + diagnóstico de dominios en 4 capas**, **semáforo global de compilaciones anti-OOM + enlace automático Proyecto ↔ Base de datos en red aislada + modo mantenimiento atómico `<10 ms`**, **fast-path HTTP zero-copy precomprimido (Brotli-11 / Zstd / Gzip + ETag/304)**, observabilidad en vivo + Prometheus `/metrics` + System Doctor en 1 clic, migrador guiado de **WordPress** e **Importador Universal** (Coolify, Docker Compose, cualquier URL Git, Vercel, Netlify, Railway, Render, Dokploy), enlace en directo con **Agentes IA (`52` herramientas MCP `2026-07-28`)**, catálogo de **14 servicios en 1 clic** y **cero construcción de comandos de shell**.

**Apache-2.0 · 6 dependencias de runtime · 21 suites + live-server + estrés + benchmarks reproducibles**

---

## Por qué Culkibo

El ciclo habitual de desarrollo con agentes de IA (Claude Code, Cursor, Windsurf, VS Code Copilot, Antigravity) se rompe esperando pipelines:

```text
Tradicional: editar → commit → push → webhook → build Docker (1–4 min) → esperar → ver
Culkibo:     guardar fichero → Commit Frame binario (/ws/sync) → vivo en ~13,9 ms (p50)
             promocionar → BuildKit con caché → healthcheck → conmutación Caddy en ~9,3 ms (p50)
```

Dos planos coordinados —simbolizados por el emblema **Twin Planes K** (espina de control blanca + plano ascendente *Forge Amber* + plano descendente *Citadel*)— sobre el mismo dominio:

- **The Forge (iteración instantánea):** `culkibo sync` agrupa ráfagas de ediciones de IA en *Commit Frames* binarios atómicos por WebSocket (`/ws/sync`, sin sobrecarga base64 y con detachment de slabs de memoria), deduplica por SHA-256 con caché LRU O(1), trocea reconciliaciones grandes (`<=250` archivos / `<=8 MiB`), verifica consistencia con árbol Merkle y mantiene un ring-buffer acotado en memoria para revertir parches en **<2 ms (p50)**.
- **The Citadel (producción inmutable):** semáforo global de concurrencia (`CULKIBO_MAX_CONCURRENT_BUILDS=2`), registro unificado de puertos por subsistema (`portRegistry`, cero colisiones), builds Docker con BuildKit (`# syntax=docker/dockerfile:1.7` + cachés bloqueados por proyecto), enlace automático con bases de datos gestionadas (red aislada + inyección de credenciales en runtime sin texto plano en disco), compresión Zstd/Gzip a nivel de servidor Caddy, modo mantenimiento `503` atómico en `<10 ms`, watchdog OOM/crash-loop con *auto-rollback* opcional y drenaje seguro con conservación de la versión anterior.

---

## Benchmarks reproducibles (sin simulaciones)

Cada número de esta tabla procede de código real ejecutado contra **Caddy v2.11.9 real** y el daemon real de Culkibo (`npm run bench:all` / `npm test`) — cero `setTimeout` simulados, cero constantes escritas a mano.

| Dimensión | Culkibo v1.0.0 (medido en Node 24 · Win x64) | Coolify / Dokploy / Competidores | Cómo reproducirlo |
|---|---:|---|---|
| **Conmutación de ruta HTTP** (Caddy v2.11.9 admin API) | **p50 9,3 ms · p95 22,0 ms · mín 7,5 ms · 0 HTTP 5xx** | Traefik file throttle 2.000 ms / HTTP poll 5.000 ms (**215×–537× más lento**) | `npm run bench` |
| **Live Sync binario E2E** (disco → `/ws/sync` → HTTP vivo) | **p50 13,86 ms · p95 16,29 ms** (`apply` servidor **p50 1,01 ms**) | Coolify ~4 min · Vercel ~42 s · Dokploy ~30 s | `npm run bench:sync` |
| **Ráfaga IA (15 ficheros simultáneos)** | **1 solo Commit Frame atómico (141,6 ms)** | 15 eventos sueltos o builds encadenados | `npm run bench:sync` |
| **Rollback de parche en memoria** | **p50 1,62 ms · p95 7,05 ms** | Rebuild completo o reinicio de contenedor | `npm run bench:sync` |
| **Arranque en frío y RAM en reposo** | **195–255 ms · 53 MB RSS · 0% CPU** (cabe en VPS 512 MB) | Coolify ≥ 2.048 MB (falla en VPS 1 GB) · Dokploy ~600–900 MB | `npm run bench:control` |
| **Concurrencia plano de control (400 req)** | **2.454 req/s · p50 6,36 ms · p95 15,13 ms · 0 fallos** | PHP/Laravel + Postgres + Redis + Horizon | `npm run bench:control` |
| **Panel web precomprimido (zero-copy fast-path)** | **Brotli-11 / Gzip-9 en RAM + ETag/304 (0 carga Express)** | Compresión al vuelo por cada visita | `GET /` · `GET /assets/*` |
| **Estrés mixto (100 req: GET + POST concurrentes)** | **100/100 éxito · 85,6 ms media · 0 fallos** | Sin fast-path O(1) nativo | `node tests/stress.test.js` |
| **WebSocket fan-out (40 clientes)** | **40/40 clientes listos en 42,9 ms · 0 caídas bajo churn** | Polling / Pusher / Soketi extra | `npm run bench:control` |
| **Dependencias de runtime** | **6** (`express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) | Cientos de paquetes PHP/Composer o monorepo Next.js | `package.json` |
| **Construcción de comandos de shell** | **0** (verificado en CI por escáner estático) | 21 avisos críticos RCE en Coolify · 34 en Dokploy | `node tests/shell-safety.test.js` |
| **Superficie MCP (`2026-07-28`)** | **52 herramientas anotadas (28 mutadoras)** | Coolify: 3 mutadoras · Dokploy: sin MCP nativo | `POST /api/mcp` (`tools/list`) |
| **Observabilidad y Doctor en 1 clic** | **Prometheus `/metrics` + p50/p95/p99 + Event Loop + 8 checks** | Requiere stack Prometheus/Grafana externo | `GET /metrics` · `#/metrics` |

---

## Dominios, múltiples comodines SSL y Origin CA

- **Dominios propios y subdominios individuales:** TLS automático con Let's Encrypt / ZeroSSL bajo demanda vía Caddy + redirección canónica 301 `www ↔ raíz` en 1 clic + cabeceras de seguridad (`HSTS`, `X-Frame-Options`, `nosniff`) y compresión **Zstd + Gzip**.
- **Múltiples certificados Wildcard (`*.a.com`, `*.b.com`, …):** políticas ACME DNS-01 de Cloudflare persistidas en disco y reconciliadas al reiniciar Caddy. Incluye [`Dockerfile.caddy`](Dockerfile.caddy) listo para compilar Caddy con `github.com/caddy-dns/cloudflare` mediante `xcaddy`, detección automática de capacidades del binario (`/api/ingress/capabilities`) y ordenación por especificidad (host exacto siempre por delante del comodín).
- **Alternativa sin recompilar Caddy (Cloudflare Origin CA / PEM propios):** sube certificados y claves PEM desde el panel o API (`/api/ssl/certificates/upload`) con verificación criptográfica X.509 de par público/privado y carga automática en `apps.tls.certificates.load_files`.
- **Diagnóstico en 4 capas:** un clic sobre cualquier dominio comprueba en vivo **DNS → Ruta Caddy → Certificado TLS (handshake real) → Puerto TCP destino** con recomendaciones claras en español.

---

## Comparativa honesta

| Capacidad | Culkibo | Coolify | Dokploy | CapRover / Dokku |
|---|:---:|:---:|:---:|:---:|
| Plano de datos Caddy atómico (TLS bajo demanda + Zstd/Gzip + HTTP/3 + `grace_period`) | ✅ | Traefik (poll 2–5 s) | Traefik | nginx |
| Asistente 3 pasos para dominios, redirección `www`, multi-wildcard DNS-01, PEM/Origin CA y diagnóstico 4 capas | ✅ | Manual | Manual | Manual |
| Live Sync binario sub-20 ms (Commit Frames + Merkle + Rollback <2 ms) | ✅ | ❌ | ❌ | ❌ |
| Migrador guiado de WordPress (análisis en vivo + MariaDB + SQL / 512 MB + dominio directo) | ✅ | Plantilla básica | Plantilla básica | Plantilla básica |
| Importador universal (Coolify v4, Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy) | ✅ | ❌ | ❌ | ❌ |
| Builds Docker con BuildKit cache mounts + semáforo anti-OOM + modo mantenimiento `<10 ms` | ✅ | Parcial | Parcial | Parcial |
| Bases de datos gestionadas (6 motores: PG, MySQL, MariaDB, Redis, Valkey, Mongo) + auto-enlace red privada | ✅ | ✅ | ✅ | Parcial |
| Backups programados (cron) + checksums SHA-256 + S3 / Cloudflare R2 / MinIO + retención GFS | ✅ | ✅ | ✅ | Manual |
| Catálogo 1-clic con redes aisladas y secretos AES-256-GCM (14 plantillas) | ✅ | ✅ | ✅ | ✅ |
| Hub en directo de Agentes IA + MCP `2026-07-28` (52 herramientas, 28 mutadoras, redacción de secretos) | ✅ | Parcial (3) | ❌ | ❌ |
| Observabilidad nativa (Prometheus `/metrics`, p50/p95/p99, Event Loop, Doctor 1-clic) | ✅ | Externa | Básica | ❌ |
| Cero `exec`/`sh -c` + protección SSRF IPv4/IPv6 + tickets WS de un solo uso + `0600` | ✅ | ❌ | ❌ | Parcial |
| Consumo en VPS de 512 MB / 1 GB RAM | ✅ (~53 MB) | ❌ (≥ 2 GB) | Ajustado | ✅ |
| **Multi-servidor / cluster Swarm-K8s** | 🚧 Roadmap (1 VPS hoy) | ✅ | ✅ | Swarm |

> **Honestidad radical:** Culkibo v1.0 gestiona un único host (VPS o máquina local). La orquestación multi-servidor está en el roadmap; todo lo marcado con ✅ está implementado, probado en las 21 suites y verificable en este repositorio.

---

## Instalación

### 1. VPS Debian / Ubuntu (1 línea, producción)

Instala usuario sin privilegios `culkibo`, Node 22, Docker, Caddy con TLS automático (y soporte HTTP/3 `443/udp`), unidad `systemd` endurecida, token aleatorio con permisos `0600` en `data/auth.json` y servicio escuchando en loopback tras Caddy:

```bash
curl -fsSL https://raw.githubusercontent.com/macaqueboy/culkibo/main/scripts/install.sh | sudo bash
```

Para desinstalar limpiamente: `sudo bash /opt/culkibo/scripts/uninstall.sh`.  
El instalador cuenta con su propio banco de pruebas contra un contenedor Debian 12 real con `systemd` ([`scripts/test-install.sh`](scripts/test-install.sh)).

### 2. Docker Compose (Culkibo + Caddy v2.11 + `caddy-dns/cloudflare`)

```bash
git clone https://github.com/macaqueboy/culkibo.git
cd culkibo
docker compose up -d --build
```

Levanta el daemon de Culkibo en `http://127.0.0.1:3030` conectado por red interna privada a Caddy v2.11 (con [`Dockerfile.caddy`](Dockerfile.caddy) preparado para múltiples certificados Wildcard DNS-01 y sin exponer nunca el puerto admin `:2019` al host).

### 3. Desarrollo local (Linux, macOS, Windows)

Requiere Node.js 20+ (recomendado Node 22/24). Docker y Caddy son opcionales en local: sin ellos, Culkibo ejecuta proyectos como procesos locales y degrada con mensajes explícitos.

```bash
git clone https://github.com/macaqueboy/culkibo.git
cd culkibo
npm install
npm --prefix web install
npm run build
npm start
```

En Windows: `./start.ps1`. Panel web en `http://localhost:3030`.

---

## Seguridad por construcción

1. **Cero construcción de comandos de shell:** todos los subprocesos (`git`, `docker`, `npm`, `caddy`) se lanzan con `spawn()` / `execFile()` y arrays `argv` explícitos (`shell: false`). Los secretos viajan por `--env-file` efímeros (`0600`) o `GIT_ASKPASS`, jamás en `argv` ni en `.git/config`. El invariante se verifica en cada commit con [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
2. **Aislamiento de red por servicio y base de datos:** cada base de datos gestionada y cada servicio del catálogo recibe su propia red Docker bridge privada sin puertos publicados por defecto (`127.0.0.1` sólo bajo petición, `0.0.0.0` sólo con confirmación explícita de riesgo UFW/Docker). El enlace Proyecto ↔ BD conecta el contenedor en runtime sin guardar contraseñas en `projects.json`.
3. **Cifrado en reposo e integridad verificada:** credenciales de bases de datos, secretos del catálogo y configuración S3/R2 se cifran con **AES-256-GCM** (`0600`), los respaldos de proyectos incluyen y verifican checksums **SHA-256** reales antes de restaurar, y las respuestas MCP redactan automáticamente los valores de `envVars` y `buildArgs`.
4. **Autenticación HTTP + WebSocket + Panel remoto (`AuthGate`):**
   - Validación estricta de `Origin` y bloqueo de spoofing `X-Forwarded-For` + SSRF IPv4/IPv6.
   - Token de 256 bits comparado en tiempo constante (`crypto.timingSafeEqual`) y tickets WebSocket de un solo uso (`/api/auth/ws-ticket`), exigido automáticamente en conexiones no-loopback (o siempre con `CULKIBO_REQUIRE_TOKEN=1`).

---

## CLI

```bash
node bin/culkibo.js start                               # arranca el daemon y el panel
node bin/culkibo.js status                              # estado operativo y memoria RSS
node bin/culkibo.js doctor                              # diagnóstico (Node, Docker, Git, Caddy)

node bin/culkibo.js sync <projectId> [dir]              # Live Sync en tiempo real hacia The Forge
node bin/culkibo.js deploy <projectId>                  # despliegue a producción en The Citadel
node bin/culkibo.js rollback <projectId>                # rollback instantáneo a versión anterior

node bin/culkibo.js catalog list                        # listar las 14 plantillas de 1 clic (incluye WordPress)
node bin/culkibo.js update                              # actualizar Culkibo sin shell ni pérdida de estado
node bin/culkibo.js pod list                            # estado de The Forge y The Citadel
node bin/culkibo.js domain list                         # dominios y estado TLS real
node bin/culkibo.js docker                              # inspección de contenedores
node bin/culkibo.js ingress <hostname>                  # ruta y estado real en Caddy

node bin/culkibo.js backup <projectId>                  # exportar proyecto con checksum SHA-256
node bin/culkibo.js restore <archivo.json>              # restaurar verificando integridad SHA-256
node bin/culkibo.js mcp                                 # servidor MCP por stdio (logs a stderr)
```

---

## Conectar agentes de IA (MCP `2026-07-28`)

Culkibo expone **52 herramientas anotadas** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), incluyendo **28 herramientas de escritura** y redacción automática de secretos: desplegar a producción, consultar la cola global de builds (`culkibo_get_deploy_queue`), hacer rollback, activar modo mantenimiento en `<10 ms` (`culkibo_toggle_maintenance`), enlazar bases de datos (`culkibo_link_database`), aprovisionar bases de datos y copias S3/R2, instalar servicios del catálogo, analizar webs WordPress, importar stacks Docker Compose, inspeccionar métricas y diagnóstico (`culkibo_get_metrics`, `culkibo_system_doctor`), verificar árboles Merkle de Live Sync y promocionar Forge → Citadel.

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "culkibo": {
      "command": "node",
      "args": ["/ruta/a/culkibo/bin/culkibo.js", "mcp"],
      "env": {
        "CULKIBO_API_URL": "http://localhost:3030",
        "CULKIBO_TOKEN": "tu-token-de-data-auth-json"
      }
    }
  }
}
```

### Cursor, Windsurf, Antigravity y clientes Streamable HTTP (`2026-07-28`)

Endpoint único (`POST`): `http://localhost:3030/api/mcp`

```bash
curl -s http://localhost:3030/api/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: server/discover' \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}}}}'
```

> El transporte heredado `2024-11-05` (`GET /api/mcp/sse` + `POST /api/mcp/message`) sigue operativo con cabecera `Deprecation: true` para clientes antiguos.

---

## Pruebas, tipos, lint y benchmarks

```bash
npm run typecheck             # TypeScript checkJs en todo el servidor (0 errores)
npm --prefix web run lint     # oxlint React 19 + Compiler rules (0 warnings, 0 errors)
npm run web:build             # compilación Vite + TypeScript + precompresión .br/.gz
npm test                      # 21 suites + live-server + websocket-stress + stress
npm run test:bench            # aserciones estrictas de benchmarks y paridad competitiva
npm run bench:all             # reporte completo de los 3 benchmarks reales
```

### Cobertura de las 21 suites (`tests/run-all.js`)

| Suite | Qué verifica |
|---|---|
| `shell-safety.test.js` | 0 construcción de comandos de shell en `server/`, `bin/`, `scripts/`, `bench/` |
| `security-hardening.test.js` | C1–C6, H1–H9: SSRF (metadata/RFC1918/S3/webhooks), proxy loopback spoofing, symlinks, PAT scoping, redacción MCP |
| `metrics-and-bugs.test.js` | XFF leftmost spoof, IPv6-mapped hex SSRF, tickets WS de un solo uso, rate-limit auth, Prometheus `/metrics`, Doctor 8 checks y regresiones profundas |
| `scale-and-wildcard.test.js` | Multi-wildcard DNS-01 persistente, 301 `www`, mantenimiento 503, PEM/Origin CA X.509 match/mismatch, `portRegistry` 20-way, semáforo de builds, MCP redaction (52 tools), SHA-256 tamper rejection, Live Sync 520-file chunking, static `br`/ETag/304 |
| `importers.test.js` | Migrador WordPress en vivo + reescritura SQL segura + Docker Compose + Vercel/Netlify/Railway/Render/Dokploy + Git URLs |
| `live-sync.test.js` | Path traversal, Commit Frames binarios, SHA-256 dedup, Merkle Tree, rollback <4 ms, auth WS `/ws/sync`, E2E real |
| `competitor-benchmarks.test.js` | Aserciones reales de RAM, arranque, concurrencia, Live Sync, Caddy cutover 0×5xx, MCP y catálogo |
| `caddy.test.js` | Caddy admin API real: config base, `@id`, actualización in-situ, canario 10/90, rollback ante error |
| `deploy.test.js` | BuildKit, detección de stacks, secretos fuera de argv, cutover con drenaje, rollback real Docker |
| `database.test.js` | 6 motores, AES-256-GCM, lista blanca, AWS SigV4 byte a byte, multipart S3/R2, cron, retención GFS |
| `catalog.test.js` | 14 plantillas en 8 categorías (incluye WordPress), imágenes fijadas, secretos, puertos `42000-42999`, proyección segura |
| `mcp.test.js` | 52 herramientas anotadas, JSON-RPC 2.0, Streamable HTTP `2026-07-28`, `server/discover`, SSE y errores |
| `ssl.test.js` | Registro X.509 real, purga de PEMs fabricados, TLS bajo demanda delegado a Caddy |
| `domain.test.js` | Rutas exactas, comodines con frontera de etiqueta, anti-duplicados, proxy Cloudflare |
| `cloudflare.test.js` | Zonas, registros DNS, TXT ACME DNS-01 y túneles |
| `github.test.js` | OAuth, autodetección de stacks, firma HMAC SHA-256, idempotencia de redeliveries |
| `coolifyMigrator.test.js` | Extracción y agrupación desde Coolify v4 (apps, DBs, servicios, volúmenes) |
| `localRunner.test.js` | `GIT_ASKPASS`, puertos, traversal, Unicode, estáticos y procesos |
| `stop-lifecycle.test.js` | Arranque, parada, hibernación, liberación real de puertos y persistencia atómica |
| `orchestrator.test.js` | Métricas reales del daemon (RSS/CPU), watchers y logs |
| `backup.test.js` | Exportación, restauración con SHA-256 y volcados sin shell |

Más `live-server.test.js`, `websocket-stress.test.js` (30 clientes concurrentes con churn) y `stress.test.js` (100 peticiones mixtas simultáneas).

---

## Estructura

```text
Dockerfile                         Imagen del plano de control (Node 22 + docker-cli-buildx)
Dockerfile.caddy                   Imagen Caddy v2.11 + xcaddy caddy-dns/cloudflare (multi-wildcard DNS-01)
bin/culkibo.js                     CLI (start, sync, deploy, rollback, catalog, doctor, mcp...)
server/
  index.js                         Daemon HTTP + fast-path estático/API precomprimido + WebSocket (/ws y /ws/sync)
  middleware/auth.js               Auth por Origen + Token en tiempo constante (HTTP y WS)
  routes/api.js                    API REST completa
  services/
    portRegistry.js                Registro unificado de puertos por subsistema (cero colisiones)
    metricsCollector.js            Telemetría O(1) (Float64Array, Event Loop, Prometheus /metrics)
    systemDoctor.js                Diagnóstico real de 8 comprobaciones + 3 correcciones en 1 clic
    liveSyncEngine.js              Motor Live Sync: Commit Frames binarios, LRU O(1), Merkle Tree, rollback <2 ms
    liveSyncClient.js              Watcher nativo/Chokidar + reconciliación troceada + cliente WS persistente
    deployManager.js               Pipeline Docker BuildKit + semáforo anti-OOM + enlace BD + watchdog + rollback
    caddyManager.js                Cliente Caddy admin API (PATCH rápido, Zstd/Gzip, HTTP/3, multi-DNS-01, 503, 301)
    ingressManager.js              Reconciliador declarativo, multi-wildcard persistente, diagnóstico 4 capas y TLS
    databaseManager.js             6 motores gestionados, redes aisladas, cron, mutex por BD y retención GFS
    s3Uploader.js                  Cliente S3/R2/MinIO con firma AWS SigV4 nativa (0 dependencias)
    ssrfGuard.js                   Protección SSRF IPv4/IPv6, contención de rutas y escritura atómica 0600
    wordpressMigrator.js           Análisis en vivo, provisión MariaDB e importación SQL segura
    universalImporter.js           Importador Docker Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy
    catalogManager.js              Gestor de servicios 1-clic con secretos cifrados AES-256-GCM
    catalog/templates.js           14 plantillas auditadas en 8 categorías (incluye WordPress 6.7)
    mcpServer.js                   Servidor MCP 2026-07-28 (52 herramientas anotadas con redacción de secretos)
    mcpStreamableHttp.js           Transporte Streamable HTTP 2026-07-28
    projectManager.js              Persistencia atómica con Group Commit y caché serializada/ETag por proyecto
    localRunner.js                 Ejecución local sin shell y GIT_ASKPASS limitado a github.com
    githubService.js               GitHub API (incl. orgs), autodetección y webhooks HMAC
    coolifyMigrator.js             Importador real desde Coolify v4
    cloudflareService.js           API de Cloudflare (DNS + túneles)
    sslManager.js                  Registro X.509 honesto + subida criptográfica PEM / Origin CA
    domainManager.js               Dominios, redirecciones canónicas y resolución O(1)
    notificationService.js         Alertas Telegram, Discord, Slack y webhooks (SSRF-safe)
web/src/                           Panel web (React 19 + Tailwind v4, emblema Twin Planes K, es-ES)
scripts/                           Instalador VPS Debian/Ubuntu + desinstalador + test systemd
tests/                             21 suites + estrés + live-server + paridad competitiva
bench/                             Benchmarks reproducibles (route-swap, live-sync, control-plane)
docs/superpowers/specs/            Especificación arquitectónica y decisiones de diseño
```

---

## Licencia

[Apache-2.0](LICENSE) — Copyright © 2026 Pablo (`macaqueboy`).
