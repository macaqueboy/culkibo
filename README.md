# Culkibo

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js >=20](https://img.shields.io/badge/Node.js-%E2%89%A520-339933.svg)](package.json)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28%20(72%20tools)-18181b.svg)](#conectar-agentes-de-ia-mcp-2026-07-28)

**Orquestador cloud autohospedado, open-source y diseñado para la era de los agentes de IA.**  
Alternativa ultrarrápida, intuitiva y auditable frente a Coolify y Dokploy: Live Sync binario sub-10 ms (*The Forge*), despliegues inmutables sin cortes con **Caddy v2.11** (*The Citadel*), **vistas previas por rama/PR con puerta anti-forks, tareas Cron seguras sin shell, consola de logs/stats/exec en vivo y cancelación + rollback multi-versión**, **Edge Hardening nativo en Caddy (HTTP Basic Auth OpenBSD bcrypt, IP Allowlist CIDR, límite de cuerpo, cabeceras personalizadas, Túneles Cloudflare sin puertos, multi-wildcard SSL persistente + auditoría automática de caducidad TLS)**, **copias de seguridad de BD con snapshot previo automático + deshacer restauración + retención horaria/diaria/semanal + Snapshot completo de instancia cifrado con AES-256-GCM (DR)**, **webhooks multi-Git (GitHub, GitLab, Gitea/Forgejo, Bitbucket) + Deploy Hook CI/CD**, migrador guiado de **WordPress** (subida SQL en streaming hasta 500 MB + `.sql.gz`) e **Importador Universal** (Coolify v4, Compose, Git, Vercel, Netlify, Railway `toml/json`, Render, Dokploy), **72 herramientas MCP `2026-07-28` + `resources/*` y `prompts/*`**, catálogo de **23 servicios en 1 clic (9 categorías incl. IA)** y **cero construcción de comandos de shell**.

**Apache-2.0 · 6 dependencias de runtime · 22 suites + live-server + estrés + benchmarks reproducibles**

---

## Por qué Culkibo

El ciclo habitual de desarrollo con agentes de IA (Claude Code, Cursor, Windsurf, VS Code Copilot, Antigravity) se rompe esperando pipelines:

```text
Tradicional: editar → commit → push → webhook → build Docker (1–4 min) → esperar → ver
Culkibo:     guardar fichero → Commit Frame binario (/ws/sync) → vivo en ~8,1 ms (p50)
             promocionar → BuildKit con caché → healthcheck → conmutación Caddy en ~5,5 ms (p50)
```

Dos planos coordinados —simbolizados por el emblema **Twin Planes K** (espina de control blanca + plano ascendente *Forge Amber* + plano descendente *Citadel*)— sobre el mismo dominio:

- **The Forge (iteración instantánea):** `culkibo sync` agrupa ráfagas de ediciones de IA en *Commit Frames* binarios atómicos por WebSocket (`/ws/sync`, sin sobrecarga base64 y con detachment de slabs de memoria), deduplica por SHA-256 con caché LRU O(1), trocea reconciliaciones grandes (`<=250` archivos / `<=8 MiB`), verifica consistencia real con árbol Merkle cliente/servidor, genera tickets temporales de sincronización y mantiene un ring-buffer en memoria para revertir parches en **~1,2 ms (p50)**.
- **The Citadel (producción inmutable):** semáforo global de concurrencia (`CULKIBO_MAX_CONCURRENT_BUILDS=2`), cancelación segura de builds en curso, historial multi-versión con rollback a cualquier release retenido, tareas **Cron** en contenedor/HTTP sin shell, **Vistas previas** por rama o Pull Request con protección anti-forks y limpieza automática, hooks `pre-deploy` / `post-deploy`, registro unificado de puertos (`portRegistry`), enlace automático con bases de datos gestionadas en red privada, compresión Zstd/Gzip a nivel de servidor Caddy, modo mantenimiento `503` atómico `<10 ms`, watchdog OOM/crash-loop y drenaje seguro con conservación de la versión anterior.

---

## Benchmarks reproducibles (sin simulaciones)

Cada número de esta tabla procede de código real ejecutado contra **Caddy v2.11.9 real** y el daemon real de Culkibo (`npm run bench:all` / `npm test`) — cero `setTimeout` simulados, cero constantes escritas a mano.

| Dimensión | Culkibo v1.0.0 (medido en Node 24 · Win x64) | Coolify / Dokploy / Competidores | Cómo reproducirlo |
|---|---:|---|---|
| **Conmutación de ruta HTTP** (Caddy v2.11.9 admin API) | **p50 5,5 ms · p95 9,8 ms · mín 4,6 ms · 0 HTTP 5xx** | Traefik file throttle 2.000 ms / HTTP poll 5.000 ms (**363×–909× más lento**) | `npm run bench` |
| **Live Sync binario E2E** (disco → `/ws/sync` → HTTP vivo) | **p50 8,07 ms · p95 9,70 ms** (`apply` servidor **p50 0,53 ms**) | Coolify ~4 min · Vercel ~42 s · Dokploy ~30 s | `npm run bench:sync` |
| **Ráfaga IA (15 ficheros simultáneos)** | **1 solo Commit Frame atómico (101,0 ms)** | 15 eventos sueltos o builds encadenados | `npm run bench:sync` |
| **Rollback de parche en memoria** | **p50 1,16 ms · p95 6,09 ms** | Rebuild completo o reinicio de contenedor | `npm run bench:sync` |
| **Arranque en frío y RAM en reposo** | **147,1 ms · 50 MB RSS · 0% CPU** (cabe en VPS 512 MB) | Coolify ≥ 2.048 MB (falla en VPS 1 GB) · Dokploy ~600–900 MB | `npm run bench:control` |
| **Concurrencia plano de control (400 req)** | **3.724 req/s · p50 4,30 ms · p95 9,11 ms · 0 fallos** | PHP/Laravel + Postgres + Redis + Horizon | `npm run bench:control` |
| **Panel web precomprimido (zero-copy fast-path)** | **Brotli-11 / Gzip-9 en RAM + ETag/304 (0 carga Express)** | Compresión al vuelo por cada visita | `GET /` · `GET /assets/*` |
| **Estrés mixto (100 req: GET + POST concurrentes)** | **100/100 éxito · 57,6 ms media · 0 fallos** | Sin fast-path O(1) nativo | `node tests/stress.test.js` |
| **WebSocket fan-out (40 clientes)** | **40/40 clientes listos en 23,7 ms · 0 caídas bajo churn** | Polling / Pusher / Soketi extra | `npm run bench:control` |
| **Dependencias de runtime** | **6** (`express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) | Cientos de paquetes PHP/Composer o monorepo Next.js | `package.json` |
| **Construcción de comandos de shell** | **0** (verificado en CI por escáner estático) | 21 avisos críticos RCE en Coolify · 34 en Dokploy | `node tests/shell-safety.test.js` |
| **Superficie MCP (`2026-07-28`)** | **72 herramientas anotadas (41 mutadoras) + `resources/*` + `prompts/*`** | Coolify: 3 mutadoras · Dokploy: sin MCP nativo | `POST /api/mcp` (`tools/list`) |
| **Observabilidad y Doctor en 1 clic** | **Prometheus `/metrics` + p50/p95/p99 + Event Loop + 9 checks + Audit log** | Requiere stack Prometheus/Grafana externo | `GET /metrics` · `#/metrics` |

---

## Dominios, Edge Hardening, Multi-Wildcard SSL y Túneles

- **Asistente en 4 modos:** dominio propio con TLS automático (Let's Encrypt / ZeroSSL), redirección canónica 301 `www ↔ raíz`, **multi-wildcard DNS-01** (`*.a.com`, `*.b.com`, … con [`Dockerfile.caddy`](Dockerfile.caddy)) y **Túnel Cloudflare (sin abrir puertos)** con gestión guiada en 3 pasos desde el panel.
- **Edge Hardening por dominio (nativo en Caddy, cero plugins):**
  - **HTTP Basic Auth** con bcrypt OpenBSD puro (`$2a$`/`$2b$`, cero dependencias nativas) y `hash_cache` en memoria.
  - **IP Allowlist CIDR** (rechazo 403 en el borde mediante `subroute` + `not.client_ip`).
  - **Límite de tamaño de petición** (`request_body`), política `X-Frame-Options` (`DENY` / `SAMEORIGIN`), cabeceras de respuesta/petición personalizadas y compresión **Zstd + Gzip**.
- **Certificados propios / Cloudflare Origin CA:** selector visual de archivos `.pem`/`.key` con verificación criptográfica X.509 de par público/privado, carga directa en Caddy y **watchdog automático de caducidad TLS (<14 días)** con alertas deduplicadas.
- **Diagnóstico en 4 capas:** comprueba en vivo **DNS → Ruta Caddy → Certificado TLS (handshake real) → Puerto TCP destino** con recomendaciones claras en español.

---

## Comparativa honesta

| Capacidad | Culkibo | Coolify | Dokploy | CapRover / Dokku |
|---|:---:|:---:|:---:|:---:|
| Plano de datos Caddy atómico (TLS bajo demanda + Zstd/Gzip + HTTP/3 + Basic Auth + IP Allowlist) | ✅ | Traefik (poll 2–5 s) | Traefik | nginx |
| Asistente 4 modos (DNS, `www` 301, multi-wildcard DNS-01, Túnel Cloudflare) + PEM/Origin CA + auditoría TLS | ✅ | Manual | Manual | Manual |
| Live Sync binario sub-10 ms (Commit Frames + Merkle + Rollback ~1 ms) | ✅ | ❌ | ❌ | ❌ |
| Vistas previas por rama/PR (anti-forks) + Tareas Cron sin shell + Logs/Stats/Exec en vivo | ✅ | Parcial | Parcial | Parcial |
| Multi-Git Webhooks (GitHub, GitLab, Gitea, Bitbucket) + Monorepo `watchPaths` + Deploy Hook CI/CD | ✅ | ✅ | Parcial | Manual |
| Migrador guiado de WordPress (análisis en vivo + MariaDB + streaming SQL 500 MB / `.sql.gz`) | ✅ | Plantilla básica | Plantilla básica | Plantilla básica |
| Importador universal (Coolify v4, Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy) | ✅ | ❌ | ❌ | ❌ |
| Bases de datos (6 motores) + snapshot pre-restauración + deshacer + S3/R2 + DR instancia cifrado AES-256-GCM | ✅ | Parcial | Parcial | Manual |
| Catálogo 1-clic con redes aisladas, editor de variables, stats y secretos AES-256-GCM (23 plantillas / 9 cat. incl. IA) | ✅ | ✅ | ✅ | ✅ |
| Hub en directo de Agentes IA + MCP `2026-07-28` (72 herramientas, 41 mutadoras, `resources/*` y `prompts/*`) | ✅ | Parcial (3) | ❌ | ❌ |
| Observabilidad nativa (Prometheus `/metrics`, p50/p95/p99, Event Loop, Doctor 9 checks, Audit log) | ✅ | Externa | Básica | ❌ |
| Cero `exec`/`sh -c` + protección SSRF IPv4/IPv6 + tickets WS de un solo uso + `0600` + UX sin AI slop (atajos `?`, `Ctrl+K`) | ✅ | ❌ | ❌ | Parcial |
| Consumo en VPS de 512 MB / 1 GB RAM | ✅ (~50 MB) | ❌ (≥ 2 GB) | Ajustado | ✅ |
| **Multi-servidor / cluster Swarm-K8s** | 🚧 Roadmap (1 VPS hoy) | ✅ | ✅ | Swarm |

> **Honestidad radical:** Culkibo v1.0 gestiona un único host (VPS o máquina local). La orquestación multi-servidor está en el roadmap; todo lo marcado con ✅ está implementado, probado en las 22 suites + navegador en vivo (escritorio y móvil) y verificable en este repositorio.

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

En Windows: `./start.ps1`. Panel web en `http://localhost:3030` (pulsa `?` para ver atajos de teclado o `Ctrl+K` / `⌘K` para la paleta de comandos).

---

## Seguridad por construcción

1. **Cero construcción de comandos de shell:** todos los subprocesos (`git`, `docker`, `npm`, `caddy`, `cron`, `exec`) se lanzan con `spawn()` / `execFile()` y arrays `argv` validados por [`safeCommand.js`](server/services/safeCommand.js) (`shell: false`). Los secretos viajan por `--env-file` efímeros (`0600`) o `GIT_ASKPASS`, jamás en `argv` ni en `.git/config`. El invariante se verifica en cada commit con [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
2. **Aislamiento de red por servicio y base de datos:** cada base de datos gestionada y cada servicio del catálogo recibe su propia red Docker bridge privada sin puertos publicados por defecto (`127.0.0.1` sólo bajo petición, `0.0.0.0` sólo con confirmación explícita de riesgo UFW/Docker). El enlace Proyecto ↔ BD conecta el contenedor en runtime sin guardar contraseñas en `projects.json`.
3. **Cifrado en reposo, DR cifrado e integridad verificada:** credenciales de bases de datos, secretos del catálogo, configuración S3/R2 y **Snapshots completos de instancia (DR)** se cifran con **AES-256-GCM + scrypt** (`0600`), los respaldos incluyen y verifican checksums **SHA-256** antes de restaurar, y las respuestas MCP redactan automáticamente valores sensibles.
4. **Autenticación HTTP + WebSocket + Audit Log + Rate Limit:**
   - Validación estricta de `Origin`, bloqueo de spoofing `X-Forwarded-For` / `Forwarded` + SSRF IPv4/IPv6 y limitador LRU compartido (`rateLimiter.js`).
   - Token de 256 bits comparado en tiempo constante (`crypto.timingSafeEqual`) y tickets WebSocket efímeros de un solo uso (`/api/auth/ws-ticket`) ligados a IP, sin envío del token maestro por subprotocolo WS.
   - Registro de auditoría append-only (`data/audit.jsonl`, `0600`, rotación automática) con redacción recursiva de secretos.

---

## CLI

```bash
node bin/culkibo.js start                               # arranca el daemon y el panel
node bin/culkibo.js status                              # estado operativo y memoria RSS
node bin/culkibo.js doctor                              # diagnóstico (9 comprobaciones)

node bin/culkibo.js sync <projectId> [dir]              # Live Sync en tiempo real hacia The Forge
node bin/culkibo.js deploy <projectId>                  # despliegue a producción en The Citadel
node bin/culkibo.js rollback <projectId>                # rollback instantáneo a versión anterior

node bin/culkibo.js catalog list                        # listar las 23 plantillas de 1 clic (9 categorías incl. IA)
node bin/culkibo.js update                              # actualizar Culkibo sin shell ni pérdida de estado
node bin/culkibo.js pod list                            # estado de The Forge y The Citadel
node bin/culkibo.js domain list                         # dominios y estado TLS real
node bin/culkibo.js docker                              # inspección de contenedores
node bin/culkibo.js ingress <hostname>                  # ruta y estado real en Caddy

node bin/culkibo.js backup <projectId>                  # exportar proyecto con checksum SHA-256
node bin/culkibo.js restore <archivo.json>              # restaurar verificando integridad SHA-256
node bin/culkibo.js telemetry status|preview|disable    # inspeccionar o desactivar telemetría anónima
node bin/culkibo.js mcp                                 # servidor MCP por stdio (logs a stderr)
```

---

## Conectar agentes de IA (MCP `2026-07-28`)

Culkibo expone **72 herramientas anotadas** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), incluyendo **41 herramientas de escritura**, además de **`resources/*`** (4 recursos vivos de solo lectura) y **`prompts/*`** (3 flujos guiados): desplegar/cancelar/revertir en producción, consultar logs/stats o ejecutar comandos seguros en contenedores, gestionar tareas Cron y vistas previas por rama/PR, activar modo mantenimiento `<10 ms`, configurar Basic Auth / IP Allowlist / túneles Cloudflare / auditoría TLS, aprovisionar/inspeccionar bases de datos, backups S3/R2 y snapshots completos de instancia (DR), instalar y actualizar servicios del catálogo, analizar webs WordPress, importar stacks Docker Compose y verificar árboles Merkle de Live Sync.

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
npm test                      # 24 suites + live-server + websocket-stress + stress
npm run test:bench            # aserciones estrictas de benchmarks y paridad competitiva
npm run bench:all             # reporte completo de los 3 benchmarks reales
```

### Cobertura de las 24 suites (`tests/run-all.js`)

| Suite | Qué verifica |
|---|---|
| `shell-safety.test.js` | 0 construcción de comandos de shell en `server/`, `bin/`, `scripts/`, `bench/` |
| `security-hardening.test.js` | C1–C6, H1–H9: SSRF (metadata/RFC1918/S3/webhooks), proxy loopback spoofing, symlinks, PAT scoping, redacción MCP |
| `competitor-prs.test.js` | Regresiones de PRs/CVEs de competidores (Coolify, Dokploy, CapRover, Dokku, Kamal, Caddy, Portainer, Traefik, NPM, Nixpacks/Railpack, Runtipi, Backrest, MCP SDK): DNS rebinding, WS brute-force, fail-closed HMAC/fork, `::ffff:` CIDR, bcrypt cost, canonical loop, PEM multi-block, Dockerfiles multi-stack, GFS UTC, GCM authTagLength, webhook secret reset, MCP `rawMeta` |
| `telemetry.test.js` | Saneado anti-PII de 11 fases, deduplicación por fingerprint, cola con prioridad, circuit breaker exponencial, precedencia opt-out (`CULKIBO_TELEMETRY=0`/`DO_NOT_TRACK=1`), endpoints `/api/telemetry/*` y entrega E2E al recolector cloud |
| `metrics-and-bugs.test.js` | XFF leftmost spoof, IPv6-mapped hex SSRF, tickets WS de un solo uso, rate-limit auth, Prometheus `/metrics`, Doctor 9 checks y regresiones profundas |
| `scale-and-wildcard.test.js` | Multi-wildcard DNS-01 persistente, 301 `www`, mantenimiento 503, PEM/Origin CA X.509 match/mismatch, `portRegistry` 20-way, semáforo de builds, MCP redaction (72 tools), SHA-256 tamper rejection, Live Sync 520-file chunking, static `br`/ETag/304 |
| `resilience-and-features.test.js` | `safeCommand` anti-inyección, `cronParser`/`CronManager` CRUD, `previewManager` RFC-1123 + anti-forks, OpenBSD `bcryptHash` + Caddy Basic Auth/IP Allowlist/Body Limit, auditoría TLS, DR snapshot cifrado AES-256-GCM + `dryRun`, multi-Git webhooks + `watchPaths`, WordPress MySQL 8 sanitizer, `railway.toml`, 23 plantillas catálogo, `auditLogger`/`rateLimiter`, runtime HTTP 200 y MCP `72 tools`/`resources`/`prompts` |
| `importers.test.js` | Migrador WordPress en vivo + reescritura SQL segura + Docker Compose + Vercel/Netlify/Railway/Render/Dokploy + Git URLs |
| `live-sync.test.js` | Path traversal, Commit Frames binarios, SHA-256 dedup, Merkle Tree, rollback <4 ms, auth WS `/ws/sync`, E2E real |
| `competitor-benchmarks.test.js` | Aserciones reales de RAM, arranque, concurrencia, Live Sync, Caddy cutover 0×5xx, MCP y catálogo |
| `caddy.test.js` | Caddy admin API real: config base, `@id`, actualización in-situ, canario 10/90, rollback ante error |
| `deploy.test.js` | BuildKit, detección de stacks, secretos fuera de argv, cutover con drenaje, rollback real Docker |
| `database.test.js` | 6 motores, AES-256-GCM, lista blanca, AWS SigV4 byte a byte, multipart S3/R2, cron, retención GFS |
| `catalog.test.js` | 23 plantillas en 9 categorías (incluye WordPress e IA), imágenes fijadas, secretos, puertos `42000-42999`, proyección segura |
| `mcp.test.js` | 72 herramientas anotadas, `resources/*`, `prompts/*`, JSON-RPC 2.0, Streamable HTTP `2026-07-28`, `server/discover`, SSE y errores |
| `ssl.test.js` | Registro X.509 real, purga de PEMs fabricados, TLS bajo demanda delegado a Caddy |
| `domain.test.js` | Rutas exactas, comodines con frontera de etiqueta, anti-duplicados, proxy Cloudflare |
| `cloudflare.test.js` | Zonas, registros DNS, TXT ACME DNS-01 y túneles |
| `github.test.js` | OAuth, autodetección de stacks, firma HMAC SHA-256, idempotencia de redeliveries |
| `coolifyMigrator.test.js` | Extracción y agrupación desde Coolify v4 (apps, DBs, servicios, volúmenes) |
| `localRunner.test.js` | `GIT_ASKPASS`, puertos, traversal, Unicode, estáticos y procesos |
| `stop-lifecycle.test.js` | Arranque, parada, hibernación, liberación real de puertos y persistencia atómica |
| `orchestrator.test.js` | Métricas reales del daemon (RSS/CPU), watchers y logs |
| `backup.test.js` | Exportación, restauración con SHA-256 y volcados sin shell |

Más `live-server.test.js`, `websocket-stress.test.js` (30 clientes concurrentes con churn y cierre limpio) y `stress.test.js` (100 peticiones mixtas simultáneas).

---

## Estructura

```text
Dockerfile                         Imagen del plano de control (Node 22 + docker-cli-buildx)
Dockerfile.caddy                   Imagen Caddy v2.11 + xcaddy caddy-dns/cloudflare (multi-wildcard DNS-01)
bin/culkibo.js                     CLI (start, sync, deploy, rollback, catalog, doctor, mcp...)
server/
  index.js                         Daemon HTTP + fast-path estático/API precomprimido + WebSocket (/ws y /ws/sync)
  middleware/auth.js               Auth por Origen + Token en tiempo constante + tickets WS efímeros (HTTP y WS)
  routes/api.js                    API REST completa (deploys, crons, previews, edge, DR, webhooks multi-Git)
  services/
    safeCommand.js                 Tokenizador argv seguro sin shell (para exec, hooks y tareas Cron)
    cronParser.js / cronManager.js Parser 5 campos + planificador Cron por proyecto con historial
    previewManager.js              Vistas previas aisladas por rama/PR con protección anti-forks y reaper TTL
    bcryptHash.js                  Implementación pura de OpenBSD bcrypt ($2a$/$2b$) para Caddy Basic Auth
    webhookService.js              Webhooks multi-Git (GitHub/GitLab/Gitea/Bitbucket), monorepo y Deploy Hook
    auditLogger.js                 Audit log append-only (0600, rotación 5 MB, redacción recursiva de secretos)
    rateLimiter.js                 Limitador LRU compartido con resolución segura de proxies de confianza
    portRegistry.js                Registro unificado de puertos por subsistema (cero colisiones)
    metricsCollector.js            Telemetría O(1) (Float64Array, Event Loop, Prometheus /metrics)
    systemDoctor.js                Diagnóstico real de 9 comprobaciones + correcciones en 1 clic
    liveSyncEngine.js              Motor Live Sync: Commit Frames binarios, LRU O(1), Merkle Tree, rollback ~1 ms
    liveSyncClient.js              Watcher nativo/Chokidar + reconciliación troceada + cliente WS persistente
    deployManager.js               Pipeline Docker BuildKit + cancelación + multi-rollback + logs/stats/exec en vivo
    caddyManager.js                Cliente Caddy admin API (Basic Auth, IP Allowlist, Zstd/Gzip, HTTP/3, multi-DNS-01)
    ingressManager.js              Reconciliador declarativo, multi-wildcard, diagnóstico 4 capas y watchdog TLS
    databaseManager.js             6 motores, snapshot pre-restauración + deshacer, cron, S3/R2 y retención horaria/GFS
    dbBackupManager.js             Exportación/importación de proyectos y Snapshot completo de instancia (AES-256-GCM)
    s3Uploader.js                  Cliente S3/R2/MinIO con firma AWS SigV4 nativa y listado remoto (0 dependencias)
    ssrfGuard.js                   Protección SSRF IPv4/IPv6, contención de rutas y escritura atómica 0600
    wordpressMigrator.js           Análisis en vivo, MariaDB, streaming SQL 500 MB / .sql.gz y limpieza MySQL 8
    universalImporter.js           Importador Docker Compose, Git, Vercel/Netlify/Railway (TOML/JSON)/Render/Dokploy
    catalogManager.js              Gestor de servicios 1-clic con env editor, stats, updates y secretos AES-256-GCM
    catalog/templates.js           23 plantillas auditadas en 9 categorías (incluye WordPress 6.7 e IA)
    mcpServer.js                   Servidor MCP 2026-07-28 (72 herramientas, 4 resources, 3 prompts, redacción)
    mcpStreamableHttp.js           Transporte Streamable HTTP 2026-07-28
    projectManager.js              Persistencia atómica con Group Commit y caché serializada/ETag por proyecto
    localRunner.js                 Ejecución local sin shell y GIT_ASKPASS limitado a github.com
    githubService.js               GitHub API (incl. orgs), autodetección y webhooks HMAC
    coolifyMigrator.js             Importador real desde Coolify v4
    cloudflareService.js           API de Cloudflare (DNS + gestión guiada de Túneles Cloudflare)
    sslManager.js                  Registro X.509 real + subida criptográfica PEM / Origin CA
    domainManager.js               Dominios, Basic Auth, IP Allowlist, redirecciones canónicas y resolución O(1)
    notificationService.js         Alertas Telegram, Discord, Slack y webhooks HMAC (14 eventos + historial)
    telemetryService.js            Telemetría anónima opt-out, saneado 11 fases, fingerprint dedup y circuit breaker
telemetry-collector/               Recolector cloud autónomo (0 deps, SQLite WAL + panel Ops + Cloudflare Workers/D1)
web/src/                           Panel web (React 19 + Tailwind v4, HelpTip, ErrorBoundary, atajos ?, Ctrl+K, es-ES)
scripts/                           Instalador VPS Debian/Ubuntu + desinstalador + test systemd
tests/                             24 suites + estrés + live-server + paridad competitiva
bench/                             Benchmarks reproducibles (route-swap, live-sync, control-plane)
PRIVACY.md                         Política transparente de telemetría anónima y guía de opt-out
docs/superpowers/specs/            Especificación arquitectónica y decisiones de diseño
```

---

## Telemetría y privacidad

Culkibo envía informes anónimos de fallos, errores de la interfaz y métricas agregadas para corregir problemas rápidamente en versiones públicas. **Nunca** recopila secretos, contraseñas, dominios, IPs ni datos de negocio. Puedes inspeccionar el sobre JSON exacto en `Ajustes → Sistema` (o con `node bin/culkibo.js telemetry preview`) y desactivarla en cualquier momento (`CULKIBO_TELEMETRY=0`, `DO_NOT_TRACK=1`, CLI o panel web). Consulta [PRIVACY.md](PRIVACY.md) y [telemetry-collector/README.md](telemetry-collector/README.md).

---

## Licencia

[Apache-2.0](LICENSE) — Copyright © 2026 Pablo (`macaqueboy`).
