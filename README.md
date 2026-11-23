# Culkibo

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js >=20](https://img.shields.io/badge/Node.js-%E2%89%A520-339933.svg)](package.json)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28%20(49%20tools)-18181b.svg)](#conectar-agentes-de-ia-mcp-2026-07-28)

**Orquestador cloud autohospedado, open-source y diseñado para la era de los agentes de IA.**  
Alternativa ultrarrápida, auditable y fácil de usar frente a Coolify y Dokploy: Live Sync binario sub-20 ms (*The Forge*), despliegues inmutables sin cortes con Caddy (*The Citadel*), **observabilidad en vivo + Prometheus `/metrics` + System Doctor en 1 clic**, paleta global `Cmd+K`, migrador guiado de **WordPress** e **Importador Universal** (Coolify, Docker Compose, cualquier URL Git, Vercel, Netlify, Railway, Render, Dokploy), asistente de **Dominios y Wildcard SSL** en 3 pasos, enlace en directo con **Agentes IA (`49` herramientas MCP `2026-07-28`)**, catálogo de **14 servicios en 1 clic** y **cero construcción de comandos de shell**.

**Apache-2.0 · 6 dependencias de runtime · 20 suites + live-server + estrés + benchmarks reproducibles**

---

## Por qué Culkibo

El ciclo habitual de desarrollo con agentes de IA (Claude Code, Cursor, Windsurf, VS Code Copilot, Antigravity) se rompe esperando pipelines:

```text
Tradicional: editar → commit → push → webhook → build Docker (1–4 min) → esperar → ver
Culkibo:     guardar fichero → Commit Frame binario (/ws/sync) → vivo en ~8,5 ms (p50)
             promocionar → BuildKit con caché → healthcheck → conmutación Caddy en ~7–10 ms (p50)
```

Dos planos coordinados sobre el mismo dominio:

- **The Forge (iteración instantánea):** `culkibo sync` agrupa ráfagas de ediciones de IA en *Commit Frames* binarios atómicos por WebSocket (`/ws/sync`, sin sobrecarga base64), deduplica por SHA-256 en cliente y servidor, verifica consistencia con árbol Merkle, distingue recarga en caliente (`path_b_hot`) de reinicio (`path_c_restart`) y mantiene un ring-buffer acotado en memoria para revertir parches en **<4 ms**.
- **The Citadel (producción inmutable):** construye imágenes Docker con BuildKit (`# syntax=docker/dockerfile:1.7` + `--mount=type=cache` persistente para Next.js, Vite, Node, Python, Go y estáticos), verifica salud real, conmuta la ruta de forma atómica vía API de administración de Caddy (`grace_period` de 10 s), drena conexiones y conserva la versión anterior para rollback sin reconstruir.

---

## Benchmarks reproducibles (sin simulaciones)

Cada número de esta tabla procede de código real ejecutado contra **Caddy v2.11.9 real** y el daemon real de Culkibo — cero `setTimeout` simulados, cero constantes escritas a mano. Puedes reproducirlos en tu propia máquina con `npm run bench:all` y validarlos como aserciones con `npm run test:bench`.

| Dimensión | Culkibo v1.0.0 (medido en Node 24 · Win x64) | Coolify / Dokploy / Competidores | Cómo reproducirlo |
|---|---:|---|---|
| **Conmutación de ruta HTTP** (Caddy v2.11.9 admin API) | **p50 7,0–9,6 ms · p95 11,9–12,7 ms · 0 HTTP 5xx** | Traefik file throttle 2.000 ms / HTTP poll 5.000 ms (**208×–714× más lento**) | `npm run bench` |
| **Live Sync binario E2E** (disco → `/ws/sync` → HTTP vivo) | **p50 7,3–25,3 ms** (`apply` servidor **0,74–3,5 ms**) | Coolify ~4 min · Vercel ~42 s · Dokploy ~30 s | `npm run bench:sync` |
| **Ráfaga IA (15 ficheros simultáneos)** | **1 solo Commit Frame atómico (~101–236 ms)** | 15 eventos sueltos o builds encadenados | `npm run bench:sync` |
| **Rollback de parche en memoria** | **p50 0,65–1,98 ms · p95 4,27 ms** | Rebuild completo o reinicio de contenedor | `npm run bench:sync` |
| **Arranque en frío y RAM en reposo** | **115–284 ms · 49–62 MB RSS · 0% CPU** (cabe en VPS 512 MB) | Coolify ≥ 2.048 MB (falla en VPS 1 GB) · Dokploy ~600–900 MB | `npm run bench:control` |
| **Concurrencia plano de control (200–400 req)** | **1.781–3.508 req/s · p95 9,4–19,0 ms · 0 fallos** | PHP/Laravel + Postgres + Redis + Horizon | `npm run bench:control` |
| **Estrés mixto (100 req: GET + POST concurrentes)** | **100/100 éxito · 87–92 ms media · 0 fallos** | Sin fast-path O(1) nativo | `node tests/stress.test.js` |
| **WebSocket fan-out (40 clientes)** | **40/40 clientes listos · 0 caídas bajo churn** | Polling / Pusher / Soketi extra | `npm run bench:control` |
| **Dependencias de runtime** | **6** (`express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) | Cientos de paquetes PHP/Composer o monorepo Next.js | `package.json` |
| **Construcción de comandos de shell** | **0** (verificado en CI por escáner estático) | 21 avisos críticos RCE en Coolify · 34 en Dokploy | `node tests/shell-safety.test.js` |
| **Superficie MCP (`2026-07-28`)** | **49 herramientas anotadas (26 mutadoras)** | Coolify: 3 mutadoras · Dokploy: sin MCP nativo | `POST /api/mcp` (`tools/list`) |
| **Observabilidad y Doctor en 1 clic** | **Prometheus `/metrics` + p50/p95/p99 + Event Loop + 8 checks** | Requiere stack Prometheus/Grafana externo | `GET /metrics` · `#/metrics` |

---

## Comparativa honesta

| Capacidad | Culkibo | Coolify | Dokploy | CapRover / Dokku |
|---|:---:|:---:|:---:|:---:|
| Plano de datos Caddy atómico (TLS bajo demanda + `grace_period`) | ✅ | Traefik (poll 2–5 s) | Traefik | nginx |
| Asistente 3 pasos para dominios, proveedores DNS y Wildcard Cloudflare DNS-01 | ✅ | Manual | Manual | Manual |
| Live Sync binario sub-20 ms (Commit Frames + Merkle + Rollback <4 ms) | ✅ | ❌ | ❌ | ❌ |
| Migrador guiado de WordPress (análisis en vivo + MariaDB + SQL / 512 MB) | ✅ | Plantilla básica | Plantilla básica | Plantilla básica |
| Importador universal (Coolify v4, Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy) | ✅ | ❌ | ❌ | ❌ |
| Builds Docker con BuildKit cache mounts (Next/Vite/Node/Python/Go) | ✅ | ✅ (caché frágil) | ✅ | Parcial |
| Bases de datos gestionadas (6 motores: PG, MySQL, MariaDB, Redis, Valkey, Mongo) | ✅ | ✅ | ✅ | Parcial |
| Backups programados (cron) + S3 / Cloudflare R2 / MinIO + retención GFS | ✅ | ✅ | ✅ | Manual |
| Catálogo 1-clic con redes aisladas y secretos AES-256-GCM (14 plantillas) | ✅ | ✅ | ✅ | ✅ |
| Hub en directo de Agentes IA + MCP `2026-07-28` (49 herramientas, 26 mutadoras) | ✅ | Parcial (3) | ❌ | ❌ |
| Observabilidad nativa (Prometheus `/metrics`, p50/p95/p99, Event Loop, Doctor 1-clic) | ✅ | Externa | Básica | ❌ |
| Cero `exec`/`sh -c` + protección SSRF IPv4/IPv6 + tickets WS de un solo uso + `0600` | ✅ | ❌ | ❌ | Parcial |
| Consumo en VPS de 512 MB / 1 GB RAM | ✅ (~49–62 MB) | ❌ (≥ 2 GB) | Ajustado | ✅ |
| **Multi-servidor / cluster Swarm-K8s** | 🚧 Roadmap (1 VPS hoy) | ✅ | ✅ | Swarm |

> **Honestidad radical:** Culkibo hoy gestiona un único host (VPS o máquina local). La orquestación multi-servidor está en el roadmap; todo lo marcado con ✅ está implementado, probado en CI y verificable en este repositorio.

---

## Instalación

### 1. VPS Debian / Ubuntu (1 línea, producción)

Instala usuario sin privilegios `culkibo`, Node 22, Docker, Caddy con TLS automático, unidad `systemd` endurecida, token aleatorio con permisos `0600` en `data/auth.json` y servicio escuchando en loopback tras Caddy:

```bash
curl -fsSL https://raw.githubusercontent.com/macaqueboy/culkibo/main/scripts/install.sh | sudo bash
```

Para desinstalar limpiamente: `sudo bash /opt/culkibo/scripts/uninstall.sh`.  
El instalador cuenta con su propio banco de pruebas contra un contenedor Debian 12 real con `systemd` ([`scripts/test-install.sh`](scripts/test-install.sh)).

### 2. Docker Compose (Culkibo + Caddy v2.11)

```bash
git clone https://github.com/macaqueboy/culkibo.git
cd culkibo
docker compose up -d --build
```

Levanta el daemon de Culkibo en `http://127.0.0.1:3030` conectado por red interna privada a `caddy:2.11-alpine` (el puerto admin `:2019` de Caddy jamás se expone al host).

### 3. Desarrollo local (Linux, macOS, Windows)

Requiere Node.js 20+ (recomendado Node 22). Docker y Caddy son opcionales en local: sin ellos, Culkibo ejecuta proyectos como procesos locales y degrada con mensajes explícitos.

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
2. **Aislamiento de red por servicio y base de datos:** cada base de datos gestionada y cada servicio del catálogo recibe su propia red Docker bridge privada sin puertos publicados por defecto (`127.0.0.1` sólo bajo petición, `0.0.0.0` sólo con confirmación explícita de riesgo UFW/Docker).
3. **Cifrado en reposo:** credenciales de bases de datos, secretos del catálogo y configuración S3/R2 se cifran con **AES-256-GCM** con claves locales en `data/` (`0600`, ignoradas en `.gitignore`).
4. **Autenticación HTTP + WebSocket + Panel remoto (`AuthGate`):**
   - Validación de `Origin` (evita ataques DNS rebinding / cross-site desde el navegador del desarrollador).
   - Token de 256 bits comparado en tiempo constante (`crypto.timingSafeEqual`), exigido automáticamente en conexiones no-loopback (o siempre con `CULKIBO_REQUIRE_TOKEN=1`), tanto en REST como en upgrades WebSocket (`/ws` y `/ws/sync` vía subprotocolo `culkibo-token.<token>`).
   - Al acceder al panel desde un VPS remoto, `AuthGate` solicita el token de `data/auth.json` antes de abrir sockets o cargar datos.

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

node bin/culkibo.js backup <projectId>                  # exportar proyecto
node bin/culkibo.js restore <archivo.json>              # restaurar desde backup
node bin/culkibo.js mcp                                 # servidor MCP por stdio
```

---

## Conectar agentes de IA (MCP `2026-07-28`)

Culkibo expone **49 herramientas anotadas** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), incluyendo 26 herramientas de escritura: desplegar a producción, hacer rollback, aprovisionar bases de datos, disparar copias S3/R2, instalar/desinstalar del catálogo, analizar webs WordPress, importar stacks Docker Compose, consultar acceso remoto, inspeccionar métricas y diagnóstico (`culkibo_get_metrics`, `culkibo_system_doctor`), verificar árboles Merkle de Live Sync, revertir parches en <4 ms, promocionar Forge → Citadel y migrar desde Coolify.

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

### Cursor, Windsurf y clientes Streamable HTTP (`2026-07-28`)

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
npm run web:build             # compilación Vite + TypeScript del panel web
npm test                      # 20 suites + live-server + websocket-stress + stress
npm run test:bench            # aserciones estrictas de benchmarks y paridad competitiva
npm run bench:all             # reporte completo de los 3 benchmarks reales
```

### Cobertura de las 20 suites (`tests/run-all.js`)

| Suite | Qué verifica |
|---|---|
| `shell-safety.test.js` | 0 construcción de comandos de shell en `server/`, `bin/`, `scripts/`, `bench/` |
| `security-hardening.test.js` | C1–C6, H1–H9: SSRF (metadata/RFC1918/S3/webhooks), proxy loopback spoofing, symlinks, PAT scoping, redacción MCP |
| `metrics-and-bugs.test.js` | XFF leftmost spoof, IPv6-mapped hex SSRF, tickets WS de un solo uso, rate-limit auth, Prometheus `/metrics`, Doctor 8 checks y regresiones profundas |
| `importers.test.js` | Migrador WordPress en vivo + reescritura SQL segura + Docker Compose + Vercel/Netlify/Railway/Render/Dokploy + Git URLs |
| `live-sync.test.js` | Path traversal, Commit Frames binarios, SHA-256 dedup, Merkle Tree, rollback <4 ms, auth WS `/ws/sync`, E2E real |
| `competitor-benchmarks.test.js` | Aserciones reales de RAM, arranque, concurrencia, Live Sync, Caddy cutover 0×5xx, MCP y catálogo |
| `caddy.test.js` | Caddy admin API real: config base, `@id`, actualización in-situ, canario 10/90, rollback ante error |
| `deploy.test.js` | BuildKit, detección de stacks, secretos fuera de argv, cutover con drenaje, rollback real Docker |
| `database.test.js` | 6 motores, AES-256-GCM, lista blanca, AWS SigV4 byte a byte, multipart S3/R2, cron, retención GFS |
| `catalog.test.js` | 14 plantillas en 8 categorías (incluye WordPress), imágenes fijadas, secretos, puertos `42000-42999`, proyección segura |
| `mcp.test.js` | 49 herramientas anotadas, JSON-RPC 2.0, Streamable HTTP `2026-07-28`, `server/discover`, SSE y errores |
| `ssl.test.js` | Registro X.509 real, purga de PEMs fabricados, TLS bajo demanda delegado a Caddy |
| `domain.test.js` | Rutas exactas, comodines con frontera de etiqueta, anti-duplicados, proxy Cloudflare |
| `cloudflare.test.js` | Zonas, registros DNS, TXT ACME DNS-01 y túneles |
| `github.test.js` | OAuth, autodetección de stacks, firma HMAC SHA-256, idempotencia de redeliveries |
| `coolifyMigrator.test.js` | Extracción y agrupación desde Coolify v4 (apps, DBs, servicios, volúmenes) |
| `localRunner.test.js` | `GIT_ASKPASS`, puertos, traversal, Unicode, estáticos y procesos |
| `stop-lifecycle.test.js` | Arranque, parada, hibernación, liberación real de puertos y persistencia atómica |
| `orchestrator.test.js` | Métricas reales del daemon (RSS/CPU), watchers y logs |
| `backup.test.js` | Exportación, restauración y volcados sin shell |

Más `live-server.test.js`, `websocket-stress.test.js` (30 clientes concurrentes con churn) y `stress.test.js` (100 peticiones mixtas simultáneas).

---

## Estructura

```text
bin/culkibo.js                     CLI (start, sync, deploy, rollback, catalog, doctor, mcp...)
server/
  index.js                         Daemon HTTP + WebSocket (/ws y /ws/sync) + plano de control
  middleware/auth.js               Auth por Origen + Token en tiempo constante (HTTP y WS)
  routes/api.js                    API REST completa
  services/
    metricsCollector.js            Telemetría O(1) (Float64Array, Event Loop, Prometheus /metrics)
    systemDoctor.js                Diagnóstico real de 8 comprobaciones + 3 correcciones en 1 clic
    liveSyncEngine.js              Motor Live Sync: Commit Frames, Merkle Tree, rollback <15 ms
    liveSyncClient.js              Watcher nativo/Chokidar + cliente WS persistente para The Forge
    deployManager.js               Pipeline de producción Docker BuildKit + healthcheck + rollback
    caddyManager.js                Cliente Caddy admin API (PATCH rápido, grace_period, DNS-01)
    ingressManager.js              Reconciliador declarativo de rutas, canarios y sondas TLS
    databaseManager.js             6 motores gestionados, redes aisladas, cron y retención GFS
    s3Uploader.js                  Cliente S3/R2/MinIO con firma AWS SigV4 nativa (0 dependencias)
    ssrfGuard.js                   Protección SSRF IPv4/IPv6, contención de rutas y escritura atómica 0600
    wordpressMigrator.js           Análisis en vivo, provisión MariaDB e importación SQL segura
    universalImporter.js           Importador Docker Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy
    catalogManager.js              Gestor de servicios 1-clic con secretos cifrados AES-256-GCM
    catalog/templates.js           14 plantillas auditadas en 8 categorías (incluye WordPress 6.7)
    mcpServer.js                   Servidor MCP 2026-07-28 (49 herramientas anotadas)
    mcpStreamableHttp.js           Transporte Streamable HTTP 2026-07-28
    projectManager.js              Persistencia atómica con Group Commit y caché serializada
    localRunner.js                 Ejecución local sin shell y GIT_ASKPASS limitado a github.com
    githubService.js               GitHub API, autodetección y webhooks HMAC
    coolifyMigrator.js             Importador real desde Coolify v4
    cloudflareService.js           API de Cloudflare (DNS + túneles)
    sslManager.js                  Registro X.509 honesto (sin emisión falsa)
    domainManager.js               Dominios y resolución de rutas O(1)
    notificationService.js         Alertas Telegram, Discord, Slack y webhooks (SSRF-safe)
web/src/                           Panel web (React 19 + Tailwind v4, 100% modo claro, es-ES)
scripts/                           Instalador VPS Debian/Ubuntu + desinstalador + test systemd
tests/                             19 suites + estrés + live-server + paridad competitiva
bench/                             Benchmarks reproducibles (route-swap, live-sync, control-plane)
docs/superpowers/specs/            Especificación arquitectónica y decisiones de diseño
```

---

## Licencia

[Apache-2.0](LICENSE) — Copyright © 2026 Pablo (`macaqueboy`).
