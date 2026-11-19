# Culkibo

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js >=20](https://img.shields.io/badge/Node.js-%E2%89%A520-339933.svg)](package.json)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28%20(44%20tools)-6366f1.svg)](#conectar-agentes-de-ia-mcp-2026-07-28)

**Orquestador cloud autohospedado, open-source y diseñado para la era de los agentes de IA.**  
Alternativa rápida, auditable y ligera a Coolify y Dokploy: Live Sync sub-50 ms (*The Forge*), despliegues inmutables sin cortes con Caddy (*The Citadel*), bases de datos gestionadas con copias a S3/R2, catálogo de 13 servicios en 1 clic, **cero construcción de comandos de shell** y **44 herramientas MCP (`2026-07-28`)**.

**Apache-2.0 · ~18.100 líneas de servidor + CLI · 7 dependencias de runtime · 17 suites + estrés + benchmarks reproducibles**

---

## Por qué Culkibo

El ciclo habitual de desarrollo con agentes de IA (Claude Code, Cursor, Codex, Antigravity) se rompe esperando pipelines:

```text
Tradicional: editar → commit → push → webhook → build Docker (1–4 min) → esperar → ver
Culkibo:     guardar fichero → Commit Frame atómico (/ws/sync) → vivo en ~35 ms
             promocionar → BuildKit con caché → healthcheck → conmutación Caddy en ~20 ms
```

Dos planos coordinados sobre el mismo dominio:

- **The Forge (iteración instantánea):** `culkibo sync` agrupa ráfagas de ediciones de IA en *Commit Frames* atómicos por WebSocket (`/ws/sync`), deduplica por SHA-256, verifica consistencia con árbol Merkle, distingue recarga en caliente (`path_b_hot`) de reinicio (`path_c_restart`) y mantiene un ring-buffer en memoria para revertir parches en **<15 ms**.
- **The Citadel (producción inmutable):** construye imágenes Docker con BuildKit (`# syntax=docker/dockerfile:1.7` + `--mount=type=cache` persistente para Next.js, Vite, Node, Python, Go y estáticos), verifica salud real, conmuta la ruta de forma atómica vía API de administración de Caddy (`grace_period` de 10 s), drena conexiones y conserva la versión anterior para rollback sin reconstruir.

---

## Benchmarks reproducibles (sin simulaciones)

Cada número de esta tabla procede de código real ejecutado contra **Caddy v2.11.9 real** y el daemon real de Culkibo — cero `setTimeout` simulados, cero constantes escritas a mano. Puedes reproducirlos en tu propia máquina con `npm run bench:all` y validarlos como aserciones con `npm run test:bench`.

| Dimensión | Culkibo (medido) | Coolify / Dokploy / Competidores | Cómo reproducirlo |
|---|---:|---|---|
| **Conmutación de ruta HTTP** (Caddy admin API) | **p50 19,9 ms · p95 31,9 ms · 0 HTTP 5xx** | Traefik file throttle 2.000 ms / HTTP poll 5.000 ms (**100×–250× más lento**) | `npm run bench` |
| **Live Sync E2E** (disco → `/ws/sync` → HTTP vivo) | **p50 ~35 ms** (15 ficheros IA → **1 Commit Frame**) | Coolify ~4 min · Vercel ~42 s · Dokploy ~30 s | `npm run bench:sync` |
| **Rollback de parche en memoria** | **p95 ~11 ms** (3–11 ms reales) | Rebuild completo o reinicio de contenedor | `npm run bench:sync` |
| **Memoria RAM en reposo** | **67–74 MB RSS** (cabe en VPS de 512 MB) | Coolify ≥ 2.048 MB (falla en VPS 1 GB) · Dokploy ~600–900 MB | `npm run bench:control` |
| **Concurrencia plano de control** | **1.200–2.250 req/s · p95 17–58 ms · 0 fallos** | PHP/Laravel + Postgres + Redis + Horizon | `npm run bench:control` |
| **WebSocket fan-out** | **40/40 clientes listos en ~62 ms** | Polling / Pusher / Soketi extra | `npm run bench:control` |
| **Dependencias de runtime** | **7** (`express`, `ws`, `axios`, `chokidar`, `commander`, `cors`, `dotenv`) | Cientos de paquetes PHP/Composer o monorepo Next.js | `package.json` |
| **Construcción de comandos de shell** | **0** (verificado en CI por escáner estático) | 21 avisos críticos RCE en Coolify · 34 en Dokploy | `node tests/shell-safety.test.js` |
| **Superficie MCP (`2026-07-28`)** | **44 herramientas anotadas (25 mutadoras)** | Coolify: 3 mutadoras · Dokploy: sin MCP nativo | `POST /api/mcp` (`tools/list`) |

---

## Comparativa honesta

| Capacidad | Culkibo | Coolify | Dokploy | CapRover / Dokku |
|---|:---:|:---:|:---:|:---:|
| Plano de datos Caddy atómico (TLS bajo demanda + `grace_period`) | ✅ | Traefik (poll 2–5 s) | Traefik | nginx |
| Wildcard TLS DNS-01 Cloudflare nativo en Caddy | ✅ | Manual | Manual | Manual |
| Live Sync sub-50 ms (Commit Frames + Merkle + Rollback <15 ms) | ✅ | ❌ | ❌ | ❌ |
| Builds Docker con BuildKit cache mounts (Next/Vite/Node/Python/Go) | ✅ | ✅ (caché frágil) | ✅ | Parcial |
| Bases de datos gestionadas (6 motores: PG, MySQL, MariaDB, Redis, Valkey, Mongo) | ✅ | ✅ | ✅ | Parcial |
| Backups programados (cron) + S3 / Cloudflare R2 / MinIO + retención GFS | ✅ | ✅ | ✅ | Manual |
| Catálogo 1-clic con redes aisladas y secretos AES-256-GCM (13 plantillas) | ✅ | ✅ | ✅ | ✅ |
| MCP `2026-07-28` Streamable HTTP nativo (44 herramientas, 25 mutadoras) | ✅ | Parcial (3) | ❌ | ❌ |
| Migrador real desde Coolify v4 (apps, DBs, volúmenes, envs, dominios) | ✅ | — | ❌ | ❌ |
| Cero `exec`/`sh -c` garantizado por test estático en CI | ✅ | ❌ | ❌ | Parcial |
| Consumo en VPS de 512 MB / 1 GB RAM | ✅ (~73 MB) | ❌ (≥ 2 GB) | Ajustado | ✅ |
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

node bin/culkibo.js catalog list                        # listar las 13 plantillas de 1 clic
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

Culkibo expone **44 herramientas anotadas** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), incluyendo 25 herramientas de escritura: desplegar a producción, hacer rollback, aprovisionar bases de datos, disparar copias S3/R2, instalar/desinstalar del catálogo, verificar árboles Merkle de Live Sync, revertir parches en <15 ms, promocionar Forge → Citadel y migrar desde Coolify.

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
npm test                      # 17 suites + live-server + websocket-stress + stress
npm run test:bench            # aserciones estrictas de benchmarks y paridad competitiva
npm run bench:all             # reporte completo de los 3 benchmarks reales
```

### Cobertura de las 17 suites (`tests/run-all.js`)

| Suite | Qué verifica |
|---|---|
| `shell-safety.test.js` | 0 construcción de comandos de shell en `server/`, `bin/`, `scripts/`, `bench/` |
| `live-sync.test.js` | Path traversal, Commit Frames atómicos, SHA-256 dedup, Merkle Tree, rollback <15 ms, auth WS `/ws/sync`, E2E real |
| `competitor-benchmarks.test.js` | Aserciones reales de RAM, arranque, concurrencia, Live Sync, Caddy cutover 0×5xx, MCP y catálogo |
| `caddy.test.js` | Caddy admin API real: config base, `@id`, actualización in-situ, canario 10/90, rollback ante error |
| `deploy.test.js` | BuildKit, detección de stacks, secretos fuera de argv, cutover con drenaje, rollback real Docker |
| `database.test.js` | 6 motores, AES-256-GCM, lista blanca, AWS SigV4 byte a byte, multipart S3/R2, cron, retención GFS |
| `catalog.test.js` | 13 plantillas en 8 categorías, imágenes fijadas, secretos, puertos `42000-42999`, proyección segura |
| `mcp.test.js` | 44 herramientas anotadas, JSON-RPC 2.0, Streamable HTTP `2026-07-28`, `server/discover`, SSE y errores |
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
    liveSyncEngine.js              Motor Live Sync: Commit Frames, Merkle Tree, rollback <15 ms
    liveSyncClient.js              Watcher nativo/Chokidar + cliente WS persistente para The Forge
    deployManager.js               Pipeline de producción Docker BuildKit + healthcheck + rollback
    caddyManager.js                Cliente Caddy admin API (PATCH rápido, grace_period, DNS-01)
    ingressManager.js              Reconciliador declarativo de rutas, canarios y sondas TLS
    databaseManager.js             6 motores gestionados, redes aisladas, cron y retención GFS
    s3Uploader.js                  Cliente S3/R2/MinIO con firma AWS SigV4 nativa (0 dependencias)
    catalogManager.js              Gestor de servicios 1-clic con secretos cifrados AES-256-GCM
    catalog/templates.js           13 plantillas auditadas en 8 categorías
    mcpServer.js                   Servidor MCP 2026-07-28 (44 herramientas anotadas)
    mcpStreamableHttp.js           Transporte Streamable HTTP 2026-07-28
    projectManager.js              Persistencia atómica con Group Commit y caché serializada
    localRunner.js                 Ejecución local sin shell y GIT_ASKPASS
    githubService.js               GitHub API, autodetección y webhooks HMAC
    coolifyMigrator.js             Importador real desde Coolify v4
    cloudflareService.js           API de Cloudflare (DNS + túneles)
    sslManager.js                  Registro X.509 honesto (sin emisión falsa)
    domainManager.js               Dominios y resolución de rutas
    notificationService.js         Alertas Telegram, Discord, Slack y webhooks
web/src/                           Panel web (React 19 + Tailwind v4, 100% modo claro, es-ES)
scripts/                           Instalador VPS Debian/Ubuntu + desinstalador + test systemd
tests/                             17 suites + estrés + live-server + paridad competitiva
bench/                             Benchmarks reproducibles (route-swap, live-sync, control-plane)
docs/superpowers/specs/            Especificación arquitectónica y decisiones de diseño
```

---

## Licencia

[Apache-2.0](LICENSE) — Copyright © 2026 Pablo (`macaqueboy`).
