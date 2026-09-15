# Culkibo

Orquestador cloud autohospedado, open-source, pensado para desarrollar con agentes de
IA. Alternativa a Coolify y Dokploy, con control nativo por MCP.

**Apache-2.0 · ~7.700 líneas de servidor · 10 suites de pruebas en verde**

---

## Antes de nada: qué funciona y qué no

Culkibo está en construcción y este README no va a fingir lo contrario. Si vas a
instalarlo, esto es lo que te vas a encontrar:

### Funciona de verdad

| | |
|---|---|
| **Ejecución local de proyectos** | Clona de GitHub, detecta monorepos (`/backend`, `/web`, `/src`…), instala dependencias, lanza el proceso y asigna puertos. Node, Vite, Next.js y sitios estáticos |
| **Ciclo de vida** | Arrancar, parar, hibernar y activar, matando de verdad el árbol de procesos y liberando el puerto en Windows y en Linux |
| **Servidor MCP** | 26 herramientas, registro de auditoría, transporte stdio y SSE |
| **Webhooks de GitHub** | Firma HMAC verificada, despliegue automático al hacer push |
| **Migrador de Coolify** | Extracción real desde la API v4: aplicaciones, bases de datos, volúmenes, variables |
| **API de Cloudflare** | Zonas, registros DNS y túneles reales. Sin token entra en modo simulado y lo dice (`isMock: true`) |
| **Docker** | Estado, contenedores, métricas y logs. Si no hay Docker, degrada a procesos |
| **Notificaciones** | Telegram, Discord, Slack y webhook genérico cuando un servicio cae o falla un build |
| **Panel web** | React 19 + Tailwind v4, telemetría por WebSocket, importador de Coolify, gestor de dominios |

### Todavía no funciona

| | Estado real |
|---|---|
| **Proxy inverso** | El router de ingress **no reenvía tráfico**. Devuelve una página describiendo a dónde enrutaría |
| **HTTPS / TLS** | No hay terminación TLS. El daemon solo habla HTTP |
| **Certificados wildcard** | El flujo DNS-01 escribe el registro TXT real en Cloudflare, pero **no ejecuta el protocolo ACME**: el certificado que guarda es un PEM de relleno |
| **Métricas de los pods** | La CPU, memoria y latencia de The Forge y The Citadel son valores simulados |
| **Reparto de tráfico** | `switchTraffic` cambia un objeto en memoria; no mueve tráfico |
| **Recarga en caliente** | Se detecta y clasifica el cambio, pero **no se transporta ni se aplica** |
| **Multi-servidor** | Solo la máquina local |
| **Backups programados** | Exporta a JSON bajo demanda. Sin cron y sin subida a S3/R2 |

Esa segunda tabla es el plan de trabajo, y está detallado en
[`docs/superpowers/specs/`](docs/superpowers/specs/).

> Una versión anterior de este README anunciaba «despliegues en caliente sub-35 ms» y
> certificados wildcard emitidos por ACME. Ninguna de las dos cosas era cierta: el
> número venía de un `setTimeout(8)` en el código. Se han eliminado ambos, del producto
> y de aquí.

---

## Hacia dónde va

El objetivo no es ser otro Coolify. Es cerrar el bucle que hoy rompe el desarrollo con
agentes de IA:

```
Hoy:      crear repo → push → vincular → build → esperar
          → cambio → commit → push → webhook → build → esperar → ver

Objetivo: guardar fichero → ver en tu URL pública
```

Dos entornos sobre la misma URL. **The Forge** es tu proceso corriendo en tu máquina,
visible en internet. **The Citadel** es la build inmutable en tu VPS, que responde
cuando cierras el portátil. Promocionas lo que has visto funcionar, no una rama de Git
que puede diferir, y revertir es instantáneo.

Todo el diseño, con presupuesto de latencia medido salto a salto y las contrapartidas
reconocidas, está en la especificación enlazada arriba.

---

## Seguridad

Culkibo orquesta procesos y contenedores. Eso lo convierte en un objetivo, así que hay
dos compromisos que se pueden verificar con un `grep` y no con una promesa:

**Nunca se construyen comandos de shell.** Los procesos se lanzan con `spawn()` y un
array de argumentos; nunca concatenando cadenas. Los secretos viajan por el entorno,
nunca en `argv` (donde los ve cualquiera con `ps`) ni dentro de una URL. Para clonar
repositorios privados, el token va por `GIT_ASKPASS` y no acaba en el `.git/config` del
repo clonado.

Esto no es cosmético: es la clase de fallo que ha producido **21 avisos críticos en
Coolify y 34 en Dokploy**, y dos de esos parches están catalogados como *«incomplete
fix»* de un aviso anterior. No se puede parchear caso a caso; hay que eliminarla por
construcción.

**El plano de control exige autenticación.** Dos capas:

- *Origen*: las peticiones de navegador con un `Origin` fuera de la lista reciben 403.
  Esto cubre el caso que la gente no espera — cualquier web que visites podría, si no,
  pedirle cosas a tu `localhost:3030` desde tu propio navegador.
- *Token*: para lo que no es navegador (CI, agentes MCP, `curl`), comparado en tiempo
  constante.

Desde loopback y sin navegador se sigue pasando sin token, para que probar en local sea
inmediato. Si expones el daemon, pon `CULKIBO_REQUIRE_TOKEN=1`.

**Y el argumento que no se compra:** son ~7.700 líneas de servidor. Puedes leerlas
enteras en una tarde antes de confiarle tu producción. Coolify tiene del orden de
300.000. Cada funcionalidad que añadamos compite contra el coste de dejar de ser
auditable.

Si encuentras un fallo de seguridad, abre un issue sin detalles de explotación y lo
coordinamos.

---

## Instalación

Requiere Node.js 20 o superior. Docker es opcional: sin él, Culkibo ejecuta los
proyectos como procesos.

```bash
npm install
npm run build        # compila el panel web
npm start            # arranca el daemon
```

Panel en `http://localhost:3030`.

En el primer arranque se genera un token de acceso en `data/auth.json` y la consola te
dice dónde está. Copia `.env.example` a `.env` si prefieres configurarlo tú.

En Windows, `./start.ps1` hace los tres pasos.

---

## CLI

```bash
node bin/culkibo.js start                      # arranca el daemon y el panel
node bin/culkibo.js status                     # estado operativo
node bin/culkibo.js doctor                     # diagnóstico del entorno

node bin/culkibo.js pod list                   # estado de The Forge y The Citadel
node bin/culkibo.js domain list                # dominios y certificados
node bin/culkibo.js docker                     # inspección de contenedores
node bin/culkibo.js ingress app.midominio.com  # a qué pod resolvería un Host

node bin/culkibo.js backup <projectId>         # exportar un proyecto
node bin/culkibo.js restore <archivo.json>     # restaurar desde un backup

node bin/culkibo.js mcp                        # servidor MCP por stdio
```

El ciclo de vida de los proyectos (arrancar, parar, hibernar) se hace hoy desde el panel
o por la API REST; todavía no tiene comandos propios en la CLI.

---

## Conectar un agente de IA

**Claude Desktop** — en `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "culkibo": {
      "command": "node",
      "args": ["/ruta/a/Culkibo/bin/culkibo.js", "mcp"],
      "env": { "CULKIBO_API_URL": "http://localhost:3030" }
    }
  }
}
```

**Cursor, Windsurf y compatibles** — añade el endpoint SSE:

```
http://localhost:3030/api/mcp/sse
```

> El servidor MCP declara la revisión `2024-11-05` sobre transporte HTTP+SSE, que está
> deprecado desde marzo de 2025. La migración a Streamable HTTP está en la
> especificación. Funciona hoy con los clientes actuales, pero no es la versión vigente
> del protocolo.

---

## Pruebas

```bash
npm test
```

Levanta su propio daemon si no encuentra uno, así que funciona en frío y en CI.

| Suite | Qué cubre |
|---|---|
| `cloudflare.test.js` | Tokens, zonas, DNS, TXT de ACME, túneles |
| `ssl.test.js` | Registro de certificados, TLS bajo demanda, caducidades |
| `domain.test.js` | Rutas exactas y comodín, incluida la frontera de etiqueta |
| `orchestrator.test.js` | Detección de cambios, reparto de tráfico, watchers |
| `mcp.test.js` | JSON-RPC 2.0, catálogo de herramientas, auditoría |
| `backup.test.js` | Exportación, restauración y volcados sin shell |
| `github.test.js` | HMAC de webhooks y despliegue automático |
| `coolifyMigrator.test.js` | Extracción y agrupación desde la API de Coolify |
| `localRunner.test.js` | Puertos, estáticos, traversal, manejo de secretos |
| `stop-lifecycle.test.js` | Parada real de procesos y liberación de puertos |

Más `live-server.test.js` (ingress y control de acceso), `websocket-stress.test.js`
(30 clientes concurrentes) y `stress.test.js` (100 peticiones simultáneas).

---

## Estructura

```
bin/culkibo.js              CLI
server/
  index.js                  daemon HTTP + WebSocket + ingress
  middleware/auth.js        control de acceso del plano de control
  routes/api.js             API REST
  services/
    localRunner.js          ejecución de proyectos, clonado, puertos
    projectManager.js       persistencia atómica y ciclo de vida
    containerOrchestrator.js  watchers y estado de los pods
    cloudflareService.js    API de Cloudflare (real + modo simulado)
    sslManager.js           registro de certificados  ⚠ ACME simulado
    domainManager.js        dominios y tabla de enrutado
    mcpServer.js            servidor MCP (26 herramientas)
    githubService.js        OAuth, repos y webhooks
    coolifyMigrator.js      importación desde Coolify v4
    notificationService.js  Telegram, Discord, Slack, webhook
    dockerManager.js        contenedores
    dbBackupManager.js      exportar y restaurar
web/src/                    panel (React 19 + Tailwind v4, modo claro)
tests/                      suites de verificación
docs/superpowers/specs/     diseño y decisiones
```

---

## Licencia

Apache-2.0.
