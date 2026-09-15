# Culkibo — Forge & Citadel: diseño del pipeline de edición en tiempo real

**Fecha:** 2026-09-12
**Estado:** BORRADOR — pendiente de validación técnica (4 investigaciones en curso)
**Autor:** Pablo + Claude Opus 5

---

## 1. La apuesta

> Un desarrollador —o su agente de IA— guarda un fichero en su máquina, y el cambio
> aparece en la URL pública de su aplicación en menos de 200 ms. Sin commit, sin build,
> sin redespliegue. Y cuando el cambio le convence, lo promociona a producción con un
> clic o con una llamada MCP.

Esto no es "desplegar más rápido". Es **eliminar el despliegue** del bucle de desarrollo
y dejarlo solo donde aporta: al publicar.

### El bucle que sustituimos

```
Hoy (Coolify, Dokploy, Vercel, Railway):
  crear repo → push → vincular → build → esperar
    → cambio → commit → push → webhook → build → esperar → ver
  ≈ 7 pasos, 30 s – 4 min por iteración

Culkibo:
  guardar fichero → ver
  ≈ 0 pasos, ~50-200 ms
```

Para alguien que itera 50 veces al día con un agente de IA, la diferencia no es de
velocidad: es que uno permite mantener el estado de concentración y el otro no.

---

## 2. Estado real del repositorio (honestidad previa)

Antes de diseñar nada, el inventario de lo que hoy es real y lo que es simulación.
**Esto no es una crítica del trabajo hecho: el plano de control y el dashboard están
bien construidos. Lo que falta es el plano de datos.**

### Simulado

| Componente | Realidad |
|---|---|
| `containerOrchestrator.triggerHotSync()` | `await new Promise(r => setTimeout(r, 8))`. El «<35 ms» del `package.json` es ese temporizador |
| `server/index.js` — «Edge Ingress» | No hace proxy. Devuelve una página HTML describiendo a dónde *enrutaría*. `X-Culkibo-Latency: 24ms` es una cadena literal |
| Reparto canario | `Math.random()` por petición dentro de Express |
| `sslManager.issueWildcardCertificate()` | `setTimeout` encadenados que escriben `mockCertPem`. El emisor declarado, «Let's Encrypt Authority R3», es una cadena retirada hace años |
| Métricas de pods (Forge / Citadel) | `Math.random()` cada 3 segundos |
| `switchTraffic()` | Muta un objeto en memoria |
| Terminación TLS | No existe. Cero `https.createServer` en el repositorio |

### Real y funcionando

`dockerManager` (invoca el CLI de Docker), `cloudflareService` (llama a
`api.cloudflare.com/client/v4`, con modo mock explícito marcado `isMock: true`),
`githubService` (webhooks con HMAC verificado), `localRunner` (lanza procesos, clona
repositorios, detecta monorepos, libera puertos), `mcpServer` (26 herramientas, aunque
sobre un protocolo obsoleto — ver §8).

### Regla derivada

**Borrar la simulación, no iterar sobre ella.** Mientras el estado de un certificado sea
un campo en nuestro JSON, podremos volver a falsearlo. La cura es que deje de ser
nuestro: que lo posea Caddy y que un health check haga un handshake TLS real y muestre
el emisor y la caducidad verdaderos.

---

## 3. Por qué existe el hueco

Investigación de 2026-09-12 sobre Coolify, Dokploy, CapRover, Dokku, Kamal, Appwrite,
Vercel, Railway, Render, Fly.io, Cloudflare, Netlify, Porter, Northflank y Zeabur, más
16 proveedores de sandboxes para agentes.

### 3.1 Nadie sincroniza desde la máquina local

Ni uno de los 16 proveedores de sandboxes ofrece sincronización continua
máquina-local → sandbox.

- **Daytona**: issue abierto sin implementar desde 2026-01-08, cero comentarios
- **E2B**, **Cloudflare Sandbox SDK**: su `watch` observa el filesystem *del sandbox*
- **Modal**: los volúmenes son solo de lectura hacia dentro (`.reload_volumes()`)
- **Freestyle**: su propio blog recomienda `rsync -az` por SSH
- **Docker Sandboxes**: latencia cero solo porque es **local** (bind mount virtiofs)

### 3.2 Nadie hace HMR en producción

Todas las promesas de «instantáneo» del sector se resuelven como *redespliegue rápido*
o *enrutado por versión*:

- Temporal → Patching API
- Restate → «en la mayoría de casos, usa pause y resume»
- `vercel/workflow` → las ejecuciones nuevas usan la versión nueva
- Cloudflare Workers → «unos segundos», propagación de KV hasta 60 s

**No existe implementación verificada en producción del intercambio sub-segundo de
código en un proceso que ya está sirviendo.** Ese es a la vez nuestro foso y nuestro
riesgo.

La prueba más elocuente: **devpush** (4.745★), el clon self-hosted de Vercel más votado
de 2025-26, sigue haciendo `git push → webhook → build → contenedor → rollout`.

### 3.3 El tier self-hosted no tiene wildcard TLS

| Plataforma | DNS-01 / wildcard |
|---|---|
| Coolify | **Cero ocurrencias de `dnschallenge` en todo el repositorio.** Solo HTTP-01 |
| Dokploy | Solo `httpChallenge`. Cuatro de sus issues más votados lo piden (70👍, 33👍, 22👍) |
| CapRover | Nginx + LE, HTTP-01 |
| Kamal | `x/crypto/autocert` — HTTP-01 / TLS-ALPN, sin wildcard |
| Dokku | **Único que lo tiene** — vía plugin lego, solo CLI, por app, sin interfaz |

### 3.4 Su seguridad es estructuralmente mala

| | Avisos publicados | Críticos | Altos |
|---|---|---|---|
| Coolify | 70 | **21** | 26 |
| Dokploy | 60 | **34** | 17 |

**Casi todos son el mismo defecto**: cadenas controladas por el usuario interpoladas en
comandos de shell ejecutados como root por SSH. La lista de críticos de Coolify es una
sola herida repetida — inyección por ruta de volumen, nombre de fichero de configuración
del proxy, script de init de PostgreSQL, backup, import, parámetros de compose, URL de
Git, **nombre del proyecto**, cadena de versión, generación de comandos SSH.

Dos de los parches están catalogados como *«incomplete fix»* de un aviso anterior: prueba
de que la clase no se puede parchear, solo eliminar por construcción.

Además, `GHSA-725v-f5gh-22q9` (crítico): IDOR entre inquilinos — desplegar en servidores
de otro cliente y leer sus claves SSH.

### 3.5 La ventana está abierta ahora

- **Coolify v5**: issue #5685, el más votado del repositorio por 5× (687👍), abierto desde
  abril de 2025. La rama `v5.x` lleva muerta desde 2026-03-27, **3.131 commits por
  detrás** de main. Su fundador, por escrito: *«mi prioridad fue programar a lo loco»*,
  *«las actualizaciones rompen funcionalidad existente, y eso es inaceptable»*
- **Coolify quema ~400 % de CPU en reposo** (issues abiertos desde 2024); falla en VPS
  de 1 GB
- **Nixpacks**, del que depende Coolify, sin release desde 2025-10-24
- **Heroku** entró en modo mantenimiento el 2026-02-06. No habrá más funcionalidades
- **Dokploy** dejó de ser open source en enero de 2026 (licencia DSAL, source-available)

**Apache-2.0 y un v1.0.0 que arranca son, hoy, activos competitivos.**

### 3.6 Pero hay competencia entrando

| Proyecto | Qué es |
|---|---|
| **Cloudflare Dynamic Workers** | Beta abierta 2026-03-24. Un Worker instancia otro con código dado en runtime, en ms. **La amenaza más directa al titular** |
| **Cloudflare Sandbox SDK** | Watch de ficheros + URLs de preview automáticas. 1.0 preview |
| machine0.io (YC S26) | VMs manejadas enteramente por CLI o MCP |
| Ink (ml.ink) | «Despliega apps full-stack desde agentes de IA vía MCP» |
| Terminal Use (YC W26) | «Vercel para agentes que trabajan sobre ficheros» |
| OpenSandbox | 15.146★, Apache-2.0, CNCF |

Ninguno es self-hosted en el VPS del usuario, y ninguno sincroniza desde la máquina
local. Ese es el terreno defendible.

---

## 4. Decisiones de diseño

Cinco decisiones cerradas en la fase de brainstorming.

### D1 — Modelo híbrido: Forge local, Citadel en el VPS, misma URL

El proceso de desarrollo corre **donde se edita**. El VPS sostiene la URL y arbitra.

Razón: el suelo de latencia es la red. Si el fichero se guarda y el proceso corre en la
misma máquina, ese tramo cuesta 0 ms. Ninguna tecnología —microVM, WASM, snapshot— bate
la velocidad de la luz en fibra.

**Corolario contraintuitivo**: Firecracker y las microVMs **no** aceleran este bucle.
Optimizan el arranque en frío, y el bucle de edición nunca toca el arranque en frío.
Son roadmap (despertar proyectos dormidos, aislamiento multi-inquilino), no v1.

### D2 — El origen fijo es el VPS del usuario

Self-hosted, como Coolify. El usuario administra sus redes. Culkibo se adapta a lo que
encuentre.

Monetización futura: **vender el cerebro, nunca los músculos.** El cliente pone su
infraestructura, nosotros cobramos el plano de control que la orquesta. Cero coste de
cómputo, cero abuso, márgenes de software, y totalmente compatible con Apache-2.0.

No bloquea nada hoy.

### D3 — Promoción de lo ya probado, no de una rama de Git

Culkibo congela el estado exacto que el usuario está viendo en Forge y lo construye en el
VPS. **Se promociona lo que se ha visto funcionar**, no un commit que puede diferir.

Botón en la interfaz + herramienta MCP. Si la build falla, Citadel sigue sirviendo la
anterior. Rollback en un clic.

Git sigue disponible para lo que sirve —guardar historia— pero deja de ser el peaje para
ver un cambio.

### D4 — Ramas de datos copy-on-write, adaptativas

Forge lee datos reales de producción; sus escrituras y migraciones caen en una rama y no
pueden tocar producción. Al promocionar, la migración ya validada se aplica.

No hay una técnica única que funcione en todo VPS, así que se detecta el substrato:

| Substrato detectado | Mecanismo | Coste |
|---|---|---|
| btrfs / ZFS | snapshot de subvolumen | milisegundos |
| BD externa (Neon, PlanetScale, Supabase) | su propia API de branching | milisegundos |
| ext4 + BD pequeña | `CREATE DATABASE ... TEMPLATE` | segundos |
| ext4 + BD grande | degrada a lectura real / escritura descartable | instantáneo |

Nunca falla, y **nunca miente sobre lo que está haciendo**.

> Detalle exacto pendiente de la investigación en curso (§12).

### D5 — Enfoque B con C como red automática

**B — hot-swap verificado** (camino rápido) y **C — proceso nuevo con swap de ruta**
(camino seguro). No son alternativas: Culkibo elige según lo que detecta.

| Detecta | Camino | Latencia |
|---|---|---|
| Node + Vite, cambio en módulo hoja con frontera de aceptación | **B** | ~80-200 ms |
| Node + Vite, cambio en la raíz del grafo, `package.json` o config | **C** | ~1-3 s |
| Python, PHP, Go, Rails, cualquier otro stack | **C** siempre | ~1-3 s |

Esto resuelve la tensión entre «mínima latencia» y «máxima seguridad»: cuando el cambio
es seguro de intercambiar en caliente vamos a 100 ms; cuando no lo es, **lo decimos** y
tardamos un segundo.

**Nunca se reporta un reinicio como hot sync.**

---

## 5. Arquitectura

### 5.1 Pipeline de edición

```
  [Máquina del desarrollador]                    [VPS del usuario]

  Claude Code guarda N ficheros
        │
        ▼
  @parcel/watcher  (ReadDirectoryChangesW nativo)
        │
        ▼
  Commit frame: acumula hasta quiescencia
  hash de contenido + nº de secuencia
        │
        ▼
  WebSocket persistente ────────────────────►  Plano de control (Node)
  (ya abierto, TLS ya negociado)                      │
                                                      ▼
                                              Escribe en el directorio
                                              bind-mounted del proyecto
                                                      │
                                                      ▼
                                              Clasifica el cambio
                                               ┌──────┴──────┐
                                          hoja │             │ raíz del grafo
                                               ▼             ▼
                                      Proceso sombra    Proceso nuevo
                                      aplica + smoke    + health check
                                               │             │
                                               ▼             ▼
                                          Swap atómico ── Caddy admin API
                                                      │
                                                      ▼
                                              HMR push al navegador
```

### 5.2 Componentes y su razón

| Componente | Elección | Por qué |
|---|---|---|
| Watcher | **@parcel/watcher** | C++ nativo por plataforma, usa Watchman si está. Sustituye a chokidar 4 |
| Debounce | 5 ms + dedup por hash | El actual (`awaitWriteFinish` 40 ms + debounce 30 ms) impone **70-80 ms de suelo antes de empezar**. La propia documentación de Chokidar dice que esa opción lo hace «mucho menos reactivo» |
| Transporte | WebSocket persistente | Conexión ya abierta y TLS ya negociado: el coste por edición es un frame, no un handshake |
| Aplicación | **bind mount**, nunca `docker cp` | Mismo kernel, mismo filesystem: visibilidad inmediata. `docker cp` cuesta un spawn de proceso (decenas de ms). Es por esto que Tilt/Skaffold/Garden son lentos: no pueden hacer bind mount entre nodos. Nosotros tenemos un solo VPS — es nuestra ventaja |
| Recarga | Vite 8 `createServerModuleRunner` | **Node no puede invalidar un módulo ESM cargado.** `module.register()` deprecado en v25.9.0 y en runtime en v26.0.0; `registerHooks()` no reemplaza módulos ya cargados. Vite mantiene su propio grafo fuera del registro ESM de Node |
| Ingress | **Caddy**, vía admin API | No por rendimiento (los cuatro proxies miden ~0,4 ms) sino por la **vía de actualización**: la admin API es síncrona, sin downtime y con rollback automático. El file provider de Traefik tiene throttle de 2 s; el HTTP provider, poll de 5 s |
| TLS | **Caddy on-demand TLS** + `lego` para wildcard | `acme-client` de npm lleva sin commits desde 2024-07-17, sin ARI y sin perfiles. `lego` (9.867★) está activo |
| Dashboard | `ws` + eventos JSON | **Sin CRDT.** El dashboard es de un solo escritor: el servidor manda, el navegador observa. Un CRDT resuelve fusión concurrente multi-escritor, un problema que no tenemos |

### 5.3 Mecanismos que forman el núcleo

Lo novedoso no es ninguna pieza suelta, sino la combinación de cuatro:

1. **Transacción de sincronización (commit frame).** Los cambios se acumulan hasta
   detectar que el editor dejó de escribir, y se aplican como **una unidad**. Crítico:
   un agente de IA no edita un fichero, edita quince. Sin esto, la URL pública sirve
   estados rotos intermedios mientras el agente trabaja.

2. **Clasificación previa.** Se analiza el grafo de módulos *antes* de tocar nada para
   decidir entre camino B y camino C, y se muestra cuál se tomó.

3. **Verificación en sombra.** El parche se aplica primero a un proceso gemelo sin
   tráfico público. Un smoke test. Si sobrevive, swap. Si no, el error aparece en el
   dashboard y **la URL pública no se entera**.

4. **Historial de parches.** Como el grafo de módulos vive en memoria, guardar los
   últimos N módulos reemplazados hace que revertir sea reponer el anterior:
   **rollback en menos de 10 ms**, sin reconstruir nada.

### 5.4 Integridad de la sincronización

Tres modos de fallo silencioso documentados, todos en la ruta Windows → Docker:

- El buffer de libuv para `ReadDirectoryChangesW` es de **4.096 bytes** (~40 rutas
  cortas). Microsoft documenta que al desbordarse *«se descarta el contenido entero del
  buffer»* y la llamada **devuelve éxito igualmente**
- `fs.watch` se ata a un **inodo**: los editores que guardan creando y renombrando dejan
  el watch huérfano
- La documentación de Node advierte que observar ficheros es *«poco fiable, y en algunos
  casos imposible… usando software de virtualización como Vagrant o Docker»*

Un evento perdido significa que la URL pública sirve código viejo **sin ningún error**.
Es el peor fallo posible para un producto que promete «lo que ves es lo que está
desplegado».

Defensa en tres capas:

1. **Número de secuencia monótono** por parche, con acuse de recibo del otro extremo.
   Un hueco en la numeración fuerza reconciliación
2. **Comparación Merkle periódica** del árbol observado, cada pocos segundos y fuera del
   camino caliente. La divergencia se cura sola en vez de acumularse
3. **Estado visible**: indicador «en sync / N ficheros divergen» en el dashboard **y**
   expuesto como herramienta MCP, para que un agente lo detecte y lo repare solo

Regla: *«no llegó ningún evento» y «no hubo ningún cambio» nunca pueden ser
indistinguibles.*

---

## 6. Presupuesto de latencia

Medido salto a salto. ◆ = dato con fuente. ○ = estimación razonada del mecanismo.

| Salto | Típico | p99 | Base |
|---|---|---|---|
| Evento de fichero en Windows | 5-20 ms | 40 ms | ○ (el settle de 20 ms de Watchman ◆ es el único comparable publicado) |
| Hash + diff | 1-3 ms | 8 ms | ○ |
| WAN una dirección, casa → VPS en la UE | 10-25 ms | 60 ms | ○ dependiente del entorno |
| Escritura en el bind mount | <1-3 ms | 10 ms | ○ mismo kernel |
| Invalidar y reevaluar un módulo | 15-60 ms | 150 ms | ◆ acotado por arriba: Vite 8.2.2 mide 93-130 ms de HMR para apps de 1.000-10.000 componentes |
| Push HMR al navegador | 10-25 ms | 60 ms | ○ (+~0,4 ms de proxy ◆) |
| El navegador aplica | 5-20 ms | 50 ms | ○ |
| **Total** | **~50-155 ms** | **~380 ms** | |

**El claim honesto es «por debajo de 150 ms típico» con el método publicado, no una cifra
única.** Los dos términos dominantes son los dos saltos de red, que dependen de la
conexión de cada usuario.

### Contexto competitivo

| | Latencia |
|---|---|
| **Culkibo (camino B)** | **~50-155 ms** |
| Blaxel, reanudar desde standby | ~25 ms |
| Daytona, crear sandbox nuevo | ~90 ms |
| Freestyle, arrancar VM | 65 ms |
| E2B, reanudar | ~1 s |
| Cloudflare Containers, arranque en frío | 1-3 s |
| Zeabur, plantilla | ~30 s |
| Vercel, app Next.js | 42 s |
| **Coolify, misma app** | **4 min** |

Nota: las cifras de sandboxes miden *crear o reanudar un entorno*. Culkibo no crea ni
reanuda nada — el proceso ya está vivo. No son directamente comparables, y **hay que
decirlo al publicarlas**.

---

## 7. Modelo de seguridad

### 7.1 Principio: eliminar clases, no parchear casos

Los 55 críticos de Coolify y Dokploy son una sola clase. Se elimina por construcción:

1. **Cero construcción de comandos de shell.** API de Docker sobre el socket y
   `spawn(cmd, [args])` en todas partes. Nunca `shell: true`, nunca interpolación
2. **Secretos fuera de argv.** Un token o contraseña jamás aparece en la línea de
   comandos (visible en `ps`), en una URL de clonado, ni en un mensaje de error
3. **Sin SSH en el camino caliente.** Es la lección que Coolify lleva 17 meses intentando
   aplicar con su agente Rust

### 7.2 Separación de planos

El túnel expone la máquina del desarrollador a Internet. Coolify nunca toca el portátil;
nosotros sí. Es superficie de ataque nueva y hay que tratarla como tal.

| | Plano público | Plano de control |
|---|---|---|
| Qué sirve | La aplicación, y solo la aplicación | HMR, sincronización, telemetría |
| Origen | El hostname público del proyecto | Origen autenticado aparte |
| Auth | Ninguna (es una web pública) | Token por proyecto |
| Deducible desde la URL pública | — | **Nunca** |

El contenedor **jamás** acepta un módulo empujado por red. Escribe siempre el plano de
control, que es quien valida.

### 7.3 Deuda de seguridad actual

Corregido en la auditoría del 2026-09-12 (10/10 tests en verde, build limpia):

- Barrera global de excepciones no capturadas; el daemon ya no cae por un error suelto
- Handler `error` en cada watcher de Chokidar (un `EPERM` mataba el proceso)
- Path traversal en el servidor estático — servía `data/github.json` con el PAT
- XSS reflejado por cabecera Host en el ingress
- `*.culkibo.dev` coincidía con `evilculkibo.dev` (falta el punto de frontera)
- Colisión de IDs de proyecto en importaciones masivas
- Árboles de procesos inmortales en Linux (`detached: false` + kill de grupo negativo)
- Claves privadas versionadas en Git (destrackeadas; **el historial sigue conteniéndolas
  y hay que purgarlo antes de publicar**)

Pendiente y explícito:

- **El daemon expone `cors({origin:'*'})` sin autenticación.** Cualquier web que el
  usuario visite puede pilotarlo. Es un cambio de comportamiento que rompe clientes, y
  por eso no se aplicó unilateralmente
- Los patrones `exec(\`git clone ${url}\`)` y `PGPASSWORD="${pwd}" pg_dump` siguen ahí

**Nada de esto se presume en público hasta estar arreglado.** Decir «somos más seguros
que Coolify» con un crítico propio abierto es peor que no decir nada.

### 7.4 La credencial que ellos no pueden copiar

Coolify tiene ~300.000 líneas: nadie puede auditarlas. Culkibo tiene **6.500**. Un
desarrollador desconfiado puede leerlas enteras una tarde antes de meter su producción
dentro.

Esa asimetría no caduca y no se compra. Sostenerla es una restricción de diseño: **cada
funcionalidad nueva compite contra el coste de dejar de ser auditable en una tarde.**

---

## 8. Superficie para agentes (MCP)

Nuestro servidor MCP declara `protocolVersion: '2024-11-05'` y solo sirve HTTP+SSE, un
transporte **deprecado desde la revisión 2025-03-26**. La revisión actual es
**2026-07-28**.

Para un producto cuyo eslogan es «controlado por agentes de IA», estar dos años por
detrás en el protocolo es el arreglo más barato y de mayor impacto del plan.

### El hueco real no es tener más herramientas

| Plataforma | Su MCP |
|---|---|
| Coolify | 45 herramientas, pero **solo 3 modifican algo**. Es un visor |
| Porter | Solo OAuth: **inusable headless en CI** — justo el caso del agente |
| Fly.io | Experimental |
| Northflank | No tiene |
| Cloudflare | Fragmentado en 18 servidores; el agente debe adivinar cuál |
| Vercel | Decide qué clientes de IA pueden conectarse |

Posiciones sin ocupar, y son las nuestras:

1. **Paridad de escritura**: todo lo que puede hacer la interfaz, lo puede hacer un
   agente, con el mismo modelo de autorización
2. **Auth headless** que funcione en CI sin humano delante
3. **Errores accionables por máquina**, no volcados de log
4. **`culkibo_verify_sync`**: estado de sincronización comprobable por el agente
5. **El migrador de Coolify expuesto como herramienta MCP** — «apunta tu agente a tu
   Coolify y que te mude» es un canal de adquisición, no una funcionalidad

> Diseño concreto de la superficie de herramientas pendiente de la investigación en
> curso (§12).

---

## 9. Sistema de diseño

Valores extraídos del CSS de producción que Linear, Vercel, Stripe, Resend y Raycast
sirven hoy — no de artículos.

### 9.1 Corrección: `slate` es el color equivocado

Croma medido en OKLCH en el escalón de borde:

| | hex | Croma |
|---|---|---|
| Vercel gray-300 | `#e6e6e6` | **0.0000** |
| Linear borde primario | `#e9e8ea` | 0.0029 |
| Tailwind **zinc**-200 | `#e4e4e7` | 0.0040 |
| Stripe gray100 | `#ebeef1` | 0.0052 |
| **Tailwind slate-200** | `#e2e8f0` | **0.0126** |

`slate` es 2-4× más cromático que cualquier cosa que sirvan Linear, Vercel o Stripe, y 4×
más que `zinc`. El rediseño de Linear de 2026 se movió explícitamente *«de tonos azulados
fríos hacia grises más cálidos»*.

A ese nivel de croma, **el tinte azul es la señal de barato**.

**Arreglo sin tocar clases**: redefinir los tokens en `@theme` de Tailwind v4. Todo el
`border-slate-200` del código pasa a valer lo correcto.

### 9.2 Las ocho reglas del modo claro

1. Texto primario `#171717`–`#414552`, **nunca `#000`**
2. **Bordes a 1,2-1,5:1 de contraste, no 3:1.** Poner cada borde a 2-3:1 es el sello de
   Bootstrap. WCAG 1.4.11 exige 3:1 solo cuando el borde es la única señal (un input
   vacío, una muestra sin etiqueta)
3. Sombras: alpha **2-8 %**, mínimo 2 capas, teñidas hacia el tono de la superficie,
   siempre acompañadas de un anillo translúcido de 1px. Stripe usa
   `rgb(64 68 82 / 8%)`, no negro. **Las sombras por defecto de Tailwind son 2-5× más
   pesadas de lo debido**
4. Croma de los grises **≤ 0.005** en el escalón de borde
5. Seleccionado = pseudo-elemento interior en forma de pastilla + salto de contraste.
   **No azul, no borde**
6. Foco = 2px, vía `box-shadow` (no `outline`), `:focus-visible`, neutro al 40 % de negro
7. Estado = punto sólido + tinte al ~15 % + texto del escalón 11. **El amarillo saturado
   no alcanza 4,5:1 sobre blanco en ninguna variante** — su texto tiene que ser marrón
8. `--border-hairline: .5px` por encima de 192 dpi

### 9.3 Librerías

**Base UI 1.8.0 para todo** — Dialog, Drawer, Toast, Menu, ScrollArea, Autocomplete.
Verificado que **Linear lo usa en producción** (su HTML contiene `id="base-ui-_R_..."` y
su CSS usa la API `[data-starting-style]` / `--anchor-width`). Trae Drawer y Toast
estables: **una dependencia en vez de tres** (fuera `sonner` y `vaul`).

⌘K sobre Base UI Autocomplete + Dialog, **portando los dos algoritmos de cmdk** en vez de
la librería: las constantes de scoring de `command-score.ts` y la pila de páginas
anidadas (cuatro líneas de estado). `cmdk` está congelado desde marzo de 2025 aunque
mantiene 30 M descargas semanales.

Patrón arquitectónico a robar de Linear: **un único registro de acciones alimenta a la
vez los atajos de teclado, el ⌘K y el clic derecho** — y el menú contextual existe en
parte para *enseñar* los atajos.

### 9.4 Divulgación progresiva

Nielsen Norman, literal: *«Evita los modales, porque ocultan los datos de referencia que
el usuario necesita mientras edita»* y *«los acordeones son problemáticos porque los
usuarios no los cierran»*. Stripe publica el mismo criterio: por defecto, panel lateral
sobre vista enfocada.

| Cuánto contenido | Patrón |
|---|---|
| ≤ 6 campos suplementarios | Expansión en línea |
| Detalle de contenedor / certificado | **Panel lateral no modal** |
| Necesita sub-navegación | Página completa con URL propia |
| — | **Nunca un modal sobre la tabla** |

Densidad (escala de Carbon): filas de **32 px con texto de 14 px** es el ajuste de
herramienta profesional — ~28 filas en 900 px frente a ~18 con filas de 48 px. La
jerarquía sale del **peso**, no del tamaño: cabecera 14px/600, fila 14px/400.

Acciones destructivas, por niveles:

| Riesgo | Fricción |
|---|---|
| Parar / reiniciar | Toggle optimista + deshacer. **Sin diálogo** |
| Borrar contenedor sin estado | Diálogo, texto específico de la consecuencia, botones `Eliminar contenedor` / `Conservar contenedor`, sin opción por defecto enfocada |
| Borrar con volúmenes, revocar un certificado vivo, quitar un dominio | **Escribir el nombre del recurso** + lista explícita de consecuencias («3 rutas devolverán 502») |

### 9.5 Español

**El Title Case es una falta de ortografía**, no una decisión de estilo. RAE, *DPD*
«mayúsculas» §5.2.24: *«No es correcto escribir todos los elementos significativos con
mayúscula.»* Hay que auditar `capitalize` fuera de las clases. `uppercase` en etiquetas
de 11-12 px destroza tildes y signos de apertura.

**La expansión del español respecto al inglés no es el +20 % del folclore.** Medido sobre
36 etiquetas reales de Culkibo: **media +40 %**, etiquetas de ≤10 caracteres **+47 %**.

| Inglés | Español | Ratio |
|---|---|---|
| `Uptime` | `Tiempo de actividad` | **317 %** |
| `Env vars` | `Variables de entorno` | **250 %** |
| `Overview` | `Información general` | **238 %** |
| `Logs` | `Registros` | **225 %** |

Consecuencias: presupuestar el chrome al **doble** del ancho inglés. Columna de estado
≥96 px. Nada de pastillas de ancho fijo. `table-layout: auto`. **Truncar valores, nunca
el chrome.**

Otras reglas:

- **Botones en infinitivo, prosa en imperativo**: `Desplegar`, `Guardar`,
  `Añadir dominio` — nunca `Despliega`. El imperativo solo en estados vacíos
- **Tú**, nunca *usted*. Evitar por completo la segunda persona del plural
- **`desplegar` / `el despliegue`** (la comunidad dev dice esto; *implementar* es de
  cloud empresarial). **«Logs» en navegación, «los registros» en prosa.** Nunca
  «bitácoras»
- **Fijar `es-ES`, no español neutro.** es-419 formatea los números igual que el inglés
  (`1.5 GB` frente a `1,5 GB`). La RAE prescribe reloj de 24 h para contextos técnicos.
  Todo a través de `Intl.*`, nunca formateo a mano
- `la API` nunca ⊗`el API`; siglas sin `-s`: «los certificados SSL», «las API»;
  `42,1 %` **con espacio**; `&nbsp;` entre número y unidad; `¿` y `¡` obligatorios

### 9.6 Visor de logs

`@tanstack/virtual-core` tiene primitivas hechas para esto: `anchorTo: 'end'`,
`followOnAppend`, `scrollEndThreshold`, `isAtEnd()`. **Solo sigue si ya estabas al
final** — la regla de «no dar tirones a quien ha subido» está dentro de la librería.

**Contrapresión.** Un `setState` por línea a 5.000 líneas/s son 5.000 renders contra un
presupuesto de 16,7 ms, y **el auto-batching de React 19 no ayuda** porque cada
`onmessage` del WebSocket es un macrotask distinto. Solución: acumular en un `ref` y
volcar una vez por frame de animación — ≤60 actualizaciones/s llegue lo que llegue.
Tope de 10-20k líneas con salida de escape «descargar log completo». Clave por **número
de secuencia monótono asignado en ingesta, nunca por índice**.

Búsqueda: input no controlado + `useDeferredValue`, no debounce. Escapar la entrada por
defecto para que pegar un stack trace con `(` `[` `*` funcione.

**ANSI en modo claro.** Las propias librerías avisan: *«el estándar asume fondo negro»*.
Sobre blanco solo **5 de los 16 colores** superan el mínimo de accesibilidad; el amarillo
da 1,35:1. Hay que traducir la paleta con «brillante» significando *más oscuro*, y el
amarillo convertido en marrón. **No existe amarillo legible sobre blanco.**

---

## 10. Métricas publicables

Regla: **cada cifra con su método reproducible al lado, y los casos malos incluidos.**

El punto ciego del sector es exactamente este: **nadie en el tier self-hosted publica
latencias.** Ni p50 ni p95, ni Coolify ni Dokploy ni CapRover. Ser los primeros, con la
metodología abierta, convierte el número en foso en vez de eslogan.

| Afirmación | Cifra | Respaldo |
|---|---|---|
| Edición → visible en la URL pública | p50 y p95 medidos, reparto B/C incluido | Arnés de benchmark reproducible en el repo |
| Rollback de un despliegue | < 10 ms | Historial de módulos en memoria |
| Wildcard TLS por DNS-01 | Sí, por defecto, desde la interfaz | Coolify: **cero ocurrencias de `dnschallenge`** en su repositorio |
| Sin inyección de shell | Cero comandos construidos por concatenación | Verificable con `grep`; Coolify 21 críticos, Dokploy 34 |
| Auditable | ~6.500 líneas | Coolify ~300.000 |
| Superficie MCP | Paridad de escritura + auth headless | Coolify: 45 herramientas, **3 mutan**. Porter: inusable en CI |

Prohibido publicar: cualquier número que no venga de un arnés que un tercero pueda
ejecutar. El «<35 ms» actual es un `setTimeout(8)` y **sale del `package.json` en la
fase 0**.

---

## 11. Riesgos

### R1 — El hot-swap de servidor degrada a reinicio sin avisar

Vite es explícito: sin `import.meta.hot.accept()` en la entrada del servidor, un cambio
invalida **el grafo entero**. Y la Environment API sigue en **release candidate**, con
cambios rompedores anunciados para una major futura. Nadie la corre en producción.

**Mitigaciones**: clasificar antes de actuar y mostrar qué camino se tomó; fijar la minor
exacta de Vite con un test de integración que falle si cambia el contrato; publicar el
reparto real p50/p99 entre ambos caminos; evaluar Bun `--hot` como segundo runtime.

### R2 — Divergencia silenciosa entre local y remoto

Ver §5.4. Es el peor fallo posible para este producto porque **no produce ningún error**.

### R3 — Un dev server sirviendo una URL pública va a ser atacado

El canal HMR acepta mensajes de actualización de módulo y el runner evalúa código. Ver
§7.2.

Añadido: **Cloudflare cierra los WebSockets inactivos con un timeout no documentado.** Sin
heartbeat del cliente, la tubería muere en silencio y las ediciones dejan de llegar sin
error visible.

### R4 — Cloudflare llega antes

Dynamic Workers está en beta abierta y hace algo muy parecido al titular. Mitigación: el
claim preciso no es «los únicos», es **«los únicos self-hosted, en tu propio VPS, con tu
máquina local como fuente de sincronización»** — que sigue siendo cierto y verificado.

### R5 — Alcance

El diferenciador elegido (híbrido con failover + ramas de datos) es de lo más difícil de
la lista. No es un fin de semana. El riesgo real no es técnico: es abandonar a mitad.

Mitigación: fases con valor demostrable al final de cada una (§13).

---

## 12. Pendiente de validación

Cuatro investigaciones en curso a 2026-09-12. **Ninguna conclusión de este documento que
dependa de ellas debe considerarse cerrada.**

1. **MCP 2026 a fondo** — revisión exacta del protocolo, Streamable HTTP a nivel de
   implementación, `server/discover`, elicitation, auth headless, y el diseño concreto de
   la superficie de herramientas de Culkibo
2. **Validación del hot-swap** — ¿funciona de verdad `createServerModuleRunner` en un
   proceso de larga vida? ¿Qué le pasa a los pools de conexiones, timers y singletons al
   reemplazar un módulo? Arte previo de Erlang/Elixir y Clojure. Patrón de proceso sombra
   y traspaso atómico
3. **Túnel e ingress** — desmontaje de `pgrok`, configuración concreta de Caddy
   (admin API, on-demand TLS, wildcard DNS-01, canario, swap con drenaje), decisión de
   transporte del túnel, y modelo de amenaza de exponer un portátil
4. **Ramas de datos y endurecimiento** — cómo ramificar Postgres en cada substrato,
   promoción de migraciones, y sustitución concreta de cada patrón de shell actual

---

## 13. Fases

Cada fase termina con algo demostrable y con los tests en verde.

### Fase 0 — Saldar la deuda de honestidad
Borrar la simulación. Proxy inverso real, TLS real vía Caddy, ACME real vía lego,
métricas reales o ninguna. Quitar el «<35 ms» del `package.json`. Autenticación en el
daemon. Eliminar la construcción de comandos de shell.

*Sin diferenciador nuevo. Pero si alguien instala Culkibo hoy y descubre que el candado
es un PEM inventado, la confianza se acaba para siempre.*

### Fase 1 — El túnel
Edición local → URL pública con TLS y dominio propio. Camino C únicamente (proceso nuevo
+ swap de ruta). Ya es demostrable y tuiteable.

### Fase 2 — El camino rápido
Camino B: hot-swap con commit frame, clasificación, verificación en sombra e historial de
rollback. Arnés de benchmark publicado.

### Fase 3 — Failover y promoción
Citadel sirviendo cuando Forge cae. Promoción atómica de lo ya probado. Rollback.

### Fase 4 — Ramas de datos
Detección de substrato y branching adaptativo. Promoción de migraciones.

### Fase 5 — MCP de primera clase
Protocolo 2026-07-28, Streamable HTTP, paridad de escritura, auth headless, migrador de
Coolify como herramienta.

---

## 14. Restricciones invariables

1. `npm test` con **10/10 suites en verde** y `npm --prefix web run build` con **0
   errores**, en todo momento
2. **100 % modo claro**, con los tokens corregidos de §9.1
3. **100 % español**, con las reglas de §9.5
4. Cada cifra publicada, con método reproducible
5. Ninguna afirmación de seguridad hasta que sea cierta
6. Auditable en una tarde
