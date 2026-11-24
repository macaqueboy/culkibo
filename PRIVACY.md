# Privacidad y Telemetría de Culkibo

Culkibo incluye un sistema de telemetría y diagnóstico de fallos **transparente, anónimo y desactivable** diseñado para detectar errores reales en producción, priorizar mejoras y reaccionar ante regresiones en cuanto se publican nuevas versiones.

---

## 1. Qué datos enviamos

Todos los sobres se ajustan a un esquema público (`schemaVersion: 1`) y pasan por un saneado de **11 fases** antes de salir del servidor (y una segunda capa de saneado en el recolector):

| Tipo de evento | Qué contiene | Para qué sirve |
|---|---|---|
| `instance_heartbeat` | `instanceId` (UUIDv4 aleatorio), versión de Culkibo, Node.js, sistema operativo (`platform`/`arch`), rangos aproximados de RAM y número de proyectos/BDs (`0`, `1-5`, `6-20`, `20+`), disponibilidad booleana de Docker/Caddy y flags booleanos de funciones activas | Medir adopción de versiones y compatibilidad real de plataformas |
| `server_crash` | Tipo (`uncaughtException` / `unhandledRejection`), nombre/código de error, mensaje saneado y traza con rutas de usuario eliminadas (`<home>`, `<app>`) | Detectar y corregir caídas críticas del daemon |
| `api_error_5xx` | Método HTTP, ruta **canónica** (p. ej. `/api/projects/:id/deploy`, nunca IDs reales), código 5xx y mensaje saneado | Detectar fallos silenciosos en la API REST |
| `operation_failure` | Nombre de operación (`deploy`, `database_backup`, `catalog_install`, `ingress_reconcile`, `mcp_tool`), fase, motor/stack y mensaje saneado | Identificar qué flujos críticos fallan en instalaciones reales |
| `client_error` | Origen (`error_boundary`, `window_error`, `unhandled_rejection`), vista activa (lista blanca fija), tipo/mensaje saneado y rango de viewport (`mobile`/`tablet`/`desktop`/`wide`) | Corregir errores de interfaz en navegadores reales |
| `feature_usage` | Contadores agregados `ok`/`fail` por funcionalidad (p. ej. `deploy:docker`, `db_backup:postgres`) | Saber qué funciones se usan más y cuáles necesitan pulido |

---

## 2. Qué NUNCA recopilamos

- Nombres, URLs o contenido de proyectos, repositorios Git, ramas o dominios personalizados.
- Variables de entorno, contraseñas, tokens (`ghp_*`, `sk_*`, JWT, Bearer), claves privadas PEM ni cadenas de conexión con credenciales.
- Direcciones IP (en el recolector las IPs solo se usan en RAM con HMAC-SHA256 y sal efímera por arranque para rate-limiting; nunca se escriben a disco ni en SQLite).
- Correos electrónicos, nombres de usuario del sistema operativo ni rutas locales personales.
- Datos de bases de datos, backups, logs de negocio ni tráfico de usuarios finales.

---

## 3. Cómo inspeccionar el payload exacto

Antes o después de decidir, puedes ver el sobre JSON exacto que tu instancia enviaría:

- **Desde el panel web:** `Ajustes → Sistema → Telemetría y diagnósticos → Ver payload exacto`
- **Desde la CLI:**
  ```bash
  node bin/culkibo.js telemetry preview
  ```
- **Modo depuración en consola:**
  ```bash
  CULKIBO_TELEMETRY_DEBUG=1 node server/index.js
  ```

---

## 4. Cómo desactivar la telemetría (4 formas equivalentes)

La telemetría se desactiva **inmediatamente** y vacía su cola en memoria mediante cualquiera de estos métodos (por orden de precedencia):

1. **Variable de entorno dedicada (anula la configuración guardada):**
   ```bash
   CULKIBO_TELEMETRY=0
   ```
2. **Estándar `Do Not Track`:**
   ```bash
   DO_NOT_TRACK=1
   ```
3. **Interfaz web:** `Ajustes → Sistema → Telemetría y diagnósticos` (interruptor instantáneo + botón **Rotar ID**).
4. **CLI:**
   ```bash
   node bin/culkibo.js telemetry disable
   # Para volver a activarla:
   node bin/culkibo.js telemetry enable
   # Para rotar el UUID anónimo:
   node bin/culkibo.js telemetry reset
   ```

Además, la telemetría se **auto-desactiva automáticamente** durante la ejecución de tests (`NODE_ENV=test`, `CI=true`, `tests/`).

---

## 5. Endpoint y auto-alojamiento del recolector

Por defecto, Culkibo envía los lotes saneados a `CULKIBO_TELEMETRY_URL` (por defecto `https://telemetry.culkibo.dev/v1/ingest`) usando un circuit breaker exponencial (hasta 6 horas de espera si el recolector no responde), timeouts estrictos y sin frenar nunca el daemon.

Si quieres desplegar tu propio recolector en un VPS o en Cloudflare Workers + D1, consulta [telemetry-collector/README.md](telemetry-collector/README.md).
