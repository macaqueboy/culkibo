# Guía Definitiva de Migración: Coolify v4 → Culkibo (Zero Downtime)

> **Culkibo v1.0.0** es el orquestador de aplicaciones y contenedores para la era de la IA. Diseñado para ofrecer sincronización en caliente sub-35ms (frente a los 2-4 minutos de builds tradicionales en Coolify), soporte nativo de agentes IA mediante MCP (Model Context Protocol) y gestión unificada de certificados Wildcard y túneles Cloudflare.

---

## 1. Resumen de Paridad de Recursos

Culkibo preserva la estructura de proyectos de Coolify garantizando fidelidad total:

| Recurso | Coolify v4 | Culkibo v1.0.0 | Fidelidad |
| :--- | :--- | :--- | :---: |
| **Proyectos y Entornos** | Projects / Environments | Proyectos jerárquicos multi-recurso | 100% |
| **Aplicaciones Web** | Node, Python, Vite, Dockerfile, Compose | Entornos Desarrollo (Hot) & Producción (Citadel) | 100% |
| **Bases de Datos** | PostgreSQL, MySQL, Redis, MongoDB | Recursos gestionados con credenciales y volúmenes | 100% |
| **Volúmenes Persistentes** | `local_persistent_volumes` | Mapeo persistente en `/data/volumes` | 100% |
| **Montajes de Archivos** | `local_file_volumes` | Archivos de configuración inyectados | 100% |
| **Variables de Entorno** | Envs (Globales y de build) | Editor Dual (Visual y `.env` Raw) | 100% |
| **Dominios & SSL** | FQDN con Traefik | Ingress de ultra-baja latencia con Cloudflare DNS-01 | 100% |

---

## 2. Preparación Pre-Migración

### Obtener el API Token en Coolify v4
1. Entra a tu panel de Coolify (ej. `http://tu-vps:8000` o `https://app.tudominio.com`).
2. Ve a **Keys & Tokens** > **API Tokens**.
3. Haz clic en **+ Add New Token**, ponle de nombre `Culkibo-Migrator` y marca permisos de lectura completa (`read:all` o `admin`).
4. Copia el token generado (ej. `1|abc123xyz...`).

---

## 3. Procedimiento de Migración Paso a Paso

### Paso 1: Asistente Automático de Importación en Culkibo

1. Abre el panel de Culkibo en `http://localhost:3030` (o la IP de tu nuevo VPS).
2. Haz clic en el botón superior derecho **"Importar desde Coolify"**.
3. Introduce la **URL de tu Coolify** y el **Token de API**.
4. Culkibo consultará los endpoints de Coolify:
   - `/api/v1/projects`
   - `/api/v1/applications`
   - `/api/v1/databases`
   - `/api/v1/services`
5. Verás un resumen detallado con todos tus proyectos, el número de aplicaciones, bases de datos, variables de entorno y volúmenes persistentes.
6. Pulsa **"Iniciar Importación Inteligente"**. En pocos segundos todos tus proyectos estarán registrados en Culkibo.

---

### Paso 2: Migración de Datos de Bases de Datos

Para una migración sin interrupción, recomendamos volcar los datos mientras la aplicación antigua sigue sirviendo lecturas, o programar una ventana de conmutación de 1 minuto:

#### PostgreSQL (ej. GaleiaDB, AuraCV DB)
```bash
# 1. En el VPS de origen (Coolify):
docker exec -t <id_contenedor_postgres> pg_dump -U postgres -d <nombre_bd> -F c -b -v -f /tmp/backup_postgres.dump

# 2. Copiar hacia el VPS nuevo:
scp /tmp/backup_postgres.dump root@<nuevo_vps>:/var/backups/

# 3. Restaurar en Culkibo:
pg_restore -h localhost -p 5432 -U postgres -d <nombre_bd> -v /var/backups/backup_postgres.dump
```

#### MySQL / MariaDB
```bash
# 1. En el VPS de origen (Coolify):
docker exec <id_contenedor_mysql> mysqldump -u root -p<password> --single-transaction --quick <nombre_bd> > /tmp/backup_mysql.sql

# 2. Restaurar en Culkibo:
mysql -h localhost -P 3306 -u root -p<password> <nombre_bd> < /tmp/backup_mysql.sql
```

#### Redis
```bash
# Guardar estado a disco:
docker exec <id_contenedor_redis> redis-cli BGSAVE
# Copiar el archivo dump.rdb montado en el volumen persistente hacia el nuevo host.
```

#### MongoDB
```bash
docker exec <id_contenedor_mongo> mongodump --db <nombre_bd> --archive=/tmp/mongo_backup.archive --gzip
mongorestore --archive=/tmp/mongo_backup.archive --gzip --db <nombre_bd>
```

---

### Paso 3: Migración de Volúmenes Persistentes (Archivos y Medios)

Para copiar carpetas de medios (como los 6 volúmenes de MediaMate o Shorty):

```bash
# Sincronización recursiva con preservación de permisos y timestamps
rsync -avzP /var/lib/docker/volumes/<volumen_coolify>/_data/ root@<nuevo_vps>:/var/lib/culkibo/volumes/<volumen_culkibo>/
```

---

### Paso 4: Conmutación de Tráfico DNS con Zero Downtime

Si utilizas Cloudflare (Nube Naranja ☁️ activada):
1. La IP del registro `A` o `CNAME` en Cloudflare se actualiza a la nueva IP del servidor Culkibo.
2. Como el proxy de Cloudflare absorbe la caché de borde, los usuarios finales no experimentan caídas ni esperas de propagación DNS (cambio instantáneo).
3. El Ingress de Culkibo detecta automáticamente la cabecera `Host` y enruta al Entorno de Producción (:8080) con SSL activo.

---

## 4. Verificación y Health Check

Una vez finalizada la migración, ejecuta el diagnóstico completo en la terminal:

```powershell
culkibo doctor
```

Deberías ver:
```
🩺 DIAGNÓSTICO INTEGRAL DE CULKIBO
==================================================
  ✓ Node.js: v24.x (Cumple requisito mínimo >= v18)
  ✓ Motor Docker: Activo — Modo Nativo
  ✓ Directorio ./data: Permisos de lectura/escritura correctos
  ✓ Directorio ./projects: Permisos de lectura/escritura correctos
  ✓ Directorio ./data/backups: Permisos de lectura/escritura correctos
  ✓ Cloudflare API: Token configurado correctamente
  • Puerto 3030 (Panel/API): En uso (demonio activo)
==================================================
✨ Diagnóstico finalizado con éxito.
```

Comprueba los proyectos y dominios enrutados:
```powershell
culkibo pod list
culkibo domain list
```

---

## 5. Plan de Contingencia / Rollback

Si necesitas revertir el cambio temporalmente:
1. En Cloudflare, vuelve a cambiar la IP del registro DNS a la IP del VPS anterior donde corre Coolify.
2. Coolify seguirá teniendo sus contenedores intactos, ya que la migración es de solo-lectura y no altera el VPS de origen.
