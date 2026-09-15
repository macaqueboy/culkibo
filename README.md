# ⚡ CULKIBO v1.0.0 — The AI-Era Cloud Orchestrator

> Plataforma open-source alternativa de última generación a **Coolify**, **Dokploy** y **Vercel**, diseñada específicamente para la era de la IA, con despliegues en caliente sub-35ms, control nativo por MCP (Model Context Protocol) y orquestación integral de dominios con Cloudflare & Wildcard SSL (DNS-01 ACME).

---

## 🌟 Características Principales

### 1. Gestión de Dominios y Certificados Wildcard SSL
- **Integración Nativa con Cloudflare API**:
  - Desafíos **ACME DNS-01** automáticos para certificados wildcard (`*.tudominio.com` y dominio raíz).
  - Inyección y limpieza automática de registros TXT `_acme-challenge.<dominio>` sin intervención manual.
  - Gestión integral de registros DNS (A, CNAME, TXT, AAAA) con modo **Cloudflare Proxy (Nube Naranja ☁️)** o **DNS Only (Nube Gris ☁️)**.
  - Integración con **Cloudflare Zero Trust Tunnels (`cloudflared`)** para exponer pods sin abrir puertos ni IP pública.
- **Soporte Zero-Config `sslip.io` / `nip.io`**:
  - Generación instantánea de comodines TLS bajo demanda (e.g. `*.127-0-0-1.sslip.io`) para entornos locales y previsualizaciones sin necesidad de comprar un dominio.
- **Bóveda de Certificados y Verificación DNS**:
  - Comprobador en vivo de propagación y resolución DNS con detección automática de Cloudflare Edge.
  - Almacenamiento seguro en disco (`./data/certs/`), seguimiento de fechas de expiración y loop de renovación automática (&lt;30 días).

---

### 2. Arquitectura de Pods: The Forge vs The Citadel
- **The Forge (Development Hot Pod)**:
  - Sincronización en caliente y re-compilación instantánea en **&lt;35ms** (media de 18-25ms).
  - Monitorización de archivos en tiempo real mediante `chokidar`.
  - Cero cold-starts para iteración ultra-rápida asistida por IA.
- **The Citadel (Production Hardened Pod)**:
  - Despliegues inmutables con probes de lectura y salud.
  - Actualizaciones atómicas y switches de tráfico **zero-downtime**.
- **Director de Tráfico en Tiempo Real**:
  - Enrutamiento dinámico a nivel de proxy (100% Citadel, Canary 10% Dev / 90% Prod, o 100% Forge) con conmutación en microsegundos.

---

### 3. Servidor MCP (Model Context Protocol) Nativo
- Servidor MCP integrado cumpliendo con la especificación JSON-RPC 2.0 (`2024-11-05`).
- Conexión vía **stdio** o **SSE (Server-Sent Events)** en `/api/mcp/sse`.
- Herramientas expuestas para agentes como Cursor, Windsurf y Claude Desktop:
  1. `culkibo_list_pods`: Inspecciona métricas, telemetría y estado de los pods.
  2. `culkibo_hot_sync`: Aplica modificaciones de código al vuelo en &lt;35ms.
  3. `culkibo_switch_traffic`: Re-enruta tráfico de forma dinámica.
  4. `culkibo_manage_domain`: Añade o elimina dominios y activa proxy Cloudflare.
  5. `culkibo_issue_wildcard_ssl`: Dispara el desafío DNS-01 ACME en Cloudflare.
  6. `culkibo_create_sslip_domain`: Crea un comodín local con TLS en un clic.
  7. `culkibo_get_logs`: Transmite logs en streaming filtrados por pod o severidad.
- Consola de Auditoría en Tiempo Real de todas las acciones ejecutadas por agentes de IA.

---

### 4. Dashboard Web de Calidad Studio (Cero "AI Slop")
- Desarrollado en React 19 + TypeScript + Tailwind CSS v4 + Vite + Lucide Icons.
- Estética industrial refinada: tema oscuro obsidiana/carbón, acentos cálidos ámbar/forja, tipografía Plus Jakarta Sans & JetBrains Mono, micro-interacciones sutiles y consola de terminal ANSI en streaming.
- Telemetría en tiempo real por **WebSocket nativo** (`ws://localhost:3030/ws`).

---

## 🚀 Inicio Rápido

### Opción A: Script PowerShell de 1 Clic (Windows)
```powershell
.\start.ps1
```

### Opción B: Inicio con Node / npm
```bash
# 1. Instalar dependencias raíz
npm install

# 2. Compilar assets del dashboard web
npm run build

# 3. Iniciar el Daemon de Culkibo
npm start
```

Abre tu navegador en:
👉 **`http://localhost:3030`**

---

## 💻 CLI de Culkibo (`culkibo`)

La CLI permite controlar toda la plataforma por terminal:

```bash
# Ver versión
node bin/culkibo.js --version

# Listar estado y métricas de los pods
node bin/culkibo.js pod list

# Disparar sincronización en caliente (<35ms)
node bin/culkibo.js pod sync --file src/app.ts

# Conmutar tráfico entre Forge y Citadel
node bin/culkibo.js pod switch forge      # 100% Forge
node bin/culkibo.js pod switch citadel    # 100% Citadel
node bin/culkibo.js pod switch 20/80      # 20% Forge / 80% Citadel

# Listar dominios y certificados SSL
node bin/culkibo.js domain list

# Añadir dominio o comodín
node bin/culkibo.js domain add "*.midominio.com" --pod forge --proxy

# Emitir certificado Wildcard SSL vía Cloudflare DNS-01 ACME
node bin/culkibo.js domain issue-wildcard "*.midominio.com" --provider lets_encrypt

# Generar comodín sslip.io con TLS On-Demand
node bin/culkibo.js domain sslip 127.0.0.1

# Iniciar servidor MCP por stdio (Claude Desktop / Cursor)
node bin/culkibo.js mcp
```

---

## 🤖 Conectar con Agentes de IA (Cursor / Claude Desktop)

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "culkibo": {
      "command": "node",
      "args": ["C:\\Users\\pablo\\Desktop\\Culkibo\\bin\\culkibo.js", "mcp"],
      "env": {
        "CULKIBO_API_URL": "http://localhost:3030"
      }
    }
  }
}
```

### Cursor / Windsurf
Añade como SSE Server:
```
http://localhost:3030/api/mcp/sse
```

---

## 🧪 Ejecutar la Suite de Pruebas
Culkibo incluye tests automáticos para todos sus subsistemas:
```bash
npm test
```
Pruebas incluidas:
- `cloudflare.test.js`: Validación de tokens, zonas, registros DNS, inyección ACME TXT y túneles.
- `ssl.test.js`: Pipeline completo DNS-01 Let's Encrypt, TLS bajo demanda `sslip.io` y cálculo de expiración.
- `domain.test.js`: Resolución de rutas exactas y comodines, prevención de duplicados y resolución DNS.
- `orchestrator.test.js`: Latencia sub-35ms de The Forge, conmutación de tráfico y despliegue a The Citadel.
- `mcp.test.js`: Especificación JSON-RPC 2.0, catálogo de herramientas, ejecución y auditoría.
- `live-server.test.js`: Servidor HTTP/WebSocket y entrega de assets estáticos de producción.

---

## 📁 Estructura del Proyecto

```
c:\Users\pablo\Desktop\Culkibo\
├── bin/
│   └── culkibo.js                 # CLI ejecutable de Culkibo
├── server/
│   ├── index.js                   # Daemon principal HTTP + WebSocket + MCP
│   ├── routes/
│   │   └── api.js                 # API REST completa
│   └── services/
│       ├── cloudflareService.js   # Cliente Cloudflare (Zonas, DNS, Túneles, ACME)
│       ├── sslManager.js          # Orquestador ACME DNS-01, Wildcard & On-Demand TLS
│       ├── domainManager.js       # Registro de dominios y tabla de enrutamiento
│       ├── containerOrchestrator.js # Gestor The Forge (<35ms) vs The Citadel
│       └── mcpServer.js           # Servidor nativo Model Context Protocol
├── web/                           # Dashboard UI (React 19 + TypeScript + Tailwind v4)
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.tsx         # Barra superior con WS live status y hot sync
│   │   │   ├── PodsOverview.tsx   # Visualizador The Forge vs Citadel & Traffic Slider
│   │   │   ├── DomainManager.tsx  # Orquestador de Dominios, Wildcard ACME & sslip.io
│   │   │   ├── CloudflareTunnelCard.tsx # Gestión de credenciales CF, Tunnels y DNS
│   │   │   ├── LiveLogs.tsx       # Terminal de streaming en tiempo real
│   │   │   ├── McpInspector.tsx   # Sala de control MCP y playground de herramientas AI
│   │   │   ├── DeployModal.tsx    # Modal de despliegue atómico a producción
│   │   │   └── SettingsView.tsx   # Matriz de capacidades del sistema
│   │   ├── lib/api.ts             # Cliente tipado de API y WebSocket
│   │   └── App.tsx
│   └── dist/                      # Bundle de producción listo para servir
├── tests/                         # Suite de verificación integral
├── start.ps1                      # Lanzador rápido para PowerShell
└── package.json                   # Configuración del paquete raíz
```

---

Diseñado y construido con precisión para Pablo.
