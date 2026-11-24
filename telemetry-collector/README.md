# Culkibo Telemetry Collector & Ops Dashboard

Recolector cloud **sin dependencias externas** (`0` paquetes npm) construido sobre `node:http` y `node:sqlite` (WAL nativo de Node 22/24) + adaptador alternativo para **Cloudflare Workers + D1** (capa gratuita hasta 100.000 envíos/día).

## Características

- **Ingesta endurecida (`POST /v1/ingest`)**: validación estricta Schema v1, límite 64 KB, segunda capa anti-PII y rate-limit dual (IP hasheada con HMAC-SHA256 + sal efímera en RAM + límite por `instanceId`). **Nunca guarda IPs reales en disco ni en base de datos.**
- **Agrupación de fallos y detección de regresiones**: agrupa crashes, HTTP 5xx, fallos operativos y errores de UI por `fingerprint`. Si un fallo marcado como `resolved` reaparece en una versión nueva de Culkibo, lo reabre automáticamente y dispara una alerta de **REGRESIÓN**.
- **Alertas instantáneas**: Telegram, Discord, Slack y Webhook firmado con HMAC-SHA256 (`X-Culkibo-Signature`), con cooldown por fingerprint y alertas de pico.
- **Panel Ops incluido (`GET /`)**: KPIs 24h/7d/30d, adopción de versiones, plataformas/Docker/Caddy, tabla interactiva de fallos con trazas, tasa de éxito por funcionalidad y exportación JSON/CSV.
- **Archivo histórico NDJSON.gz**: guarda un archivo diario saneado y comprime los días anteriores con `gzip`.

## Despliegue rápido (Docker / VPS)

```bash
cd telemetry-collector
cp .env.example .env
# Rellena ADMIN_TOKEN y tu bot de Telegram / Webhook de Discord en .env
docker compose up -d --build
```

Luego apunta tu dominio (por ejemplo `https://telemetry.culkibo.dev`) mediante Caddy/Cloudflare al puerto `127.0.0.1:8787`.

## Despliegue sin coste en Cloudflare Workers + D1

```bash
cd telemetry-collector/cloudflare
npx wrangler d1 create culkibo-telemetry
# Copia el database_id en wrangler.toml
npx wrangler d1 execute culkibo-telemetry --remote --file=./schema.sql
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put ALERT_TELEGRAM_BOT_TOKEN
npx wrangler secret put ALERT_TELEGRAM_CHAT_ID
npx wrangler deploy
```

## Pruebas

```bash
npm test
```
