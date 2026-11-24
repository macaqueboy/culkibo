'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { loadConfig } = require('./lib/config');
const { validateEnvelope } = require('./lib/schema');
const { DualRateLimiter } = require('./lib/rateLimit');
const { TelemetryStorage } = require('./lib/storage');
const { TelemetryAlerter } = require('./lib/alerter');

const DASHBOARD_HTML = fs.readFileSync(path.join(__dirname, 'lib', 'dashboard.html'), 'utf8');

/** @param {string} a @param {string} b */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** @param {http.IncomingMessage} req @param {boolean} trustProxy */
function extractClientIp(req, trustProxy) {
  if (trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim();
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length > 0) return parts[parts.length - 1];
    }
  }
  return req.socket?.remoteAddress || 'unknown';
}

/** @param {http.IncomingMessage} req @param {number} maxBytes */
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > maxBytes) {
        done = true;
        req.resume();
        const err = new Error('Payload demasiado grande');
        /** @type {any} */ (err).statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!done) {
        done = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      }
    });
    req.on('error', (err) => {
      if (!done) {
        done = true;
        reject(err);
      }
    });
  });
}

/** @param {http.ServerResponse} res @param {number} status @param {any} data @param {Record<string, string>} [extraHeaders] */
function sendJson(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

/**
 * Crea una instancia completa del servidor recolector (útil tanto en producción como en tests).
 * @param {Record<string, any>} [overrides]
 */
function createCollectorServer(overrides = {}) {
  const config = loadConfig(overrides);
  const storage = new TelemetryStorage({
    dbPath: config.dbPath,
    archiveDir: config.archiveDir,
    retentionDays: config.retentionDays,
    alertSpikeThreshold: config.alertSpikeThreshold,
  });
  const rateLimiter = new DualRateLimiter(overrides.rateLimit || {});
  const alerter = new TelemetryAlerter({
    alerts: config.alerts,
    alertCooldownMs: config.alertCooldownMs,
    fetchImpl: overrides.fetchImpl,
  });

  const startedAt = Date.now();
  const retentionTimer = setInterval(() => {
    try { storage.pruneRetention(); } catch { /* ignore */ }
  }, 12 * 60 * 60 * 1000);
  if (retentionTimer.unref) retentionTimer.unref();

  /** @param {http.IncomingMessage} req */
  function isAdminAuthorized(req) {
    const auth = String(req.headers.authorization || '');
    if (!auth.startsWith('Bearer ')) return false;
    return safeEqual(auth.slice(7).trim(), config.adminToken);
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      const pathname = url.pathname;
      const method = (req.method || 'GET').toUpperCase();

      if (method === 'GET' && pathname === '/health') {
        return sendJson(res, 200, {
          ok: true,
          service: 'culkibo-telemetry-collector',
          uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
        });
      }

      if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
          'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        });
        res.end(DASHBOARD_HTML);
        return;
      }

      if (method === 'POST' && pathname === '/v1/ingest') {
        const ip = extractClientIp(req, config.trustProxy);
        const ipCheck = rateLimiter.checkIp(ip);
        if (!ipCheck.allowed) {
          return sendJson(res, 429, { error: 'Demasiadas peticiones desde este origen' }, { 'Retry-After': String(ipCheck.retryAfterSec) });
        }

        let raw;
        try {
          raw = await readBody(req, config.maxBodyBytes);
        } catch (err) {
          const code = /** @type {any} */ (err).statusCode || 400;
          return sendJson(res, code, { error: err.message }, code === 413 ? { Connection: 'close' } : {});
        }

        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch {
          return sendJson(res, 400, { error: 'JSON malformado' });
        }

        const validated = validateEnvelope(parsed);
        if (!validated.ok || !validated.envelope) {
          return sendJson(res, 400, { error: validated.error || 'Sobre inválido' });
        }

        const instCheck = rateLimiter.checkInstance(validated.envelope.instanceId);
        if (!instCheck.allowed) {
          return sendJson(res, 429, { error: 'Límite horario alcanzado para esta instancia' }, { 'Retry-After': String(instCheck.retryAfterSec) });
        }

        const { accepted, alertCandidates } = storage.ingestEnvelope(validated.envelope);

        for (const cand of alertCandidates) {
          void alerter.notify(cand)
            .then((r) => { if (r && r.sent > 0) storage.markAlertSent(cand.fingerprint); })
            .catch(() => {});
        }

        return sendJson(res, 202, {
          accepted,
          alertsQueued: alertCandidates.length,
        });
      }

      if (pathname.startsWith('/admin/api/')) {
        if (!isAdminAuthorized(req)) {
          return sendJson(res, 401, { error: 'Se requiere cabecera Authorization: Bearer <ADMIN_TOKEN>' });
        }

        if (method === 'GET' && pathname === '/admin/api/summary') {
          return sendJson(res, 200, storage.getSummary());
        }

        if (method === 'GET' && pathname === '/admin/api/issues') {
          const status = url.searchParams.get('status') || 'all';
          const type = url.searchParams.get('type') || 'all';
          const limit = Number(url.searchParams.get('limit') || 100);
          return sendJson(res, 200, { issues: storage.listIssues({ status, type, limit }) });
        }

        const patchMatch = pathname.match(/^\/admin\/api\/issues\/([a-f0-9_-]{8,32})$/i);
        if (method === 'PATCH' && patchMatch) {
          const raw = await readBody(req, 4096);
          const body = JSON.parse(raw || '{}');
          const updated = storage.updateIssueStatus(patchMatch[1], String(body.status || ''));
          if (!updated) return sendJson(res, 404, { error: 'Fingerprint no encontrado' });
          return sendJson(res, 200, { updated });
        }

        if (method === 'GET' && pathname === '/admin/api/events') {
          const type = url.searchParams.get('type') || 'all';
          const fingerprint = url.searchParams.get('fingerprint') || '';
          const limit = Number(url.searchParams.get('limit') || 100);
          return sendJson(res, 200, { events: storage.listEvents({ type, fingerprint, limit }) });
        }

        if (method === 'GET' && pathname === '/admin/api/export') {
          const fmt = url.searchParams.get('format') === 'csv' ? 'csv' : 'json';
          const content = storage.exportIssues(fmt);
          res.writeHead(200, {
            'Content-Type': fmt === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8',
            'Content-Disposition': `attachment; filename="culkibo-telemetry.${fmt}"`,
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-store',
          });
          res.end(content);
          return;
        }

        return sendJson(res, 404, { error: 'Ruta de administración no encontrada' });
      }

      return sendJson(res, 404, { error: 'No encontrado' });
    } catch (err) {
      return sendJson(res, 500, { error: 'Error interno del recolector' });
    }
  });

  const close = () => new Promise((resolve) => {
    clearInterval(retentionTimer);
    server.close(() => {
      storage.close();
      resolve();
    });
  });

  return { server, config, storage, alerter, rateLimiter, close };
}

if (require.main === module) {
  const app = createCollectorServer();
  app.server.listen(app.config.port, app.config.bind, () => {
    console.log(`[Culkibo Telemetry Collector] Escuchando en http://${app.config.bind}:${app.config.port}`);
    console.log(`[Culkibo Telemetry Collector] SQLite WAL: ${app.config.dbPath}`);
    if (app.config.tokenGenerated) {
      console.log(`[Culkibo Telemetry Collector] ADMIN_TOKEN generado y guardado en: ${app.config.tokenFile}`);
    }
  });
  const shutdown = () => {
    app.close().then(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { createCollectorServer };
