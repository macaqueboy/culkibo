const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { atomicWriteJsonSync } = require('../services/ssrfGuard');

const AUTH_FILE = path.join(__dirname, '..', '..', 'data', 'auth.json');

/**
 * Autenticación del plano de control.
 *
 * Dos capas obligatorias:
 *  - Origen: corta peticiones cross-origin desde pestañas maliciosas.
 *  - Token: protege cualquier acceso remoto (VPS, reverse proxy, CI, MCP).
 *
 * Incluye:
 *  - Verificación de TODOS los saltos en X-Forwarded-For / Forwarded (corta spoofing leftmost).
 *  - Protección anti fuerza bruta integrada en el propio authMiddleware (LRU acotado).
 *  - Tickets WebSocket efímeros de un solo uso (30 s) + rotación atómica de token.
 */

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost']);

/** @type {string | null} */
let cachedToken = null;
/** @type {Buffer | null} */
let cachedTokenBuf = null;
/** @type {Set<string>} */
const dynamicOrigins = new Set();

// Tickets WebSocket de un solo uso (30 s TTL, acotados a 200 entradas)
/** @type {Map<string, { expiresAt: number, ip: string }>} */
const wsTickets = new Map();
const WS_TICKET_TTL_MS = 30000;

// Rate-limiter global de fallos de autenticación (LRU acotado, nunca clear() masivo)
/** @type {Map<string, { count: number, resetAt: number }>} */
const authFailMap = new Map();
const AUTH_FAIL_WINDOW_MS = 60000;
const AUTH_FAIL_MAX = 20;
const AUTH_FAIL_MAP_CAP = 2000;
const NO_BRUTE_FORCE = Object.freeze({ blocked: false, retryAfterSec: 0 });
const OK_LOOPBACK = Object.freeze({ ok: true, method: 'loopback' });
const OK_LOOPBACK_ORIGIN = Object.freeze({ ok: true, method: 'loopback_origin' });
const OK_TOKEN = Object.freeze({ ok: true, method: 'token' });
const OK_WS_TICKET = Object.freeze({ ok: true, method: 'ws_ticket' });
const ERR_INVALID_TOKEN = Object.freeze({ ok: false, status: 401, error: 'Token inválido' });
const ERR_INVALID_TICKET = Object.freeze({ ok: false, status: 401, error: 'Ticket WebSocket inválido o caducado' });
const ERR_AUTH_REQUIRED = Object.freeze({
  ok: false,
  status: 401,
  error: 'Autenticación requerida',
  detail: 'Envía el token en la cabecera Authorization: Bearer <token>, o en X-Culkibo-Token. Lo encuentras en data/auth.json o en la variable CULKIBO_TOKEN.'
});
const TRUST_PROXY_UNIQUE_LOCAL = String(process.env.CULKIBO_TRUST_PROXY || 'loopback').toLowerCase().includes('uniquelocal');

/** @param {string} ip */
function isPrivateProxyPeer(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^::ffff:/, '');
  if (LOOPBACK.has(clean)) return true;
  if (!TRUST_PROXY_UNIQUE_LOCAL) return false;
  if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
  if (/^(fc|fd)[0-9a-f]{2}:/i.test(clean)) return true;
  const m = clean.match(/^172\.(\d+)\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

/**
 * Extrae el hostname limpio de una cabecera `Host` (quitando puerto, corchetes IPv6 y punto FQDN).
 * @param {string | undefined} rawHost
 * @returns {string}
 */
function extractHostHeaderName(rawHost) {
  if (!rawHost) return '';
  const first = String(rawHost).split(',')[0].trim().toLowerCase();
  if (!first) return '';
  if (first.startsWith('[')) {
    const end = first.indexOf(']');
    return end > 1 ? first.slice(1, end).replace(/\.+$/, '') : '';
  }
  const colonIdx = first.indexOf(':');
  const name = colonIdx !== -1 ? first.slice(0, colonIdx) : first;
  return name.replace(/\.+$/, '');
}

/** Normaliza `host[:port]` quitando puerto por defecto (`:80` / `:443`). */
function normalizeHostWithPort(rawHost, protocol) {
  const clean = String(rawHost || '').trim().toLowerCase();
  if (!clean) return '';
  if (protocol === 'https:' && clean.endsWith(':443')) return clean.slice(0, -4);
  if (protocol === 'http:' && clean.endsWith(':80')) return clean.slice(0, -3);
  return clean;
}

/** Permite registrar un origen adicional en caliente (p. ej. dominio propio del panel). */
function addAllowedOrigin(origin) {
  if (!origin || typeof origin !== 'string') return;
  try {
    const parsed = new URL(origin.trim());
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      dynamicOrigins.add(parsed.origin);
      cachedOriginsKey = null;
    }
  } catch (e) {}
}

/** Token activo. Se genera y persiste la primera vez si no hay ninguno. */
function resolveToken() {
  if (cachedToken) return cachedToken;

  if (process.env.CULKIBO_TOKEN) {
    cachedToken = process.env.CULKIBO_TOKEN;
    cachedTokenBuf = Buffer.from(cachedToken, 'utf8');
    return cachedToken;
  }

  try {
    if (fs.existsSync(AUTH_FILE)) {
      const stored = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
      if (typeof stored.token === 'string' && stored.token) {
        cachedToken = stored.token;
        cachedTokenBuf = Buffer.from(stored.token, 'utf8');
        return cachedToken;
      }
    }
  } catch (e) {}

  cachedToken = crypto.randomBytes(32).toString('hex');
  cachedTokenBuf = Buffer.from(cachedToken, 'utf8');
  try {
    atomicWriteJsonSync(AUTH_FILE, { token: cachedToken, createdAt: new Date().toISOString() }, 0o600);
  } catch (e) {
    console.warn('[Auth] No se pudo guardar el token en disco; será distinto en cada arranque:', e.message);
  }
  return cachedToken;
}

/** @type {Set<() => void>} */
const tokenRotatedListeners = new Set();

/** Permite suscribirse a rotaciones del token maestro para revocar sesiones WS/SSE activas. */
function onTokenRotated(listener) {
  if (typeof listener === 'function') tokenRotatedListeners.add(listener);
  return () => tokenRotatedListeners.delete(listener);
}

/** Rota el token maestro de forma atómica (si no viene fijado por variable de entorno). */
function rotateToken() {
  if (process.env.CULKIBO_TOKEN) {
    throw new Error('El token está fijado por la variable de entorno CULKIBO_TOKEN. Cámbiala y reinicia el servicio.');
  }
  const nextToken = crypto.randomBytes(32).toString('hex');
  const rotatedAt = new Date().toISOString();
  atomicWriteJsonSync(AUTH_FILE, { token: nextToken, rotatedAt }, 0o600);
  cachedToken = nextToken;
  cachedTokenBuf = Buffer.from(nextToken, 'utf8');
  wsTickets.clear();
  for (const fn of tokenRotatedListeners) {
    try { fn(); } catch (e) {}
  }
  return { rotated: true, token: nextToken, rotatedAt, tokenSource: 'data/auth.json' };
}

/** @type {string | null} */
let cachedOriginsKey = null;
/** @type {Set<string> | null} */
let cachedOriginsSet = null;

/** Orígenes de navegador permitidos (cacheado por env). */
function allowedOrigins() {
  const port = process.env.PORT || 3030;
  const raw = process.env.CULKIBO_ALLOWED_ORIGINS || '';
  const dynKey = dynamicOrigins.size ? Array.from(dynamicOrigins).join(',') : '';
  const key = `${port}|${raw}|${dynKey}`;
  if (cachedOriginsSet && cachedOriginsKey === key) return cachedOriginsSet;

  const configured = raw.split(',').map(s => s.trim()).filter(Boolean);
  cachedOriginsKey = key;
  cachedOriginsSet = new Set([
    ...configured,
    ...dynamicOrigins,
    `http://localhost:${port}`,
    `http://127.0.0.1:${port}`,
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  ]);
  return cachedOriginsSet;
}

/**
 * @param {string | undefined} origin
 * @param {any} [req]
 */
function isOriginAllowed(origin, req = null) {
  if (!origin) return true; // no es una petición de navegador
  if (allowedOrigins().has(origin)) return true;

  // Si el panel está servido desde el propio host de este daemon (p. ej. un
  // VPS con dominio propio o IP pública), el mismo origen (`Origin.host === Host`)
  // se permite siempre que se autentique con token (nunca exime loopback).
  if (req && req.headers) {
    try {
      const parsedOrigin = new URL(origin);
      if (parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') return false;
      const originHost = normalizeHostWithPort(parsedOrigin.host, parsedOrigin.protocol);
      const peerAddr = req.socket?.remoteAddress || '';
      const trustFwd = isPrivateProxyPeer(peerAddr);
      let reqHostRaw = req.headers.host;
      if (trustFwd && req.headers['x-forwarded-host']) {
        const fwdHosts = String(req.headers['x-forwarded-host']).split(',').map((s) => s.trim()).filter(Boolean);
        if (fwdHosts.length > 0) reqHostRaw = fwdHosts[fwdHosts.length - 1];
      }
      const reqHost = normalizeHostWithPort(String(reqHostRaw || '').split(',')[0].trim(), parsedOrigin.protocol);
      if (originHost && reqHost && originHost === reqHost) return true;
    } catch (e) {}
  }

  return false;
}

/** Comparación en tiempo constante: una comparación normal filtra el token. */
function tokenMatches(provided) {
  if (!provided) return false;
  if (!cachedTokenBuf) resolveToken();
  if (!cachedTokenBuf) return false;
  const a = Buffer.from(String(provided), 'utf8');
  if (a.length !== cachedTokenBuf.length) return false;
  try {
    return crypto.timingSafeEqual(a, cachedTokenBuf);
  } catch (e) {
    return false;
  }
}

/** Extrae IP efectiva del cliente para buckets de rate-limiting y tickets WS. */
function clientIp(req) {
  const peer = String(req?.socket?.remoteAddress || '').trim().toLowerCase().replace(/^::ffff:/, '');
  if (isPrivateProxyPeer(peer)) {
    if (req?.headers?.['x-forwarded-for']) {
      const hops = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()).filter(Boolean);
      if (hops.length > 0) return hops[hops.length - 1].toLowerCase().replace(/^::ffff:/, '');
    }
    if (req?.headers?.forwarded) {
      const matches = Array.from(String(req.headers.forwarded).matchAll(/for=(?:"?\[?)([^;\s,"\]]+)/gi));
      if (matches.length > 0) {
        return matches[matches.length - 1][1].trim().toLowerCase().replace(/^::ffff:/, '');
      }
    }
  }
  return peer || String(req?.ip || 'local').trim().toLowerCase().replace(/^::ffff:/, '');
}

/** Emite un ticket WebSocket efímero (30 s, un solo uso) ligado a la IP del cliente. */
function createWsTicket(req) {
  const now = Date.now();
  if (wsTickets.size > 200) {
    for (const [k, v] of wsTickets.entries()) {
      if (v.expiresAt <= now) wsTickets.delete(k);
    }
    if (wsTickets.size > 200) {
      const oldest = wsTickets.keys().next().value;
      if (oldest) wsTickets.delete(oldest);
    }
  }
  const ticket = crypto.randomBytes(24).toString('base64url');
  wsTickets.set(ticket, { expiresAt: now + WS_TICKET_TTL_MS, ip: clientIp(req) });
  return { ticket, expiresInMs: WS_TICKET_TTL_MS };
}

/** Consume un ticket WebSocket efímero (un solo uso). */
function consumeWsTicket(ticket, req) {
  if (!ticket) return false;
  const entry = wsTickets.get(ticket);
  if (!entry) return false;
  wsTickets.delete(ticket);
  if (entry.expiresAt < Date.now()) return false;
  if (req) {
    const ip = clientIp(req);
    if (entry.ip && ip && entry.ip !== ip && !(LOOPBACK.has(entry.ip) && LOOPBACK.has(ip))) {
      return false;
    }
  }
  return true;
}

/**
 * Extrae token o ticket efímero de la petición (sin asignaciones innecesarias en /ws).
 * Por seguridad, `Sec-WebSocket-Protocol` SOLO se lee cuando `allowWsSubprotocol: true`
 * (exclusivamente desde `server.on('upgrade')`), impidiendo que peticiones HTTP normales
 * falseen `Upgrade: websocket` para eludir rate-limiting o consumir tickets WS.
 *
 * @param {any} req
 * @param {{ allowWsSubprotocol?: boolean }} [options]
 * @returns {{ token: string | null, ticket: string | null }}
 */
function extractCredentials(req, options = {}) {
  const header = req.headers.authorization;
  if (header && header.length > 7 && header.slice(0, 7).toLowerCase() === 'bearer ') {
    return { token: header.slice(7).trim(), ticket: null };
  }
  const xTok = req.headers['x-culkibo-token'];
  if (xTok) return { token: String(xTok).trim(), ticket: null };

  if (options && options.allowWsSubprotocol) {
    const upgrade = req.headers.upgrade;
    if (upgrade && String(upgrade).toLowerCase() === 'websocket') {
      const proto = req.headers['sec-websocket-protocol'];
      if (proto) {
        const parts = String(proto).split(',');
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i].trim();
          if (part.startsWith('culkibo-ticket.')) {
            return { token: null, ticket: part.slice('culkibo-ticket.'.length).trim() };
          }
          if (part.startsWith('culkibo-token.')) {
            return { token: part.slice('culkibo-token.'.length).trim(), ticket: null };
          }
        }
      }
    }
  }
  return { token: null, ticket: null };
}

function extractToken(req, options = {}) {
  return extractCredentials(req, options).token;
}

/**
 * Comprueba si la petición procede realmente de loopback local.
 * P0-1: Exige que TODOS los saltos de `X-Forwarded-For` y TODOS los parámetros
 * `for=` de `Forwarded` pertenezcan a `LOOPBACK`, impidiendo el spoofing del
 * primer salto detrás de Caddy/Nginx/Cloudflare.
 */
function isLoopback(req) {
  const peer = req.socket?.remoteAddress || '';
  if (peer && !LOOPBACK.has(peer)) return false;

  const xff = req.headers && req.headers['x-forwarded-for'];
  if (xff) {
    const hops = String(xff).split(',').map((s) => s.trim().replace(/^::ffff:/, '')).filter(Boolean);
    if (hops.length === 0 || hops.some((ip) => !LOOPBACK.has(ip))) return false;
  }

  const fwd = req.headers && req.headers.forwarded;
  if (fwd) {
    const matches = Array.from(String(fwd).matchAll(/for=(?:"?\[?)([^;\s,"\]]+)/gi));
    if (matches.length === 0) return false;
    if (matches.some((m) => !LOOPBACK.has(m[1].trim().replace(/^::ffff:/, '')))) return false;
  }

  if (peer) return true;
  const ip = (req.ip || '').replace(/^::ffff:/, '');
  return LOOPBACK.has(ip);
}

/** Rutas públicas (autenticadas por su propio mecanismo o consulta de estado/sesión). */
const PUBLIC_PATHS = new Set([
  '/health',
  '/api/health',
  '/api/auth/session',
  '/api/auth/verify',
  '/api/webhooks/github',
  '/api/webhooks/gitlab',
  '/api/webhooks/gitea',
  '/api/webhooks/bitbucket',
  '/api/ingress/ask'
]);
const DEPLOY_HOOK_PATH_RE = /^\/api\/webhooks\/deploy\/[a-zA-Z0-9_-]{1,80}$/;

function isPublicPath(reqPath) {
  return PUBLIC_PATHS.has(reqPath) || DEPLOY_HOOK_PATH_RE.test(reqPath);
}

/** Estadísticas actuales de bloqueos anti fuerza bruta (para health-summary). */
function getBruteForceStats() {
  const now = Date.now();
  let activeBlocks = 0;
  let trackedIps = 0;
  for (const entry of authFailMap.values()) {
    if (entry.resetAt > now) {
      trackedIps++;
      if (entry.count >= AUTH_FAIL_MAX) activeBlocks++;
    }
  }
  return { activeBlocks, trackedIps };
}

function checkAuthBruteForce(req) {
  if (authFailMap.size === 0) return NO_BRUTE_FORCE;
  const ip = clientIp(req);
  const now = Date.now();
  const entry = authFailMap.get(ip);
  if (entry && entry.resetAt > now && entry.count >= AUTH_FAIL_MAX) {
    const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    return { blocked: true, retryAfterSec };
  }
  return NO_BRUTE_FORCE;
}

function recordAuthFailure(req) {
  const ip = clientIp(req);
  const now = Date.now();
  let entry = authFailMap.get(ip);
  if (!entry || entry.resetAt <= now) {
    // Barrido de caducados antes de evicción LRU para que IPs muertas no expulsen bloqueos activos
    if (authFailMap.size >= AUTH_FAIL_MAP_CAP) {
      for (const [k, v] of authFailMap.entries()) {
        if (v.resetAt <= now) authFailMap.delete(k);
        if (authFailMap.size < AUTH_FAIL_MAP_CAP) break;
      }
      if (authFailMap.size >= AUTH_FAIL_MAP_CAP) {
        const oldestKey = authFailMap.keys().next().value;
        if (oldestKey) authFailMap.delete(oldestKey);
      }
    }
    entry = { count: 1, resetAt: now + AUTH_FAIL_WINDOW_MS };
  } else {
    entry.count++;
    // Refresca posición LRU
    authFailMap.delete(ip);
  }
  authFailMap.set(ip, entry);
}

function resetAuthRateLimit() {
  authFailMap.clear();
}

/**
 * Evaluación compartida para HTTP y WebSocket.
 * @param {any} req
 * @param {{ allowWsSubprotocol?: boolean }} [options]
 * @returns {{ ok: boolean, status?: number, error?: string, detail?: string, method?: string }}
 */
function authorizeRequest(req, options = {}) {
  const origin = req.headers.origin;
  if (origin && !isOriginAllowed(origin, req)) {
    return {
      ok: false,
      status: 403,
      error: 'Origen no permitido',
      detail: `El origen ${origin} no está autorizado a hablar con este daemon. Añádelo a CULKIBO_ALLOWED_ORIGINS si es tuyo.`
    };
  }

  const { token, ticket } = extractCredentials(req, options);
  if (ticket) {
    return consumeWsTicket(ticket, req) ? OK_WS_TICKET : ERR_INVALID_TICKET;
  }
  if (token) {
    return tokenMatches(token) ? OK_TOKEN : ERR_INVALID_TOKEN;
  }

  const requireToken = process.env.CULKIBO_REQUIRE_TOKEN === '1';
  if (!requireToken && isLoopback(req)) {
    // Defensa DNS Rebinding (MCP SDK CVE-2025-66414): si viene cabecera Host, debe apuntar a loopback.
    const hostName = extractHostHeaderName(req.headers && req.headers.host);
    if (hostName && !LOOPBACK.has(hostName)) {
      return ERR_AUTH_REQUIRED;
    }
    if (!origin) return OK_LOOPBACK;
    if (allowedOrigins().has(origin)) {
      return OK_LOOPBACK_ORIGIN;
    }
  }

  return ERR_AUTH_REQUIRED;
}

function authMiddleware(req, res, next) {
  const rawUrl = req.originalUrl || req.url || '';
  const qIdx = rawUrl.indexOf('?');
  const fullPath = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);

  // Validación de Origin incluso en rutas auth públicas (corta CSRF/cross-origin)
  if ((fullPath === '/api/auth/verify' || fullPath === '/api/auth/session') && req.headers.origin) {
    if (!isOriginAllowed(req.headers.origin, req)) {
      return res.status(403).json({
        error: 'Origen no permitido',
        detail: `El origen ${req.headers.origin} no está autorizado.`
      });
    }
  }

  if (isPublicPath(fullPath)) return next();

  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    return res.status(429).json({
      error: 'Demasiados intentos de autenticación fallidos. Espera un minuto antes de reintentar.'
    });
  }

  const decision = authorizeRequest(req, { allowWsSubprotocol: false });
  if (decision.ok) return next();

  const creds = extractCredentials(req, { allowWsSubprotocol: false });
  if (decision.status === 401 && (creds.token || creds.ticket)) {
    recordAuthFailure(req);
  }
  return res.status(decision.status || 401).json({
    error: decision.error,
    ...(decision.detail ? { detail: decision.detail } : {})
  });
}

/** Configuración de CORS derivada de la misma lista de orígenes (acepta req opcional). */
function corsOptions(req = null) {
  return {
    origin(origin, callback) {
      if (isOriginAllowed(origin, req)) return callback(null, true);
      callback(null, false);
    },
    credentials: false,
    allowedHeaders: [
      'Content-Type', 'Authorization', 'X-Culkibo-Token', 'X-Hub-Signature-256', 'X-Hub-Signature',
      'X-GitHub-Event', 'X-Gitlab-Token', 'X-Gitlab-Event', 'X-Gitea-Signature', 'X-Forgejo-Signature',
      'X-Deploy-Token', 'X-Backup-Filename',
      'MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name'
    ]
  };
}

/** Delegado CORS dinámico por petición para pasar `req` a `isOriginAllowed(origin, req)`. */
function corsDelegate(req, callback) {
  callback(null, corsOptions(req));
}

/** Resumen para el arranque y para /api/system/status. Nunca devuelve el token. */
function authStatus() {
  let tokenRotatedAt = null;
  try {
    if (!process.env.CULKIBO_TOKEN && fs.existsSync(AUTH_FILE)) {
      const stored = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
      tokenRotatedAt = stored.rotatedAt || stored.createdAt || null;
    }
  } catch (e) {}
  return {
    tokenConfigured: Boolean(cachedToken || process.env.CULKIBO_TOKEN || fs.existsSync(AUTH_FILE)),
    tokenSource: process.env.CULKIBO_TOKEN ? 'env' : 'data/auth.json',
    tokenRotatedAt,
    requireTokenAlways: process.env.CULKIBO_REQUIRE_TOKEN === '1',
    allowedOrigins: Array.from(allowedOrigins())
  };
}

module.exports = {
  authMiddleware,
  authorizeRequest,
  extractCredentials,
  corsOptions,
  corsDelegate,
  resolveToken,
  rotateToken,
  onTokenRotated,
  createWsTicket,
  consumeWsTicket,
  authStatus,
  isOriginAllowed,
  addAllowedOrigin,
  tokenMatches,
  isLoopback,
  isPrivateProxyPeer,
  clientIp,
  checkAuthBruteForce,
  recordAuthFailure,
  resetAuthRateLimit,
  getBruteForceStats
};
