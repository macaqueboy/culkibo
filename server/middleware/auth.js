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
  const clean = String(ip || '').replace(/^::ffff:/, '');
  if (LOOPBACK.has(clean)) return true;
  if (!TRUST_PROXY_UNIQUE_LOCAL) return false;
  if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
  const m = clean.match(/^172\.(\d+)\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
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

/** Rota el token maestro de forma atómica (si no viene fijado por variable de entorno). */
function rotateToken() {
  if (process.env.CULKIBO_TOKEN) {
    throw new Error('El token está fijado por la variable de entorno CULKIBO_TOKEN. Cámbiala y reinicia el servicio.');
  }
  const nextToken = crypto.randomBytes(32).toString('hex');
  atomicWriteJsonSync(AUTH_FILE, { token: nextToken, rotatedAt: new Date().toISOString() }, 0o600);
  cachedToken = nextToken;
  cachedTokenBuf = Buffer.from(nextToken, 'utf8');
  wsTickets.clear();
  return { token: nextToken, rotatedAt: new Date().toISOString(), tokenSource: 'data/auth.json' };
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
      const originHost = parsedOrigin.host.toLowerCase();
      const peerAddr = req.socket?.remoteAddress || '';
      const trustFwd = isPrivateProxyPeer(peerAddr);
      const rawHost = (trustFwd && req.headers['x-forwarded-host'])
        ? req.headers['x-forwarded-host']
        : req.headers.host;
      const reqHost = String(rawHost || '').split(',')[0].trim().toLowerCase();
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
  const peer = String(req?.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (isPrivateProxyPeer(peer) && req?.headers?.['x-forwarded-for']) {
    const hops = String(req.headers['x-forwarded-for']).split(',').map(s => s.trim()).filter(Boolean);
    if (hops.length > 0) return hops[hops.length - 1].replace(/^::ffff:/, '');
  }
  return peer || String(req?.ip || 'local').replace(/^::ffff:/, '');
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
  const ip = clientIp(req);
  if (entry.ip && ip && entry.ip !== ip && !LOOPBACK.has(entry.ip) && !LOOPBACK.has(ip)) {
    return false;
  }
  return true;
}

/**
 * Extrae token o ticket efímero de la petición (sin asignaciones innecesarias en /ws).
 * @returns {{ token: string | null, ticket: string | null }}
 */
function extractCredentials(req) {
  const header = req.headers.authorization;
  if (header && header.length > 7 && header.slice(0, 7).toLowerCase() === 'bearer ') {
    return { token: header.slice(7).trim(), ticket: null };
  }
  const xTok = req.headers['x-culkibo-token'];
  if (xTok) return { token: String(xTok).trim(), ticket: null };

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
  return { token: null, ticket: null };
}

function extractToken(req) {
  return extractCredentials(req).token;
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
  '/api/ingress/ask'
]);

function isPublicPath(reqPath) {
  return PUBLIC_PATHS.has(reqPath);
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
    // Evicción LRU acotada: un flood de IPs falsas jamás limpia bloqueos activos
    if (authFailMap.size >= AUTH_FAIL_MAP_CAP) {
      const oldestKey = authFailMap.keys().next().value;
      if (oldestKey) authFailMap.delete(oldestKey);
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
 * @returns {{ ok: boolean, status?: number, error?: string, detail?: string, method?: string }}
 */
function authorizeRequest(req) {
  const origin = req.headers.origin;
  if (origin && !isOriginAllowed(origin, req)) {
    return {
      ok: false,
      status: 403,
      error: 'Origen no permitido',
      detail: `El origen ${origin} no está autorizado a hablar con este daemon. Añádelo a CULKIBO_ALLOWED_ORIGINS si es tuyo.`
    };
  }

  const { token, ticket } = extractCredentials(req);
  if (ticket) {
    return consumeWsTicket(ticket, req) ? OK_WS_TICKET : ERR_INVALID_TICKET;
  }
  if (token) {
    return tokenMatches(token) ? OK_TOKEN : ERR_INVALID_TOKEN;
  }

  const requireToken = process.env.CULKIBO_REQUIRE_TOKEN === '1';
  if (!requireToken && isLoopback(req)) {
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

  const decision = authorizeRequest(req);
  if (decision.ok) return next();

  if (decision.status === 401 && extractToken(req)) {
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
      'Content-Type', 'Authorization', 'X-Culkibo-Token', 'X-Hub-Signature-256', 'X-GitHub-Event',
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
  return {
    tokenConfigured: Boolean(cachedToken || process.env.CULKIBO_TOKEN || fs.existsSync(AUTH_FILE)),
    tokenSource: process.env.CULKIBO_TOKEN ? 'env' : 'data/auth.json',
    requireTokenAlways: process.env.CULKIBO_REQUIRE_TOKEN === '1',
    allowedOrigins: Array.from(allowedOrigins())
  };
}

module.exports = {
  authMiddleware,
  authorizeRequest,
  corsOptions,
  corsDelegate,
  resolveToken,
  rotateToken,
  createWsTicket,
  consumeWsTicket,
  authStatus,
  isOriginAllowed,
  addAllowedOrigin,
  tokenMatches,
  isLoopback,
  isPrivateProxyPeer,
  checkAuthBruteForce,
  recordAuthFailure,
  resetAuthRateLimit
};
