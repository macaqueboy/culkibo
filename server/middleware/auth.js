const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { atomicWriteJsonSync } = require('../services/ssrfGuard');

const AUTH_FILE = path.join(__dirname, '..', '..', 'data', 'auth.json');

function resolveTeamsFile() {
  const dir = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.join(__dirname, '..', '..', 'data');
  return path.join(dir, 'teams.json');
}

/**
 * Autenticación y RBAC del plano de control.
 *
 * Capas obligatorias:
 *  - Origen: corta peticiones cross-origin desde pestañas maliciosas.
 *  - Token / Sesión / API Token: protege cualquier acceso remoto (VPS, proxy, CI, MCP).
 *  - RBAC multi-tenant: carga perezosa de `teamManager` SOLO cuando se presenta un
 *    token/cookie `cks_` o `ckp_` (0 sobrecoste de arranque y RAM en modo clásico).
 *
 * Incluye:
 *  - Verificación de TODOS los saltos en X-Forwarded-For / Forwarded (corta spoofing leftmost).
 *  - Protección anti fuerza bruta integrada en el propio authMiddleware (LRU acotado).
 *  - Tickets WebSocket efímeros de un solo uso (30 s) ligados al principal + revalidación.
 *  - Middlewares Express `requirePerm` / `requireRole` (default-deny con `return` inmediato).
 */

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost']);

const SESSION_COOKIE_NAME = 'culkibo_session';
const HOST_SESSION_COOKIE_NAME = '__Host-culkibo_session';

const ROLE_RANKS = Object.freeze({
  viewer: 10,
  developer: 20,
  admin: 30,
  owner: 40
});

const SUPERADMIN_MASTER = Object.freeze({
  isSuperAdmin: true,
  kind: 'master',
  userId: null,
  email: null,
  name: 'Master Token',
  role: 'owner',
  teamId: 'team_default',
  sessionId: null,
  tokenId: null,
  projectIds: null,
  scopes: Object.freeze(['*'])
});

const SUPERADMIN_LOOPBACK = Object.freeze({
  isSuperAdmin: true,
  kind: 'loopback',
  userId: null,
  email: null,
  name: 'Local Loopback',
  role: 'owner',
  teamId: 'team_default',
  sessionId: null,
  tokenId: null,
  projectIds: null,
  scopes: Object.freeze(['*'])
});

/** @type {string | null} */
let cachedToken = null;
/** @type {Buffer | null} */
let cachedTokenBuf = null;
/** @type {Set<string>} */
const dynamicOrigins = new Set();

// Carga perezosa de teamManager (cero overhead/RAM cuando no hay tokens cks_/ckp_)
/** @type {any} */
let _teamManager = null;
/** @type {(() => void) | null} */
let _teamManagerRevokedUnsub = null;
/** @type {any} */
let _testTeamManagerOverride = null;

/** @type {Set<(evt: any) => void>} */
const principalRevokedListeners = new Set();

/** @param {any} evt */
function emitPrincipalRevoked(evt) {
  for (const fn of principalRevokedListeners) {
    try { fn(evt); } catch (e) {}
  }
}

/**
 * Permite suscribirse a revocaciones de sesión/token/rol (para cortar WS/SSE con 4001).
 * @param {(evt: { userId?: string | null, sessionId?: string | null, tokenId?: string | null, teamId?: string | null, masterToken?: boolean, reason?: string }) => void} listener
 */
function onPrincipalRevoked(listener) {
  if (typeof listener === 'function') principalRevokedListeners.add(listener);
  return () => principalRevokedListeners.delete(listener);
}

/**
 * Carga `teamManager` bajo demanda y conecta sus eventos `principal_revoked`.
 * @param {any} [override]
 */
function getTeamManager(override = null) {
  if (override) return override;
  if (_testTeamManagerOverride) return _testTeamManagerOverride;
  if (!_teamManager) {
    _teamManager = require('../services/teamManager');
    if (_teamManager && typeof _teamManager.onPrincipalRevoked === 'function') {
      _teamManagerRevokedUnsub = _teamManager.onPrincipalRevoked((evt) => emitPrincipalRevoked(evt));
    }
  }
  return _teamManager;
}

/**
 * Inyección exclusiva para suites unitarias aisladas (sin tocar `data/teams.json`).
 * @param {any} mgr
 */
function _setTeamManagerForTest(mgr) {
  if (_teamManagerRevokedUnsub && _testTeamManagerOverride) {
    try { _teamManagerRevokedUnsub(); } catch (e) {}
    _teamManagerRevokedUnsub = null;
  }
  _testTeamManagerOverride = mgr || null;
  if (_testTeamManagerOverride && typeof _testTeamManagerOverride.onPrincipalRevoked === 'function') {
    _teamManagerRevokedUnsub = _testTeamManagerOverride.onPrincipalRevoked((evt) => emitPrincipalRevoked(evt));
  }
}

// Tickets WebSocket de un solo uso (30 s TTL, acotados a 200 entradas, con principal ligado)
/** @type {Map<string, { expiresAt: number, ip: string, principal: any }>} */
const wsTickets = new Map();
const WS_TICKET_TTL_MS = 30000;

// Rate-limiter global de fallos de autenticación (LRU acotado, nunca clear() masivo)
/** @type {Map<string, { count: number, resetAt: number }>} */
const authFailMap = new Map();
const AUTH_FAIL_WINDOW_MS = 60000;
const AUTH_FAIL_MAX = 20;
const AUTH_FAIL_MAP_CAP = 2000;
const NO_BRUTE_FORCE = Object.freeze({ blocked: false, retryAfterSec: 0 });
const OK_LOOPBACK = Object.freeze({ ok: true, method: 'loopback', principal: SUPERADMIN_LOOPBACK });
const OK_LOOPBACK_ORIGIN = Object.freeze({ ok: true, method: 'loopback_origin', principal: SUPERADMIN_LOOPBACK });
const OK_TOKEN = Object.freeze({ ok: true, method: 'token', principal: SUPERADMIN_MASTER });
const OK_WS_TICKET = Object.freeze({ ok: true, method: 'ws_ticket', principal: SUPERADMIN_LOOPBACK });
const ERR_INVALID_TOKEN = Object.freeze({ ok: false, status: 401, error: 'Token inválido' });
const ERR_INVALID_TICKET = Object.freeze({ ok: false, status: 401, error: 'Ticket WebSocket inválido o caducado' });
const ERR_COOKIE_CSRF = Object.freeze({
  ok: false,
  status: 403,
  error: 'Protección CSRF: las mutaciones con cookie requieren cabecera Origin permitida o Sec-Fetch-Site: same-origin'
});
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

/**
 * Parsea la cabecera `Cookie` de forma acotada sin dependencias externas.
 * @param {string | undefined} rawCookie
 * @returns {Record<string, string>}
 */
function parseCookies(rawCookie) {
  /** @type {Record<string, string>} */
  const out = Object.create(null);
  if (!rawCookie || typeof rawCookie !== 'string') return out;
  const trimmed = rawCookie.length > 4096 ? rawCookie.slice(0, 4096) : rawCookie;
  const parts = trimmed.split(';');
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i].trim();
    if (!seg) continue;
    const eq = seg.indexOf('=');
    if (eq <= 0) continue;
    const k = seg.slice(0, eq).trim();
    if (!k || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const v = seg.slice(eq + 1).trim();
    try {
      out[k] = v.includes('%') ? decodeURIComponent(v) : v;
    } catch (e) {
      out[k] = v;
    }
  }
  return out;
}

/** Detecta si la petición llega por HTTPS directo o tras proxy privado de confianza. */
function isHttpsRequest(req) {
  if (!req) return false;
  if (req.socket && req.socket.encrypted) return true;
  const peer = req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : '';
  if (isPrivateProxyPeer(peer) && req.headers && req.headers['x-forwarded-proto']) {
    const protos = String(req.headers['x-forwarded-proto']).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    if (protos.length > 0 && protos[protos.length - 1] === 'https') return true;
  }
  return false;
}

/**
 * Construye el encabezado `Set-Cookie` HttpOnly + SameSite=Strict para sesiones `cks_`.
 * @param {string} sessionToken
 * @param {any} [req]
 * @param {{ maxAgeSec?: number }} [opts]
 */
function formatSessionCookie(sessionToken, req = null, opts = {}) {
  const secure = isHttpsRequest(req);
  const name = secure ? HOST_SESSION_COOKIE_NAME : SESSION_COOKIE_NAME;
  const maxAge = Math.max(60, Math.floor(Number(opts.maxAgeSec) || 24 * 3600));
  const attrs = [
    `${name}=${sessionToken}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAge}`
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

/** Construye encabezados `Set-Cookie` para borrar la cookie de sesión en logout. */
function formatClearSessionCookie(req = null) {
  const cookies = [`${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`];
  if (isHttpsRequest(req)) {
    cookies.push(`${HOST_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0`);
  }
  return cookies;
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
  emitPrincipalRevoked({ masterToken: true, reason: 'master_token_rotated', at: rotatedAt });
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

/** Emite un ticket WebSocket efímero (30 s, un solo uso) ligado a la IP y al principal del cliente. */
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
  const principal = (req && req.auth && req.auth.principal) ? req.auth.principal : SUPERADMIN_LOOPBACK;
  wsTickets.set(ticket, { expiresAt: now + WS_TICKET_TTL_MS, ip: clientIp(req), principal });
  return { ticket, expiresInMs: WS_TICKET_TTL_MS };
}

/**
 * Consume un ticket WS efímero y revalida que el principal asociado siga activo (no revocado).
 * @param {string} ticket
 * @param {any} [req]
 * @param {any} [teamManagerOverride]
 * @returns {{ ok: boolean, principal: any }}
 */
function consumeWsTicketWithPrincipal(ticket, req = null, teamManagerOverride = null) {
  if (!ticket) return { ok: false, principal: null };
  const entry = wsTickets.get(ticket);
  if (!entry) return { ok: false, principal: null };
  wsTickets.delete(ticket);
  if (entry.expiresAt < Date.now()) return { ok: false, principal: null };
  if (req) {
    const ip = clientIp(req);
    if (entry.ip && ip && entry.ip !== ip && !(LOOPBACK.has(entry.ip) && LOOPBACK.has(ip))) {
      return { ok: false, principal: null };
    }
  }
  const principal = entry.principal || SUPERADMIN_LOOPBACK;
  if (!principal.isSuperAdmin) {
    const tm = getTeamManager(teamManagerOverride);
    if (!tm || !tm.isPrincipalStillValid(principal)) {
      return { ok: false, principal: null };
    }
  }
  return { ok: true, principal };
}

/** Consume un ticket WebSocket efímero (un solo uso, devuelve booleano por compatibilidad). */
function consumeWsTicket(ticket, req) {
  return consumeWsTicketWithPrincipal(ticket, req).ok;
}

/**
 * Extrae token, cookie de sesión o ticket efímero de la petición.
 * - `Sec-WebSocket-Protocol` SOLO se lee cuando `allowWsSubprotocol: true` (upgrade WS).
 * - Las cookies `culkibo_session` / `__Host-culkibo_session` NUNCA se leen en upgrades WS.
 * - NUNCA se leen credenciales desde query strings (`?token=`).
 *
 * @param {any} req
 * @param {{ allowWsSubprotocol?: boolean }} [options]
 * @returns {{ token: string | null, ticket: string | null, cookieToken: string | null }}
 */
function extractCredentials(req, options = {}) {
  const headers = (req && req.headers) || {};
  const header = headers.authorization;
  if (header && header.length > 7 && header.slice(0, 7).toLowerCase() === 'bearer ') {
    return { token: header.slice(7).trim(), ticket: null, cookieToken: null };
  }
  const xTok = headers['x-culkibo-token'];
  if (xTok) return { token: String(xTok).trim(), ticket: null, cookieToken: null };

  if (options && options.allowWsSubprotocol) {
    const upgrade = headers.upgrade;
    if (upgrade && String(upgrade).toLowerCase() === 'websocket') {
      const proto = headers['sec-websocket-protocol'];
      if (proto) {
        const parts = String(proto).split(',');
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i].trim();
          if (part.startsWith('culkibo-ticket.')) {
            return { token: null, ticket: part.slice('culkibo-ticket.'.length).trim(), cookieToken: null };
          }
          if (part.startsWith('culkibo-token.')) {
            return { token: part.slice('culkibo-token.'.length).trim(), ticket: null, cookieToken: null };
          }
        }
      }
    }
    // Jamás autenticar upgrades WS con cookies (mitiga CSWSH / CVE-2026-134804)
    return { token: null, ticket: null, cookieToken: null };
  }

  // Cookie HttpOnly solo en peticiones HTTP normales (nunca en WS upgrade)
  if (headers.cookie) {
    const cookies = parseCookies(headers.cookie);
    const rawCookie = cookies[HOST_SESSION_COOKIE_NAME] || cookies[SESSION_COOKIE_NAME] || null;
    if (rawCookie && rawCookie.startsWith('cks_')) {
      return { token: null, ticket: null, cookieToken: rawCookie };
    }
  }

  return { token: null, ticket: null, cookieToken: null };
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

/**
 * Verifica si una petición está autorizada a ejecutar el bootstrap inicial (`POST /api/auth/bootstrap`).
 * Exige loopback local (con Host loopback) O token maestro `CULKIBO_TOKEN` válido.
 * @param {any} req
 */
function canBootstrapRequest(req) {
  if (!req) return false;
  const origin = req.headers && req.headers.origin;
  if (origin && !isOriginAllowed(origin, req)) return false;
  const { token } = extractCredentials(req, { allowWsSubprotocol: false });
  if (token && tokenMatches(token)) return true;
  if (isLoopback(req)) {
    const hostName = extractHostHeaderName(req.headers && req.headers.host);
    if (hostName && !LOOPBACK.has(hostName)) return false;
    if (!origin || allowedOrigins().has(origin)) return true;
  }
  return false;
}

/** Rutas públicas (autenticadas por su propio mecanismo o consulta de estado/sesión). */
const PUBLIC_PATHS = new Set([
  '/health',
  '/api/health',
  '/api/auth/session',
  '/api/auth/verify',
  '/api/auth/login',
  '/api/auth/bootstrap',
  '/api/auth/invites/accept',
  '/api/webhooks/github',
  '/api/webhooks/gitlab',
  '/api/webhooks/gitea',
  '/api/webhooks/bitbucket',
  '/api/ingress/ask'
]);
const ORIGIN_GUARDED_PUBLIC_AUTH_PATHS = new Set([
  '/api/auth/verify',
  '/api/auth/session',
  '/api/auth/login',
  '/api/auth/bootstrap',
  '/api/auth/invites/accept'
]);
const BRUTE_FORCE_PUBLIC_AUTH_PATHS = new Set([
  '/api/auth/login',
  '/api/auth/bootstrap',
  '/api/auth/invites/accept'
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
 * Comprueba si `enforceOnLoopback` está activado SIN cargar `teamManager` si no existe `data/teams.json`.
 * @param {any} [teamManagerOverride]
 */
function isLoopbackAuthEnforced(teamManagerOverride = null) {
  if (teamManagerOverride) return Boolean(teamManagerOverride.isEnforceOnLoopback());
  if (_testTeamManagerOverride) return Boolean(_testTeamManagerOverride.isEnforceOnLoopback());
  if (_teamManager) return Boolean(_teamManager.isEnforceOnLoopback());
  if (!fs.existsSync(resolveTeamsFile())) return false;
  return Boolean(getTeamManager().isEnforceOnLoopback());
}

/**
 * Evaluación compartida para HTTP y WebSocket.
 * @param {any} req
 * @param {{ allowWsSubprotocol?: boolean, teamManager?: any }} [options]
 * @returns {{ ok: boolean, status?: number, error?: string, detail?: string, method?: string, principal?: any }}
 */
function authorizeRequest(req, options = {}) {
  const origin = req && req.headers ? req.headers.origin : undefined;
  if (origin && !isOriginAllowed(origin, req)) {
    return {
      ok: false,
      status: 403,
      error: 'Origen no permitido',
      detail: `El origen ${origin} no está autorizado a hablar con este daemon. Añádelo a CULKIBO_ALLOWED_ORIGINS si es tuyo.`
    };
  }

  const { token, ticket, cookieToken } = extractCredentials(req, options);
  if (ticket) {
    const consumed = consumeWsTicketWithPrincipal(ticket, req, options.teamManager);
    if (!consumed.ok) return ERR_INVALID_TICKET;
    if (consumed.principal === SUPERADMIN_LOOPBACK) return OK_WS_TICKET;
    return { ok: true, method: 'ws_ticket', principal: consumed.principal };
  }

  if (token) {
    // 1. Token maestro primero: cero overhead y 100% compatibilidad clásica
    if (tokenMatches(token)) return OK_TOKEN;

    // 2. Carga perezosa de teamManager SOLO para tokens `cks_` (sesión) o `ckp_` (API/MCP)
    if (token.startsWith('cks_')) {
      const tm = getTeamManager(options.teamManager);
      const verified = tm.verifySessionToken(token);
      if (verified && verified.ok && verified.principal) {
        return { ok: true, method: 'session', principal: verified.principal };
      }
      return ERR_INVALID_TOKEN;
    }
    if (token.startsWith('ckp_')) {
      const tm = getTeamManager(options.teamManager);
      const verified = tm.verifyApiToken(token, { ip: clientIp(req) });
      if (verified && verified.ok && verified.principal) {
        return { ok: true, method: 'api_token', principal: verified.principal };
      }
      return ERR_INVALID_TOKEN;
    }

    return ERR_INVALID_TOKEN;
  }

  // 3. Sesión por cookie HttpOnly (`culkibo_session` / `__Host-culkibo_session`, jamás en WS)
  if (cookieToken && !options.allowWsSubprotocol) {
    const method = String((req && req.method) || 'GET').toUpperCase();
    const isMutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    if (isMutating) {
      // Exige Origin exacto verificado O Sec-Fetch-Site: same-origin (subdominios hermanos evaden SameSite=Strict)
      const secFetchSite = String((req && req.headers && req.headers['sec-fetch-site']) || '').trim().toLowerCase();
      const hasValidOrigin = Boolean(origin) && isOriginAllowed(origin, req);
      const isSameOriginFetch = secFetchSite === 'same-origin';
      if (!hasValidOrigin && !isSameOriginFetch) {
        return ERR_COOKIE_CSRF;
      }
    }
    const tm = getTeamManager(options.teamManager);
    const verified = tm.verifySessionToken(cookieToken);
    if (verified && verified.ok && verified.principal) {
      return { ok: true, method: 'session_cookie', principal: verified.principal };
    }
    return ERR_INVALID_TOKEN;
  }

  const requireToken = process.env.CULKIBO_REQUIRE_TOKEN === '1';
  if (!requireToken && !isLoopbackAuthEnforced(options.teamManager) && isLoopback(req)) {
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
  if (ORIGIN_GUARDED_PUBLIC_AUTH_PATHS.has(fullPath) && req.headers && req.headers.origin) {
    if (!isOriginAllowed(req.headers.origin, req)) {
      return res.status(403).json({
        error: 'Origen no permitido',
        detail: `El origen ${req.headers.origin} no está autorizado.`
      });
    }
  }

  if (BRUTE_FORCE_PUBLIC_AUTH_PATHS.has(fullPath)) {
    const bfPub = checkAuthBruteForce(req);
    if (bfPub.blocked) {
      res.setHeader('Retry-After', String(bfPub.retryAfterSec));
      return res.status(429).json({
        error: 'Demasiados intentos de autenticación fallidos. Espera un minuto antes de reintentar.'
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
  if (decision.ok) {
    req.auth = {
      method: decision.method,
      principal: decision.principal || SUPERADMIN_LOOPBACK
    };
    return next();
  }

  const creds = extractCredentials(req, { allowWsSubprotocol: false });
  if (decision.status === 401 && (creds.token || creds.ticket || creds.cookieToken)) {
    recordAuthFailure(req);
  }
  return res.status(decision.status || 401).json({
    error: decision.error,
    ...(decision.detail ? { detail: decision.detail } : {})
  });
}

/**
 * Middleware Express RBAC por permiso (default-deny, siempre hace `return res.status(...)`).
 * @param {string} perm
 * @param {{
 *   projectParam?: string,
 *   teamParam?: string,
 *   getProjectId?: (req: any) => string | null,
 *   getProject?: (req: any) => any,
 *   getTeamId?: (req: any) => string | undefined,
 *   teamManager?: any
 * }} [opts]
 */
function requirePerm(perm, opts = {}) {
  return function rbacPermMiddleware(req, res, next) {
    const authCtx = req && req.auth;
    const principal = authCtx && authCtx.principal ? authCtx.principal : null;
    if (!principal) {
      return res.status(401).json({ error: 'Autenticación requerida', code: 'UNAUTHENTICATED' });
    }
    if (!perm || typeof perm !== 'string') {
      return res.status(403).json({ error: 'Permiso RBAC no especificado', code: 'FORBIDDEN' });
    }
    if (principal.isSuperAdmin) {
      return next();
    }

    const tm = getTeamManager(opts && opts.teamManager);
    const projectId = (opts && typeof opts.getProjectId === 'function')
      ? opts.getProjectId(req)
      : (opts && opts.projectParam && req.params ? req.params[opts.projectParam] : null);
    const projectObj = (opts && typeof opts.getProject === 'function') ? opts.getProject(req) : null;
    const teamId = (opts && typeof opts.getTeamId === 'function')
      ? opts.getTeamId(req)
      : (opts && opts.teamParam && req.params ? req.params[opts.teamParam] : undefined);

    const check = projectId
      ? tm.authorizeProject(principal, projectId, perm, projectObj)
      : tm.authorizeAction(principal, perm, { teamId });

    if (!check || !check.allowed) {
      const status = (check && check.status) || 403;
      const msg = status === 404
        ? 'Recurso no encontrado'
        : status === 401
          ? 'Sesión o token revocado o inválido'
          : `Permiso denegado (${perm})`;
      return res.status(status).json({ error: msg, code: (check && check.reason) || 'FORBIDDEN' });
    }

    return next();
  };
}

/**
 * Middleware Express RBAC por rol mínimo (`owner(40) > admin(30) > developer(20) > viewer(10)`).
 * Default-deny ante roles desconocidos; siempre retorna en error (`return res.status(...)`).
 * @param {'viewer' | 'developer' | 'admin' | 'owner'} minRole
 * @param {{ teamParam?: string, getTeamId?: (req: any) => string | undefined, teamManager?: any }} [opts]
 */
function requireRole(minRole, opts = {}) {
  const needed = Object.prototype.hasOwnProperty.call(ROLE_RANKS, minRole) ? ROLE_RANKS[minRole] : 999;
  return function rbacRoleMiddleware(req, res, next) {
    const authCtx = req && req.auth;
    const principal = authCtx && authCtx.principal ? authCtx.principal : null;
    if (!principal) {
      return res.status(401).json({ error: 'Autenticación requerida', code: 'UNAUTHENTICATED' });
    }
    if (needed === 999) {
      return res.status(403).json({ error: 'Rol RBAC desconocido', code: 'UNKNOWN_ROLE' });
    }
    if (principal.isSuperAdmin) {
      return next();
    }

    const tm = getTeamManager(opts && opts.teamManager);
    const targetTeamId = (opts && typeof opts.getTeamId === 'function')
      ? opts.getTeamId(req)
      : (opts && opts.teamParam && req.params ? req.params[opts.teamParam] : principal.teamId);

    const check = tm.doesPrincipalSatisfyRole(principal, minRole, targetTeamId);
    if (!check || !check.allowed) {
      const status = (check && check.status) || 403;
      const msg = status === 404
        ? 'Recurso no encontrado'
        : status === 401
          ? 'Sesión o token revocado o inválido'
          : `Rol insuficiente (requiere ${minRole})`;
      return res.status(status).json({ error: msg, code: (check && check.reason) || 'INSUFFICIENT_ROLE' });
    }

    return next();
  };
}

/**
 * Atajo de middleware por permiso sobre un proyecto (`req.params[paramName]`).
 * @param {string} perm
 * @param {string} [paramName]
 * @param {any} [opts]
 */
function requireProjectPerm(perm, paramName = 'id', opts = {}) {
  return requirePerm(perm, { ...opts, projectParam: paramName });
}

/**
 * Middleware catch-all default-deny para `/api/*` cuando el principal no es superadmin.
 * @param {{ teamManager?: any }} [opts]
 */
function requireRouteRbac(opts = {}) {
  return function rbacRouteGuardMiddleware(req, res, next) {
    const authCtx = req && req.auth;
    const principal = authCtx && authCtx.principal ? authCtx.principal : null;
    if (!principal) {
      return res.status(401).json({ error: 'Autenticación requerida', code: 'UNAUTHENTICATED' });
    }
    if (principal.isSuperAdmin) {
      return next();
    }
    const rawUrl = req.originalUrl || req.url || '/';
    const qIdx = rawUrl.indexOf('?');
    const fullPath = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
    const tm = getTeamManager(opts && opts.teamManager);
    const decision = tm.authorizeHttpRoute(principal, req.method || 'GET', fullPath);
    if (!decision || !decision.allowed) {
      const status = (decision && decision.status) || 403;
      return res.status(status).json({
        error: status === 401 ? 'Sesión o token revocado o inválido' : 'Acceso denegado por política RBAC',
        code: (decision && decision.reason) || 'FORBIDDEN'
      });
    }
    return next();
  };
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
      'Content-Type', 'Authorization', 'X-Culkibo-Token', 'X-Culkibo-CSRF',
      'X-Hub-Signature-256', 'X-Hub-Signature',
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

/** Resumen para el arranque y para /api/system/status. Nunca devuelve el token ni secretos. */
function authStatus() {
  let tokenRotatedAt = null;
  try {
    if (!process.env.CULKIBO_TOKEN && fs.existsSync(AUTH_FILE)) {
      const stored = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
      tokenRotatedAt = stored.rotatedAt || stored.createdAt || null;
    }
  } catch (e) {}

  let multiUserEnabled = false;
  let usersCount = 0;
  let teamsCount = 0;
  if (_testTeamManagerOverride || _teamManager || fs.existsSync(resolveTeamsFile())) {
    try {
      const summary = getTeamManager().getStatusSummary();
      multiUserEnabled = Boolean(summary.multiUserEnabled);
      usersCount = Number(summary.usersCount) || 0;
      teamsCount = Number(summary.teamsCount) || 0;
    } catch (e) {}
  }

  return {
    tokenConfigured: Boolean(cachedToken || process.env.CULKIBO_TOKEN || fs.existsSync(AUTH_FILE)),
    tokenSource: process.env.CULKIBO_TOKEN ? 'env' : 'data/auth.json',
    tokenRotatedAt,
    requireTokenAlways: process.env.CULKIBO_REQUIRE_TOKEN === '1',
    allowedOrigins: Array.from(allowedOrigins()),
    multiUserEnabled,
    usersCount,
    teamsCount
  };
}

module.exports = {
  authMiddleware,
  authorizeRequest,
  extractCredentials,
  extractToken,
  corsOptions,
  corsDelegate,
  resolveToken,
  rotateToken,
  onTokenRotated,
  onPrincipalRevoked,
  createWsTicket,
  consumeWsTicket,
  consumeWsTicketWithPrincipal,
  authStatus,
  isOriginAllowed,
  addAllowedOrigin,
  tokenMatches,
  isLoopback,
  isPrivateProxyPeer,
  canBootstrapRequest,
  clientIp,
  checkAuthBruteForce,
  recordAuthFailure,
  resetAuthRateLimit,
  getBruteForceStats,
  requirePerm,
  requirePermission: requirePerm,
  requireRole,
  requireProjectPerm,
  requireRouteRbac,
  parseCookies,
  isHttpsRequest,
  formatSessionCookie,
  formatClearSessionCookie,
  SESSION_COOKIE_NAME,
  HOST_SESSION_COOKIE_NAME,
  SUPERADMIN_MASTER,
  SUPERADMIN_LOOPBACK,
  _setTeamManagerForTest
};
