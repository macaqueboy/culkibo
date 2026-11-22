const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AUTH_FILE = path.join(__dirname, '..', '..', 'data', 'auth.json');

/**
 * Autenticación del plano de control.
 *
 * El problema que resuelve: el daemon exponía toda su API con `cors('*')` y sin
 * credencial alguna. Dos consecuencias, y la segunda es la grave:
 *
 *  1. En un VPS, cualquiera que alcance el puerto controla tus despliegues.
 *  2. En tu propia máquina, CUALQUIER web que visites puede pedirle cosas a
 *     `localhost:3030` desde tu navegador. No hace falta que te expongas a
 *     internet: basta con abrir una pestaña.
 *
 * Por eso hay dos capas, y hacen falta las dos:
 *
 *  - **Origen**: una petición de navegador llega con cabecera `Origin`. Si no
 *    está en la lista permitida, se rechaza. Esto corta el caso 2, que no se
 *    arregla con un token — el navegador de la víctima lo enviaría igual si
 *    estuviera en una cookie, y aquí ni siquiera hace falta.
 *  - **Token**: para todo lo que no es navegador — CI, agentes MCP, curl. Corta
 *    el caso 1.
 *
 * Compatibilidad: desde loopback y sin cabecera `Origin` (curl local, los
 * tests, el CLI) se deja pasar sin token, salvo que se exija explícitamente con
 * CULKIBO_REQUIRE_TOKEN=1. Así instalar y probar en local sigue siendo
 * inmediato, y exponer el daemon sigue siendo seguro.
 */

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost']);

/** @type {string | null} */
let cachedToken = null;
/** @type {Buffer | null} */
let cachedTokenBuf = null;
/** @type {Set<string>} */
const dynamicOrigins = new Set();

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
    fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
    fs.writeFileSync(AUTH_FILE, JSON.stringify({ token: cachedToken, createdAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  } catch (e) {
    console.warn('[Auth] No se pudo guardar el token en disco; será distinto en cada arranque:', e.message);
  }
  return cachedToken;
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
    // Servidor de desarrollo de Vite
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
      const trustFwd = LOOPBACK.has(peerAddr);
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

function extractToken(req) {
  const header = req.headers.authorization || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  if (req.headers['x-culkibo-token']) return String(req.headers['x-culkibo-token']).trim();

  // Para upgrades de WebSocket desde el navegador (donde `new WebSocket()` no
  // permite cabeceras personalizadas): aceptamos subprotocolo `culkibo-token.<tok>`
  // o query `?token=` exclusivamente en peticiones Upgrade.
  if (req.headers.upgrade && String(req.headers.upgrade).toLowerCase() === 'websocket') {
    const proto = String(req.headers['sec-websocket-protocol'] || '');
    for (const part of proto.split(',').map(s => s.trim())) {
      if (part.startsWith('culkibo-token.')) return part.slice('culkibo-token.'.length).trim();
    }
    try {
      const parsed = new URL(req.url || '/', 'http://localhost');
      const qTok = parsed.searchParams.get('token');
      if (qTok) return qTok.trim();
    } catch (e) {}
  }
  return null;
}

/**
 * Comprueba si la petición procede realmente de loopback local.
 * Protege tanto HTTP como upgrades WebSocket crudos detrás de Caddy/Nginx:
 * si hay cabeceras `X-Forwarded-For` / `Forwarded`, el origen real debe ser
 * también loopback; de lo contrario se exige token obligatorio.
 */
function isLoopback(req) {
  const peer = req.socket?.remoteAddress || '';
  if (peer && !LOOPBACK.has(peer)) return false;

  const xff = req.headers && req.headers['x-forwarded-for'];
  if (xff) {
    const first = String(xff).split(',')[0].trim().replace(/^::ffff:/, '');
    return LOOPBACK.has(first);
  }

  const fwd = req.headers && req.headers.forwarded;
  if (fwd) {
    const m = String(fwd).match(/for=(?:"?\[?)([^;\s,"\]]+)/i);
    if (!m) return false;
    return LOOPBACK.has(m[1].replace(/^::ffff:/, ''));
  }

  if (peer) return true;
  const ip = (req.ip || '').replace(/^::ffff:/, '');
  return LOOPBACK.has(ip);
}

/**
 * Rutas que no pueden exigir token porque las llama un tercero que no lo tiene.
 * El webhook de GitHub se autentica por su propia firma HMAC, que ya se verifica.
 */
const PUBLIC_PATHS = new Set([
  '/health',
  '/api/health',
  '/api/auth/session',
  '/api/webhooks/github',
  '/api/ingress/ask'
]);

function isPublicPath(reqPath) {
  return PUBLIC_PATHS.has(reqPath);
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

  const provided = extractToken(req);
  if (provided) {
    if (tokenMatches(provided)) return { ok: true, method: 'token' };
    return { ok: false, status: 401, error: 'Token inválido' };
  }

  const requireToken = process.env.CULKIBO_REQUIRE_TOKEN === '1';
  if (!requireToken && isLoopback(req)) {
    // Sin cabecera Origin (curl local, CLI, tests) -> permitido en loopback.
    if (!origin) return { ok: true, method: 'loopback' };
    // Con cabecera Origin en loopback sin token: exigir lista blanca explícita
    // (evita DNS rebinding donde attacker.example resuelve a 127.0.0.1).
    if (allowedOrigins().has(origin)) {
      return { ok: true, method: 'loopback_origin' };
    }
  }

  return {
    ok: false,
    status: 401,
    error: 'Autenticación requerida',
    detail: 'Envía el token en la cabecera Authorization: Bearer <token>, o en X-Culkibo-Token. Lo encuentras en data/auth.json o en la variable CULKIBO_TOKEN.'
  };
}

function authMiddleware(req, res, next) {
  const fullPath = (req.originalUrl || req.url || '').split('?')[0];
  if (isPublicPath(fullPath)) return next();

  const decision = authorizeRequest(req);
  if (decision.ok) return next();
  return res.status(decision.status || 401).json({
    error: decision.error,
    ...(decision.detail ? { detail: decision.detail } : {})
  });
}

/** Configuración de CORS derivada de la misma lista de orígenes. */
function corsOptions() {
  return {
    origin(origin, callback) {
      if (isOriginAllowed(origin)) return callback(null, true);
      callback(null, false);
    },
    credentials: false,
    allowedHeaders: [
      'Content-Type', 'Authorization', 'X-Culkibo-Token', 'X-Hub-Signature-256', 'X-GitHub-Event',
      'MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name'
    ]
  };
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
  resolveToken,
  authStatus,
  isOriginAllowed,
  addAllowedOrigin,
  tokenMatches,
  isLoopback
};
