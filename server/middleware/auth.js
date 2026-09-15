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

let cachedToken = null;

/** Token activo. Se genera y persiste la primera vez si no hay ninguno. */
function resolveToken() {
  if (cachedToken) return cachedToken;

  if (process.env.CULKIBO_TOKEN) {
    cachedToken = process.env.CULKIBO_TOKEN;
    return cachedToken;
  }

  try {
    if (fs.existsSync(AUTH_FILE)) {
      const stored = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
      if (stored.token) {
        cachedToken = stored.token;
        return cachedToken;
      }
    }
  } catch (e) {}

  cachedToken = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
    fs.writeFileSync(AUTH_FILE, JSON.stringify({ token: cachedToken, createdAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  } catch (e) {
    console.warn('[Auth] No se pudo guardar el token en disco; será distinto en cada arranque:', e.message);
  }
  return cachedToken;
}

/** Orígenes de navegador permitidos. */
function allowedOrigins() {
  const port = process.env.PORT || 3030;
  const configured = (process.env.CULKIBO_ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  return new Set([
    ...configured,
    `http://localhost:${port}`,
    `http://127.0.0.1:${port}`,
    // Servidor de desarrollo de Vite
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  ]);
}

function isOriginAllowed(origin) {
  if (!origin) return true; // no es una petición de navegador
  return allowedOrigins().has(origin);
}

/** Comparación en tiempo constante: una comparación normal filtra el token. */
function tokenMatches(provided) {
  if (!provided) return false;
  const expected = resolveToken();
  const a = Buffer.from(String(provided));
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

function extractToken(req) {
  const header = req.headers.authorization || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  if (req.headers['x-culkibo-token']) return String(req.headers['x-culkibo-token']).trim();
  return null;
}

function isLoopback(req) {
  const ip = (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  return LOOPBACK.has(ip) || LOOPBACK.has(req.ip);
}

/**
 * Rutas que no pueden exigir token porque las llama un tercero que no lo tiene.
 * El webhook de GitHub se autentica por su propia firma HMAC, que ya se verifica.
 */
const PUBLIC_PATHS = [
  /^\/health$/,
  /^\/api\/health$/,
  /^\/api\/webhooks\/github$/
];

function isPublicPath(reqPath) {
  return PUBLIC_PATHS.some(re => re.test(reqPath));
}

function authMiddleware(req, res, next) {
  // El middleware se monta en '/api', así que req.path viene recortado
  // ('/health' en lugar de '/api/health'). Se compara siempre contra la ruta
  // completa para que las exenciones no dependan de dónde esté montado.
  const fullPath = (req.originalUrl || req.url || '').split('?')[0];
  if (isPublicPath(fullPath)) return next();

  const origin = req.headers.origin;
  if (origin && !isOriginAllowed(origin)) {
    return res.status(403).json({
      error: 'Origen no permitido',
      detail: `El origen ${origin} no está autorizado a hablar con este daemon. Añádelo a CULKIBO_ALLOWED_ORIGINS si es tuyo.`
    });
  }

  const provided = extractToken(req);
  if (provided) {
    if (tokenMatches(provided)) return next();
    return res.status(401).json({ error: 'Token inválido' });
  }

  const requireToken = process.env.CULKIBO_REQUIRE_TOKEN === '1';
  if (!requireToken && isLoopback(req) && !origin) {
    // Acceso local sin navegador: CLI, tests, curl. Cómodo y no alcanzable
    // desde una página web.
    return next();
  }

  if (!requireToken && isLoopback(req) && origin && isOriginAllowed(origin)) {
    // El propio dashboard servido en localhost.
    return next();
  }

  return res.status(401).json({
    error: 'Autenticación requerida',
    detail: 'Envía el token en la cabecera Authorization: Bearer <token>, o en X-Culkibo-Token. Lo encuentras en data/auth.json o en la variable CULKIBO_TOKEN.'
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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Culkibo-Token', 'X-Hub-Signature-256', 'X-GitHub-Event']
  };
}

/** Resumen para el arranque y para /api/system/status. Nunca devuelve el token. */
function authStatus() {
  return {
    tokenConfigured: Boolean(process.env.CULKIBO_TOKEN || fs.existsSync(AUTH_FILE)),
    tokenSource: process.env.CULKIBO_TOKEN ? 'env' : 'data/auth.json',
    requireTokenAlways: process.env.CULKIBO_REQUIRE_TOKEN === '1',
    allowedOrigins: Array.from(allowedOrigins())
  };
}

module.exports = { authMiddleware, corsOptions, resolveToken, authStatus, isOriginAllowed, tokenMatches };
