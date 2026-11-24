/**
 * Limitador de tasa LRU compartido en memoria (cero dependencias externas).
 *
 * Usado de forma coherente tanto por el fast-path nativo (`server/index.js`)
 * como por Express (`server/routes/api.js`), respetando proxies de confianza y
 * evitando que el spoofing de cabeceras `X-Forwarded-For` o `Forwarded` evite
 * los límites de abuso.
 */

const { isPrivateProxyPeer, isLoopback } = require('../middleware/auth');

/**
 * Extrae la IP efectiva del cliente considerando X-Forwarded-For y Forwarded
 * únicamente cuando el peer inmediato es un proxy de confianza.
 * @param {any} req
 * @returns {string}
 */
function resolveRateLimitIp(req) {
  const peer = String(req?.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (isPrivateProxyPeer(peer)) {
    const xff = req?.headers?.['x-forwarded-for'];
    if (xff) {
      const hops = String(xff).split(',').map((s) => s.trim().replace(/^::ffff:/, '')).filter(Boolean);
      if (hops.length > 0) return hops[hops.length - 1];
    }
    const fwd = req?.headers?.forwarded;
    if (fwd) {
      const matches = Array.from(String(fwd).matchAll(/for=(?:"?\[?)([^;\s,"\]]+)/gi));
      if (matches.length > 0) return matches[matches.length - 1][1].trim().replace(/^::ffff:/, '');
    }
  }
  return peer || String(req?.ip || 'local').replace(/^::ffff:/, '');
}

/**
 * Crea un comprobador de límite de tasa en ventana fija con evicción LRU.
 * @param {{
 *   windowMs?: number,
 *   max?: number,
 *   bypassLoopback?: boolean,
 *   cap?: number,
 *   label?: string,
 *   onLimit?: ((ip: string, label: string) => void) | null
 * }} [options]
 */
function createRateLimiter({
  windowMs = 60000,
  max = 120,
  bypassLoopback = true,
  cap = 2000,
  label = 'api',
  onLimit = null
} = {}) {
  /** @type {Map<string, { count: number, resetAt: number }>} */
  const hits = new Map();

  /**
   * Comprueba si la petición excede el límite.
   * @param {any} req
   * @returns {{ allowed: boolean, retryAfterSec: number, remaining: number, ip: string }}
   */
  function check(req) {
    const hasProxyHeader = Boolean(req?.headers?.['x-forwarded-for'] || req?.headers?.forwarded);
    if (bypassLoopback && !hasProxyHeader && isLoopback(req)) {
      return { allowed: true, retryAfterSec: 0, remaining: max, ip: 'loopback' };
    }
    const ip = resolveRateLimitIp(req);
    const now = Date.now();
    let entry = hits.get(ip);
    if (!entry || entry.resetAt <= now) {
      if (hits.size >= cap) {
        const oldest = hits.keys().next().value;
        if (oldest) hits.delete(oldest);
      }
      entry = { count: 1, resetAt: now + windowMs };
      hits.set(ip, entry);
      return { allowed: true, retryAfterSec: 0, remaining: Math.max(0, max - 1), ip };
    }
    entry.count++;
    hits.delete(ip);
    hits.set(ip, entry);
    if (entry.count > max) {
      const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      if (onLimit) {
        try { onLimit(ip, label); } catch (e) {}
      }
      return { allowed: false, retryAfterSec, remaining: 0, ip };
    }
    return { allowed: true, retryAfterSec: 0, remaining: Math.max(0, max - entry.count), ip };
  }

  /** Middleware Express compatible. */
  function middleware(req, res, next) {
    const result = check(req);
    if (!result.allowed) {
      res.setHeader('Retry-After', String(result.retryAfterSec));
      return res.status(429).json({
        error: 'Demasiadas peticiones. Espera unos segundos antes de reintentar.',
        retryAfterSec: result.retryAfterSec
      });
    }
    return next();
  }

  return Object.assign(middleware, {
    check,
    reset: () => hits.clear()
  });
}

module.exports = {
  createRateLimiter,
  resolveRateLimitIp
};
