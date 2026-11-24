'use strict';

const crypto = require('crypto');

/**
 * Limitador de tasa dual con privacidad estricta:
 *  - Las IPs se hashean en RAM con HMAC-SHA256 + sal efímera por arranque (NUNCA se guarda la IP real).
 *  - Limita tanto por IP hasheada (60 req/min) como por instanceId (120 req/hora).
 *  - Limpia entradas expiradas antes de aplicar evicción LRU acotada.
 */
class DualRateLimiter {
  /**
   * @param {{ ipLimit?: number, ipWindowMs?: number, instanceLimit?: number, instanceWindowMs?: number, maxEntries?: number }} [opts]
   */
  constructor(opts = {}) {
    this.salt = crypto.randomBytes(32);
    this.ipLimit = opts.ipLimit || 60;
    this.ipWindowMs = opts.ipWindowMs || 60 * 1000;
    this.instanceLimit = opts.instanceLimit || 120;
    this.instanceWindowMs = opts.instanceWindowMs || 60 * 60 * 1000;
    this.maxEntries = opts.maxEntries || 10000;
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this.ipBuckets = new Map();
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this.instanceBuckets = new Map();
  }

  /** @param {string} rawIp */
  hashIp(rawIp) {
    const clean = String(rawIp || 'unknown').trim().toLowerCase();
    return crypto.createHmac('sha256', this.salt).update(clean).digest('hex').slice(0, 24);
  }

  /**
   * @param {Map<string, { count: number, resetAt: number }>} map
   * @param {string} key
   * @param {number} limit
   * @param {number} windowMs
   */
  _consume(map, key, limit, windowMs) {
    const now = Date.now();
    const existing = map.get(key);
    if (existing && now < existing.resetAt) {
      if (existing.count >= limit) {
        return {
          allowed: false,
          retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
        };
      }
      existing.count++;
      return { allowed: true, retryAfterSec: 0 };
    }

    if (map.size >= this.maxEntries) {
      for (const [k, v] of map.entries()) {
        if (now >= v.resetAt) map.delete(k);
      }
      if (map.size >= this.maxEntries) {
        const oldestKey = map.keys().next().value;
        if (oldestKey !== undefined) map.delete(oldestKey);
      }
    }

    map.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSec: 0 };
  }

  /** @param {string} rawIp */
  checkIp(rawIp) {
    const key = this.hashIp(rawIp);
    return this._consume(this.ipBuckets, key, this.ipLimit, this.ipWindowMs);
  }

  /** @param {string} instanceId */
  checkInstance(instanceId) {
    return this._consume(this.instanceBuckets, instanceId, this.instanceLimit, this.instanceWindowMs);
  }
}

module.exports = { DualRateLimiter };
