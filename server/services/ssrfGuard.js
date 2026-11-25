const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/** Carga perezosa de http/https/dns: evita pagar ~0.6 MB RSS al importar solo `atomicWriteJsonSync` en arranque. */
/** @type {typeof import('http') | null} */
let _httpMod = null;
/** @type {typeof import('https') | null} */
let _httpsMod = null;
function getHttpMod(isHttps) {
  if (isHttps) {
    if (!_httpsMod) _httpsMod = require('https');
    return _httpsMod;
  }
  if (!_httpMod) _httpMod = require('http');
  return _httpMod;
}

/** @type {any} */
let _dnsPromises = null;
function getDnsPromises() {
  if (!_dnsPromises) _dnsPromises = require('dns').promises;
  return _dnsPromises;
}

/**
 * Guardia compartida contra SSRF + cliente `safeFetch` con pinning de IP
 * (corta DNS rebinding TOCTOU y redirecciones maliciosas) + utilidades de
 * escritura atómica segura. Sin dependencias externas.
 */

/**
 * Parsea cualquier representación textual de IPv6 (comprimida, expandida,
 * mixta con cola IPv4 decimal como `0::ffff:127.0.0.1` o `64:ff9b::169.254.169.254`)
 * a exactamente 16 bytes (128 bits) en orden de red, o devuelve `null` si es inválida.
 * Rechaza zone IDs (`%eth0`).
 * @param {string} raw
 * @returns {Uint8Array | null}
 */
function parseIPv6ToBytes(raw) {
  if (typeof raw !== 'string') return null;
  let clean = raw.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean || clean.includes('%') || !clean.includes(':')) return null;

  const dblParts = clean.split('::');
  if (dblParts.length > 2) return null;

  /** @param {string} side @param {boolean} allowIpv4Tail */
  const parseSide = (side, allowIpv4Tail) => {
    if (!side) return [];
    const tokens = side.split(':');
    /** @type {number[]} */
    const words = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (!tok) return null;
      if (allowIpv4Tail && i === tokens.length - 1 && tok.includes('.')) {
        if (!net.isIPv4(tok)) return null;
        const octs = tok.split('.').map((n) => Number(n));
        if (octs.length !== 4 || octs.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
        words.push(((octs[0] << 8) | octs[1]) & 0xffff);
        words.push(((octs[2] << 8) | octs[3]) & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(tok)) return null;
        words.push(parseInt(tok, 16));
      }
    }
    return words;
  };

  /** @type {number[]} */
  let groups;
  if (dblParts.length === 2) {
    const left = parseSide(dblParts[0], false);
    const right = parseSide(dblParts[1], true);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    const all = parseSide(dblParts[0], true);
    if (!all || all.length !== 8) return null;
    groups = all;
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i] >> 8) & 0xff;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

/**
 * Extrae una dirección IPv4 desde representaciones IPv6 de 128 bits:
 *  - IPv4-mapped (`::ffff:0:0/96`, p. ej. `0::ffff:127.0.0.1`, `::ffff:a9fe:a9fe`)
 *  - SIIT (`::ffff:0:0:0/96`, p. ej. `::ffff:0:7f00:1`)
 *  - IPv4-compatible deprecado (`::/96` excluyendo `::` y `::1`)
 *  - NAT64 Well-Known (`64:ff9b::/96`, p. ej. `64:ff9b::169.254.169.254`)
 *  - NAT64 Local-Use RFC 8215 (`64:ff9b:1::/48`)
 *  - 6to4 (`2002::/16`)
 * @param {string} cleanLower
 * @returns {string | null}
 */
function extractEmbeddedIPv4(cleanLower) {
  const bytes = parseIPv6ToBytes(cleanLower);
  if (!bytes) return null;

  const isZeroRange = (start, endExclusive) => {
    for (let i = start; i < endExclusive; i++) {
      if (bytes[i] !== 0) return false;
    }
    return true;
  };
  const tailIPv4 = (off = 12) => `${bytes[off]}.${bytes[off + 1]}.${bytes[off + 2]}.${bytes[off + 3]}`;

  // IPv4-mapped ::ffff:0:0/96
  if (isZeroRange(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return tailIPv4(12);
  }
  // SIIT ::ffff:0:0:0/96
  if (isZeroRange(0, 8) && bytes[8] === 0xff && bytes[9] === 0xff && bytes[10] === 0 && bytes[11] === 0) {
    return tailIPv4(12);
  }
  // IPv4-compatible deprecado ::/96 (excl. :: y ::1)
  if (isZeroRange(0, 12)) {
    const isUnspecified = bytes[12] === 0 && bytes[13] === 0 && bytes[14] === 0 && bytes[15] === 0;
    const isLoopback = bytes[12] === 0 && bytes[13] === 0 && bytes[14] === 0 && bytes[15] === 1;
    if (!isUnspecified && !isLoopback) {
      return tailIPv4(12);
    }
  }
  // NAT64 well-known 64:ff9b::/96
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && isZeroRange(4, 12)) {
    return tailIPv4(12);
  }
  // NAT64 local-use RFC 8215 64:ff9b:1::/48
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && bytes[4] === 0x00 && bytes[5] === 0x01) {
    return tailIPv4(12);
  }
  // 6to4 2002::/16 (IPv4 en bytes 2..5)
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return tailIPv4(2);
  }
  return null;
}

/**
 * Devuelve true si una IPv4 pertenece a un rango privado, loopback, link-local,
 * CGNAT, documentación o reservado.
 * @param {string} ip
 */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = parts;
  if (a === 0) return true;                                  // 0.0.0.0/8
  if (a === 10) return true;                                 // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true;         // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true;                                // 127.0.0.0/8 (loopback)
  if (a === 169 && b === 254) return true;                   // 169.254.0.0/16 (link-local / cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true;          // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                   // 192.168.0.0/16
  if (a === 192 && b === 0 && c === 0) return true;          // 192.0.0.0/24 (IETF protocol)
  if (a === 192 && b === 88 && c === 99) return true;        // 192.88.99.0/24 (6to4 relay)
  if (a === 198 && (b === 18 || b === 19)) return true;      // 198.18.0.0/15 (benchmark)
  if (a >= 224) return true;                                 // multicast / reserved
  return false;
}

/**
 * Devuelve true si una IP (IPv4 o IPv6 de 128 bits, incluyendo embebidas) apunta
 * a metadatos cloud (AWS/GCP/Azure/ECS/Alibaba).
 * @param {string} ip
 */
function isMetadataIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return false;
  const embedded = extractEmbeddedIPv4(clean);
  if (embedded) return isMetadataIp(embedded);
  if (clean.startsWith('169.254.')) return true;
  if (clean === '100.100.100.200') return true; // Alibaba Cloud metadata
  const v6 = parseIPv6ToBytes(clean);
  if (v6) {
    // AWS IPv6 IMDS fd00:ec2::/32 (p. ej. fd00:ec2::254 y cualquier forma expandida)
    if (v6[0] === 0xfd && v6[1] === 0x00 && v6[2] === 0x0e && v6[3] === 0xc2) return true;
  }
  return false;
}

/**
 * Devuelve true si una IP (IPv4 o IPv6 en cualquier representación) es loopback.
 * @param {string} ip
 */
function isLoopbackIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return false;
  const embedded = extractEmbeddedIPv4(clean);
  if (embedded) return embedded.startsWith('127.');
  if (net.isIP(clean) === 4) return clean.startsWith('127.');
  const v6 = parseIPv6ToBytes(clean);
  if (v6) {
    for (let i = 0; i < 15; i++) {
      if (v6[i] !== 0) return false;
    }
    return v6[15] === 1;
  }
  return false;
}

/**
 * Devuelve true si una IP (IPv4 o IPv6 de 128 bits) es privada, loopback,
 * link-local, ULA, Teredo, multicast, discard o reservada.
 * @param {string} ip
 */
function isPrivateIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return true;
  // IPv6 con zone ID (p. ej. fe80::1%eth0) siempre es ámbito local/privado
  if (clean.includes('%')) return true;
  const embedded = extractEmbeddedIPv4(clean);
  if (embedded) return isPrivateIPv4(embedded);
  const kind = net.isIP(clean);
  if (kind === 4) return isPrivateIPv4(clean);
  if (kind === 6 || clean.includes(':')) {
    const b = parseIPv6ToBytes(clean);
    if (!b) return true; // fail-closed ante IPv6 malformada
    // Unspecified :: y Loopback ::1 (cubre 0::1, 0:0::1, ::0:1, 0000::0001)
    let prefixZero = true;
    for (let i = 0; i < 15; i++) {
      if (b[i] !== 0) { prefixZero = false; break; }
    }
    if (prefixZero && (b[15] === 0 || b[15] === 1)) return true;
    // ULA fc00::/7
    if ((b[0] & 0xfe) === 0xfc) return true;
    // Link-local fe80::/10
    if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;
    // Deprecated site-local fec0::/10
    if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;
    // Multicast ff00::/8
    if (b[0] === 0xff) return true;
    // Discard-only 100::/64 (RFC 6666)
    if (b[0] === 0x01 && b[1] === 0 && b[2] === 0 && b[3] === 0 && b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0) return true;
    // Teredo 2001:0000::/32
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true;
    // Benchmarking 2001:2::/48
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x02 && b[4] === 0x00 && b[5] === 0x00) return true;
    // ORCHIDv2 2001:20::/28
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x20) return true;
    // Documentation 2001:db8::/32
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true;
    return false;
  }
  return true;
}

/**
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @param {string} label
 * @returns {Promise<T>}
 */
function withTimeout(promise, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} excedió el tiempo límite (${timeoutMs} ms)`)), timeoutMs);
    if (timer.unref) timer.unref();
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

/**
 * Valida una URL antes de hacer peticiones salientes desde el servidor.
 * Resuelve DNS (con timeout de 5 s) y bloquea rangos privados/metadatos.
 *
 * @param {string} rawUrl
 * @param {{
 *   allowedProtocols?: string[],
 *   requireHttps?: boolean,
 *   allowPrivate?: boolean,
 *   allowLoopback?: boolean,
 *   allowCredentials?: boolean,
 *   allowedHosts?: string[] | null,
 *   blockSearchAndHash?: boolean,
 *   dnsTimeoutMs?: number
 * }} [options]
 * @returns {Promise<{ url: URL, addresses: string[] }>}
 */
async function assertSafeUrl(rawUrl, options = {}) {
  const {
    allowedProtocols = ['https:', 'http:'],
    requireHttps = false,
    allowPrivate = false,
    allowLoopback = false,
    allowCredentials = false,
    allowedHosts = null,
    blockSearchAndHash = false,
    dnsTimeoutMs = 5000
  } = options;
  const effectiveProtocols = requireHttps ? ['https:'] : allowedProtocols;

  if (typeof rawUrl !== 'string' || !rawUrl.trim() || rawUrl.length > 2048) {
    throw new Error('URL inválida o demasiado larga');
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (e) {
    throw new Error(`URL malformada: ${rawUrl.slice(0, 80)}`);
  }

  if (!effectiveProtocols.includes(parsed.protocol)) {
    throw new Error(`Protocolo no permitido: ${parsed.protocol}`);
  }
  if (!allowCredentials && (parsed.username || parsed.password)) {
    throw new Error('No se permiten credenciales incrustadas en la URL');
  }
  if (blockSearchAndHash && (parsed.search || parsed.hash)) {
    throw new Error('La URL base no puede contener parámetros de consulta ni fragmentos');
  }

  // Quitar corchetes IPv6 y punto final FQDN (evita bypass `localhost.` / `metadata.google.internal.`)
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!host) throw new Error('La URL no tiene host');

  if (Array.isArray(allowedHosts) && allowedHosts.length > 0) {
    const ok = allowedHosts.some((rawH) => {
      const h = String(rawH || '').trim().toLowerCase().replace(/\.+$/, '');
      return Boolean(h) && (host === h || host.endsWith(`.${h}`));
    });
    if (!ok) {
      throw new Error(`Dominio no autorizado para esta integración: ${host}`);
    }
  }

  // Bloquear siempre nombres de metadatos cloud conocidos (incl. variantes con punto FQDN ya limpiado)
  if (
    host === 'metadata.google.internal' ||
    host.endsWith('.metadata.google.internal') ||
    host === 'metadata.goog' ||
    host === 'metadata' ||
    host === 'instance-data' ||
    host === 'metadata.azure.com' ||
    host === 'metadata.tencentyun.com' ||
    host === 'metadata.packet.net' ||
    host === 'metadata.platformequinix.com'
  ) {
    throw new Error(`Host de metadatos bloqueado por seguridad: ${host}`);
  }

  /** @type {string[]} */
  let addresses = [];
  if (net.isIP(host)) {
    addresses = [host];
  } else if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === 'ip6-localhost' ||
    host === 'ip6-loopback'
  ) {
    addresses = ['127.0.0.1'];
  } else {
    const dns = getDnsPromises();
    try {
      const [v4, v6] = await withTimeout(
        Promise.all([
          dns.resolve4(host).catch(() => []),
          dns.resolve6(host).catch(() => [])
        ]),
        dnsTimeoutMs,
        `Resolución DNS de ${host}`
      );
      addresses = [...v4, ...v6];
    } catch (e) {
      addresses = [];
    }
    if (addresses.length === 0) {
      try {
        const looked = await withTimeout(
          dns.lookup(host, { all: true }),
          dnsTimeoutMs,
          `Resolución DNS de ${host}`
        );
        addresses = looked.map((r) => r.address);
      } catch (e) {
        throw new Error(`No se pudo resolver el dominio: ${host}`);
      }
    }
  }

  for (const addr of addresses) {
    if (isMetadataIp(addr)) {
      throw new Error(`Destino bloqueado (IP de metadatos cloud): ${addr}`);
    }
    if (!allowPrivate) {
      if (allowLoopback && isLoopbackIp(addr)) continue;
      if (isPrivateIp(addr)) {
        throw new Error(`Destino bloqueado por protección SSRF (IP privada/local): ${addr}`);
      }
    }
  }

  return { url: parsed, addresses };
}

/**
 * Cliente HTTP/HTTPS sin dependencias con validación SSRF en cada salto de
 * redirección y pinning de IP (evita DNS rebinding TOCTOU), SNI correcto para
 * HTTPS y límite de tamaño de respuesta.
 *
 * @param {string} rawUrl
 * @param {{
 *   method?: string,
 *   headers?: Record<string, string>,
 *   body?: string | Buffer | null,
 *   timeoutMs?: number,
 *   maxRedirects?: number,
 *   maxBytes?: number,
 *   allowPrivate?: boolean,
 *   allowLoopback?: boolean,
 *   requireHttps?: boolean,
 *   allowedHosts?: string[] | null
 * }} [opts]
 * @returns {Promise<{ ok: boolean, status: number, url: string, headers: Record<string, string | string[] | undefined>, body: Buffer, text: () => string, json: () => any }>}
 */
async function safeFetch(rawUrl, opts = {}) {
  const {
    method = 'GET',
    headers = {},
    body = null,
    timeoutMs = 10000,
    maxRedirects = 3,
    maxBytes = 10 * 1024 * 1024,
    allowPrivate = false,
    allowLoopback = false,
    requireHttps = false,
    allowedHosts = null
  } = opts;

  let currentUrl = rawUrl;
  let currentMethod = String(method || 'GET').toUpperCase();
  let currentBody = body;
  let currentHeaders = { ...headers };
  const initialOrigin = (() => {
    try { return new URL(String(rawUrl || '').trim()).origin; } catch (e) { return null; }
  })();

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const { url: parsed, addresses } = await assertSafeUrl(currentUrl, {
      allowPrivate,
      allowLoopback,
      requireHttps,
      allowedHosts
    });

    const pinnedIp = addresses.find((a) => net.isIP(a) === 4) || addresses[0];
    const family = net.isIP(pinnedIp) === 6 ? 6 : 4;
    const isHttps = parsed.protocol === 'https:';
    const mod = getHttpMod(isHttps);
    const targetHostname = parsed.hostname.replace(/^\[|\]$/g, '');

    /** @type {{ status: number, headers: Record<string, any>, body: Buffer }} */
    const resObj = await new Promise((resolve, reject) => {
      let settled = false;
      const done = (err, val) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(val);
      };

      const reqHeaders = { ...currentHeaders };
      if (currentBody != null && !reqHeaders['Content-Length'] && !reqHeaders['content-length']) {
        reqHeaders['Content-Length'] = String(Buffer.byteLength(currentBody));
      }

      const reqOpts = {
        protocol: parsed.protocol,
        hostname: targetHostname,
        port: parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80),
        path: `${parsed.pathname || '/'}${parsed.search || ''}`,
        method: currentMethod,
        headers: reqHeaders,
        timeout: timeoutMs,
        ...(isHttps ? { servername: net.isIP(targetHostname) ? undefined : targetHostname } : {}),
        lookup: (_host, _opts, cb) => {
          if (typeof _opts === 'function') return _opts(null, pinnedIp, family);
          if (_opts && _opts.all) return cb(null, [{ address: pinnedIp, family }]);
          return cb(null, pinnedIp, family);
        }
      };

      const req = mod.request(reqOpts, (res) => {
        const status = res.statusCode || 0;
        // Si es redirección, drenar cuerpo sin acumular
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          return done(null, { status, headers: res.headers, body: Buffer.alloc(0) });
        }
        /** @type {Buffer[]} */
        const chunks = [];
        let total = 0;
        res.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            req.destroy(new Error(`Respuesta demasiado grande (> ${maxBytes} bytes)`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => done(null, { status, headers: res.headers, body: Buffer.concat(chunks, total) }));
        res.on('error', (err) => done(err, null));
      });

      req.on('timeout', () => req.destroy(new Error(`Tiempo de espera agotado (${timeoutMs} ms)`)));
      req.on('error', (err) => done(err, null));
      if (currentBody != null && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
        req.write(currentBody);
      }
      req.end();
    });

    if (resObj.status >= 300 && resObj.status < 400 && resObj.headers.location) {
      if (hop === maxRedirects) {
        throw new Error(`Demasiadas redirecciones (> ${maxRedirects})`);
      }
      let nextParsed;
      try {
        nextParsed = new URL(String(resObj.headers.location), parsed);
      } catch (e) {
        throw new Error('Redirección con cabecera Location malformada');
      }
      // Nunca filtrar credenciales, cookies ni cabeceras API sensibles al cruzar a otro origen en una redirección
      if (nextParsed.origin !== parsed.origin || (initialOrigin && nextParsed.origin !== initialOrigin)) {
        for (const k of Object.keys(currentHeaders)) {
          if (/^(authorization|proxy-authorization|cookie|set-cookie|x-culkibo-token|x-culkibo-secret|x-api-key|api-key|apikey|x-auth-token|x-access-token|private-token|x-gitlab-token|x-github-token|x-vault-token|x-amz-security-token)$|(?:token|secret|apikey|api-key|credential|auth)/i.test(k)) {
            delete currentHeaders[k];
          }
        }
      }
      currentUrl = nextParsed.toString();
      if (resObj.status === 301 || resObj.status === 302 || resObj.status === 303) {
        currentMethod = 'GET';
        currentBody = null;
      }
      continue;
    }

    const buf = resObj.body;
    return {
      ok: resObj.status >= 200 && resObj.status < 300,
      status: resObj.status,
      url: parsed.toString(),
      headers: resObj.headers,
      body: buf,
      text: () => buf.toString('utf8'),
      json: () => JSON.parse(buf.toString('utf8'))
    };
  }

  throw new Error('Demasiadas redirecciones');
}

/**
 * Escritura atómica síncrona con `fsync`, nombre temporal único, permisos 0600,
 * respaldo `.bak` opcional y reintentos en Windows ante bloqueo breve de lectores.
 *
 * @param {string} targetPath
 * @param {any} data
 * @param {number | { mode?: number, pretty?: boolean, backup?: boolean }} [opts]
 */
function atomicWriteJsonSync(targetPath, data, opts = {}) {
  const mode = typeof opts === 'number' ? opts : (opts.mode ?? 0o600);
  const pretty = typeof opts === 'number' ? true : (opts.pretty ?? true);
  const backup = typeof opts === 'number' ? false : Boolean(opts.backup);
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const payload = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    const fd = fs.openSync(tmpPath, 'wx', mode);
    try {
      fs.writeSync(fd, payload, 0, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (backup && fs.existsSync(targetPath)) {
      try {
        fs.copyFileSync(targetPath, `${targetPath}.bak`);
        try { fs.chmodSync(`${targetPath}.bak`, mode); } catch (e) {}
      } catch (e) {}
    }
    let renamed = false;
    /** @type {any} */
    let lastRenameErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        fs.renameSync(tmpPath, targetPath);
        renamed = true;
        break;
      } catch (renameErr) {
        lastRenameErr = renameErr;
        if (renameErr && (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY' || renameErr.code === 'EACCES') && attempt < 2) {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * (attempt + 1));
          continue;
        }
        break;
      }
    }
    if (!renamed) {
      fs.copyFileSync(tmpPath, targetPath);
      try { fs.unlinkSync(tmpPath); } catch (e) {}
      if (lastRenameErr && !fs.existsSync(targetPath)) throw lastRenameErr;
    }
    try { fs.chmodSync(targetPath, mode); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Carga un fichero JSON intentando primero la copia principal y luego `.bak`.
 * Si el fichero existe en disco pero ambas copias están corruptas, lo pone en
 * cuarentena (`<ruta>.corrupt.<ts>`) en lugar de sobrescribirlo silenciosamente.
 *
 * @param {string} targetPath
 * @param {{ validate?: ((parsed: any) => boolean) | null }} [opts]
 * @returns {{ ok: boolean, data: any, exists: boolean, corrupt: boolean, recoveredFromBak: boolean, quarantinePath: string | null }}
 */
function loadJsonWithBackupSync(targetPath, { validate = null } = {}) {
  const bakPath = `${targetPath}.bak`;
  const primaryExists = fs.existsSync(targetPath);
  const bakExists = fs.existsSync(bakPath);
  if (!primaryExists && !bakExists) {
    return { ok: false, data: null, exists: false, corrupt: false, recoveredFromBak: false, quarantinePath: null };
  }
  const check = (parsed) => (typeof validate === 'function' ? Boolean(validate(parsed)) : parsed !== null && typeof parsed === 'object');
  if (primaryExists) {
    try {
      const parsed = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
      if (check(parsed)) {
        return { ok: true, data: parsed, exists: true, corrupt: false, recoveredFromBak: false, quarantinePath: null };
      }
    } catch (e) {}
  }
  if (bakExists) {
    try {
      const parsed = JSON.parse(fs.readFileSync(bakPath, 'utf8'));
      if (check(parsed)) {
        return { ok: true, data: parsed, exists: true, corrupt: false, recoveredFromBak: true, quarantinePath: null };
      }
    } catch (e) {}
  }
  /** @type {string | null} */
  let quarantinePath = null;
  if (primaryExists) {
    quarantinePath = `${targetPath}.corrupt.${Date.now()}`;
    try { fs.copyFileSync(targetPath, quarantinePath); } catch (e) { quarantinePath = null; }
  }
  return { ok: false, data: null, exists: true, corrupt: true, recoveredFromBak: false, quarantinePath };
}

/**
 * Formatea un mapa de variables para Docker `--env-file` rechazando inyecciones
 * de saltos de línea (`\r`, `\n`) y bytes nulos (`\0`) que dividirían variables.
 * @param {Record<string, any>} envObj
 * @returns {string}
 */
function formatDockerEnvFile(envObj) {
  const lines = [];
  for (const [rawKey, rawVal] of Object.entries(envObj || {})) {
    const key = String(rawKey || '').trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,254}$/.test(key)) {
      throw new Error(`Nombre de variable de entorno inválido para --env-file: ${key}`);
    }
    const val = rawVal == null ? '' : String(rawVal);
    if (/[\r\n\0]/.test(val)) {
      throw new Error(`La variable de entorno "${key}" contiene saltos de línea o bytes nulos no permitidos en --env-file`);
    }
    lines.push(`${key}=${val}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Garantiza que un subdirectorio o ruta relativa permanezca estrictamente dentro
 * de `baseRoot` (defensa en profundidad contra path traversal y symlinks).
 *
 * @param {string} baseRoot
 * @param {string} childSegment
 */
function assertContainedPath(baseRoot, childSegment) {
  const seg = String(childSegment || '');
  if (!seg || seg.includes('\0') || /[\r\n]/.test(seg)) {
    throw new Error('Ruta inválida (contiene bytes nulos o saltos de línea)');
  }
  const resolvedBase = path.resolve(baseRoot);
  const resolvedTarget = path.resolve(resolvedBase, seg);
  const rel = path.relative(resolvedBase, resolvedTarget);
  if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Ruta fuera del directorio permitido: ${seg.slice(0, 80)}`);
  }
  return resolvedTarget;
}

module.exports = {
  parseIPv6ToBytes,
  extractEmbeddedIPv4,
  isPrivateIPv4,
  isPrivateIp,
  isLoopbackIp,
  isMetadataIp,
  assertSafeUrl,
  safeFetch,
  atomicWriteJsonSync,
  loadJsonWithBackupSync,
  formatDockerEnvFile,
  assertContainedPath
};
