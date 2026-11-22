const dns = require('dns').promises;
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Guardia compartida contra SSRF + utilidades de escritura atómica segura.
 * Sin dependencias externas (solo módulos nativos de Node.js).
 */

/**
 * Devuelve true si una IPv4 pertenece a un rango privado, loopback, link-local,
 * CGNAT o reservado.
 * @param {string} ip
 */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true;                            // 0.0.0.0/8
  if (a === 10) return true;                           // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true;   // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true;                          // 127.0.0.0/8 (loopback)
  if (a === 169 && b === 254) return true;             // 169.254.0.0/16 (link-local / cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
  if (a === 192 && b === 168) return true;             // 192.168.0.0/16
  if (a === 192 && b === 0 && parts[2] === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
  if (a >= 224) return true;                           // multicast / reserved
  return false;
}

/**
 * Devuelve true si una IP (IPv4 o IPv6) apunta a metadatos cloud (AWS/GCP/Azure/ECS).
 * @param {string} ip
 */
function isMetadataIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (clean.startsWith('::ffff:')) return isMetadataIp(clean.slice(7));
  if (clean.startsWith('169.254.')) return true;
  if (clean === 'fd00:ec2::254' || clean.startsWith('fd00:ec2::')) return true;
  if (clean === '100.100.100.200') return true; // Alibaba Cloud metadata
  return false;
}

/**
 * Devuelve true si una IP (IPv4 o IPv6) es privada, loopback o reservada.
 * @param {string} ip
 */
function isPrivateIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return true;
  if (clean.startsWith('::ffff:')) {
    return isPrivateIPv4(clean.slice(7));
  }
  const kind = net.isIP(clean);
  if (kind === 4) return isPrivateIPv4(clean);
  if (kind === 6) {
    if (clean === '::' || clean === '::1') return true;
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true; // ULA fc00::/7
    if (/^fe[89ab]/.test(clean)) return true; // link-local fe80::/10
    if (clean.startsWith('ff')) return true;  // multicast
    return false;
  }
  return true;
}

/**
 * Valida una URL antes de hacer peticiones salientes desde el servidor.
 * Resuelve DNS y bloquea rangos privados/metadatos para cortar SSRF y DNS rebinding básico.
 *
 * @param {string} rawUrl
 * @param {{
 *   allowedProtocols?: string[],
 *   requireHttps?: boolean,
 *   allowPrivate?: boolean,
 *   allowLoopback?: boolean,
 *   allowCredentials?: boolean,
 *   allowedHosts?: string[] | null,
 *   blockSearchAndHash?: boolean
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
    blockSearchAndHash = false
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

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) throw new Error('La URL no tiene host');

  if (Array.isArray(allowedHosts) && allowedHosts.length > 0) {
    const ok = allowedHosts.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`));
    if (!ok) {
      throw new Error(`Dominio no autorizado para esta integración: ${host}`);
    }
  }

  // Bloquear siempre nombres de metadatos cloud conocidos
  if (host === 'metadata.google.internal' || host === 'metadata' || host === 'instance-data') {
    throw new Error(`Host de metadatos bloqueado por seguridad: ${host}`);
  }

  /** @type {string[]} */
  let addresses = [];
  if (net.isIP(host)) {
    addresses = [host];
  } else if (host === 'localhost' || host.endsWith('.localhost')) {
    addresses = ['127.0.0.1'];
  } else {
    try {
      const [v4, v6] = await Promise.all([
        dns.resolve4(host).catch(() => []),
        dns.resolve6(host).catch(() => [])
      ]);
      addresses = [...v4, ...v6];
    } catch (e) {
      addresses = [];
    }
    if (addresses.length === 0) {
      // Fallback a dns.lookup si el resolver del host (p. ej. /etc/hosts) es necesario
      try {
        const looked = await dns.lookup(host, { all: true });
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
      const isLoop = addr === '127.0.0.1' || addr === '::1' || addr.startsWith('127.') || addr === '::ffff:127.0.0.1';
      if (isLoop && allowLoopback) continue;
      if (isPrivateIp(addr)) {
        throw new Error(`Destino bloqueado por protección SSRF (IP privada/local): ${addr}`);
      }
    }
  }

  return { url: parsed, addresses };
}

/**
 * Escritura atómica síncrona con nombre temporal único, permisos 0600 opcionales
 * y fallback seguro para Windows cuando un lector retiene brevemente el destino.
 *
 * @param {string} targetPath
 * @param {any} data
 * @param {number | { mode?: number, pretty?: boolean }} [opts]
 */
function atomicWriteJsonSync(targetPath, data, opts = {}) {
  const mode = typeof opts === 'number' ? opts : (opts.mode ?? 0o600);
  const pretty = typeof opts === 'number' ? true : (opts.pretty ?? true);
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const payload = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, payload, { encoding: 'utf8', mode });
    try {
      fs.renameSync(tmpPath, targetPath);
    } catch (renameErr) {
      fs.copyFileSync(tmpPath, targetPath);
      try { fs.unlinkSync(tmpPath); } catch (e) {}
    }
    try { fs.chmodSync(targetPath, mode); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Garantiza que un subdirectorio o ruta relativa permanezca estrictamente dentro
 * de `baseRoot` (defensa en profundidad contra path traversal y symlinks).
 *
 * @param {string} baseRoot
 * @param {string} childSegment
 */
function assertContainedPath(baseRoot, childSegment) {
  const resolvedBase = path.resolve(baseRoot);
  const resolvedTarget = path.resolve(resolvedBase, String(childSegment || ''));
  const rel = path.relative(resolvedBase, resolvedTarget);
  if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Ruta fuera del directorio permitido: ${childSegment}`);
  }
  return resolvedTarget;
}

module.exports = {
  isPrivateIPv4,
  isPrivateIp,
  isMetadataIp,
  assertSafeUrl,
  atomicWriteJsonSync,
  assertContainedPath
};
