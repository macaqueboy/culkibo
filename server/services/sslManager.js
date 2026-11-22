const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { atomicWriteJsonSync } = require('./ssrfGuard');

const CERTS_DIR = path.join(__dirname, '..', '..', 'data', 'certs');
const REGISTRY_FILE = path.join(CERTS_DIR, 'registry.json');
const ALLOWED_SSLIP_SERVICES = new Set(['sslip.io', 'nip.io']);

/**
 * Registro de certificados TLS.
 *
 * ── Qué hacía este módulo antes, y por qué se ha eliminado ────────────────────
 *
 * `issueWildcardCertificate()` escribía un PEM fabricado (`mockCertPem`), le
 * ponía una caducidad de 90 días calculada a mano y lo guardaba en
 * `data/certs/` con `status: 'active'`, un emisor inventado («Let's Encrypt
 * Authority R3») y una huella de `crypto.randomBytes(20)`. Lo único real de
 * todo el proceso era el registro TXT que sí se creaba en Cloudflare. El
 * arranque además sembraba dos certificados que no habían existido nunca.
 *
 * Un certificado falso es peor que no tener ninguno: un panel que dice «activo,
 * caduca en 70 días» hace que nadie mire, y el fallo aparece el día que un
 * navegador rechaza la conexión. Por eso se ha borrado la emisión entera en vez
 * de arreglarla.
 *
 * ── Por qué no se ha implementado la emisión de verdad ───────────────────────
 *
 * La alternativa era llamar a `lego` (ACME DNS-01 con Cloudflare) desde aquí.
 * Se ha descartado:
 *
 *   1. El plano de datos YA es Caddy (ver `caddyManager.js`) y Caddy YA emite
 *      certificados solo, bajo demanda, en el primer handshake de cada host:
 *      `buildBaseConfig()` publica la política `on_demand` con
 *      `permission.module: http` apuntando a nuestro endpoint de autorización.
 *      El certificado no es un campo de nuestro JSON; vive en el volumen de
 *      Caddy. Eso es precisamente lo que hace imposible volver a falsearlo.
 *   2. Añadir `lego` significaría un SEGUNDO emisor y un segundo almacén para
 *      los mismos nombres, con dos cuentas ACME compitiendo por los mismos
 *      límites de Let's Encrypt, y haría falta un temporizador de renovación
 *      que Culkibo no tiene. Dos fuentes de verdad sobre el mismo certificado
 *      es exactamente la deriva que `ingressManager.reconcile()` existe para
 *      evitar.
 *   3. CertMagic —la biblioteca que Caddy lleva dentro— implementa ARI
 *      (RFC 9773), y las renovaciones por ARI están exentas de los límites de
 *      tasa de Let's Encrypt. `lego` invocado a mano no tendría esa exención.
 *      (Y `acme-client` de npm, la otra opción, no tiene commits desde julio de
 *      2024 y no soporta ni ARI ni perfiles.)
 *
 * Queda una carencia honesta: el comodín por DNS-01 (`*.dominio.com`) NO está
 * implementado. Caddy puede hacerlo con el módulo `caddy-dns/cloudflare`, pero
 * la imagen estándar `caddy:2-alpine` no lo incluye —hay que recompilar con
 * xcaddy—. Mientras tanto, el TLS por host bajo demanda cubre el caso real, y
 * `issueWildcardCertificate()` lo dice en vez de fingir.
 *
 * ── Qué garantiza ahora este registro ────────────────────────────────────────
 *
 * `listCertificates()` no informa jamás de un certificado que no exista. Cada
 * entrada es de uno de estos dos tipos, y ninguno admite datos inventados:
 *
 *   - `on_disk`: hay un PEM en `data/certs/`. Todos los campos publicados
 *     (emisor, caducidad, huella, SANs) se LEEN del X.509 con
 *     `crypto.X509Certificate`, no se guardan. Si el fichero desaparece o no
 *     parsea, la entrada se borra.
 *   - `delegated`: el certificado lo gestiona Caddy bajo demanda. No hay
 *     emisor ni caducidad que podamos afirmar, así que se publican `null` y
 *     `verified: false`. El dato verificado sale del handshake TLS real de
 *     `ingressManager.probeTls()`.
 */

/** Marcador de las entradas cuyo certificado gestiona el plano de datos. */
const MANAGED_BY_CADDY = 'caddy_on_demand';

class SslManager {
  constructor() {
    this.ensureDirectory();
    // Caché del X.509 ya parseado, con clave (ruta, mtime, tamaño).
    //
    // No es una optimización prematura: `domainManager.listDomains()` llama a
    // `getCertificateByDomain()` una vez por dominio, y cada llamada recorre el
    // registro. Sin caché, un GET /api/domains hacía lectura de fichero y
    // parseo de certificado O(dominios × certificados) — medido como +40 ms de
    // latencia media en la prueba de 100 peticiones concurrentes.
    //
    // Lo que NO se cachea es la existencia: `readCertificateFile()` hace
    // `statSync` en cada llamada. Si el fichero desaparece o cambia, la caché
    // no acierta y no se informa de él. La promesa —nunca publicar un
    // certificado que no existe— se mantiene intacta.
    this.parseCache = new Map();
    this.version = 0;
    this.registry = this.loadRegistry();
  }

  ensureDirectory() {
    if (!fs.existsSync(CERTS_DIR)) {
      fs.mkdirSync(CERTS_DIR, { recursive: true });
    }
  }

  loadRegistry() {
    let stored = [];
    try {
      if (fs.existsSync(REGISTRY_FILE)) {
        const parsed = JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf8'));
        if (Array.isArray(parsed)) stored = parsed;
      }
    } catch (e) {
      console.error('[SSL] Error loading cert registry:', e.message);
    }

    // Sin semillas. Las dos que había («*.culkibo.dev» y «*.127-0-0-1.sslip.io»)
    // eran invención pura: aparecían en el panel como activas sin que nadie
    // hubiera emitido nada.
    const { kept, purged } = this.purgeFabricated(stored);
    if (purged.length > 0) {
      console.warn(
        `[SSL] Se han descartado ${purged.length} entradas del registro que no corresponden a ningún certificado real: ` +
        purged.map(p => `${p.domain} (${p.reason})`).join(', ')
      );
      this.registry = kept;
      this.saveRegistry();
    }
    return kept;
  }

  /**
   * Limpieza de arranque: elimina del registro —y del disco— todo lo que la
   * versión anterior fabricó.
   *
   * Un PEM que no parsea como X.509 no es un certificado: es el `mockCertPem`
   * que se escribía antes. Se borra el fichero además de la entrada, porque el
   * requisito es que `data/certs/` deje de contener PEMs falsos, no sólo que
   * dejemos de mirarlos.
   */
  purgeFabricated(entries) {
    const kept = [];
    const purged = [];

    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;

      if (entry.managedBy === MANAGED_BY_CADDY) {
        kept.push(entry);
        continue;
      }

      if (!entry.certPath) {
        purged.push({ domain: entry.domain || '(sin dominio)', reason: 'no apunta a ningún fichero' });
        continue;
      }

      const parsed = this.readCertificateFile(entry.certPath);
      if (parsed.ok) {
        kept.push(entry);
        continue;
      }

      purged.push({ domain: entry.domain || '(sin dominio)', reason: parsed.error });
      this.deleteFabricatedFiles(entry);
    }

    return { kept, purged };
  }

  /**
   * Borra un par de ficheros fabricados, y sólo si están dentro de
   * `data/certs/`: nunca se toca nada fuera del directorio que gestionamos.
   */
  deleteFabricatedFiles(entry) {
    for (const p of [entry.certPath, entry.keyPath]) {
      if (!p) continue;
      const resolved = path.resolve(String(p));
      if (!resolved.startsWith(path.resolve(CERTS_DIR) + path.sep)) continue;
      try {
        if (fs.existsSync(resolved)) fs.unlinkSync(resolved);
      } catch (e) {
        console.warn(`[SSL] No se pudo borrar el PEM fabricado ${resolved}: ${e.message}`);
      }
    }
  }

  /**
   * Lee un certificado del disco y devuelve lo que el X.509 dice DE VERDAD.
   * Nada de lo que publica este módulo sobre un certificado en disco sale de
   * otro sitio que no sea esta función.
   */
  readCertificateFile(certPath) {
    if (!certPath) return { ok: false, error: 'el fichero no existe' };

    let stat;
    try {
      stat = fs.statSync(certPath);
    } catch (e) {
      // Se comprueba en CADA llamada, nunca desde la caché: la existencia del
      // fichero es justo lo que no puede darse por supuesto.
      this.parseCache.delete(certPath);
      return { ok: false, error: 'el fichero no existe' };
    }

    const cached = this.parseCache.get(certPath);
    if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
      return cached.result;
    }

    const result = this.parseCertificateFile(certPath);
    // Cota simple: el registro de un host normal tiene un puñado de entradas;
    // si algo lo hace crecer, se vacía antes que crecer sin límite.
    if (this.parseCache.size > 128) this.parseCache.clear();
    this.parseCache.set(certPath, { mtimeMs: stat.mtimeMs, size: stat.size, result });
    return result;
  }

  /** Parseo puro, sin caché. Sólo lo llama `readCertificateFile()`. */
  parseCertificateFile(certPath) {
    try {
      const pem = fs.readFileSync(certPath, 'utf8');
      const x509 = new crypto.X509Certificate(pem);
      const notAfter = new Date(x509.validTo);
      const notBefore = new Date(x509.validFrom);
      return {
        ok: true,
        issuer: this.extractName(x509.issuer),
        subject: this.extractName(x509.subject),
        sans: (x509.subjectAltName || '')
          .split(',')
          .map(s => s.trim().replace(/^DNS:/, ''))
          .filter(Boolean),
        notBefore: Number.isNaN(notBefore.getTime()) ? null : notBefore.toISOString(),
        notAfter: Number.isNaN(notAfter.getTime()) ? null : notAfter.toISOString(),
        fingerprint: x509.fingerprint256 || x509.fingerprint || null,
        keyType: x509.publicKey ? `${x509.publicKey.asymmetricKeyType || 'desconocido'}`.toUpperCase() : null
      };
    } catch (e) {
      // `X509Certificate` lanza cuando el PEM no es un certificado. Es
      // exactamente lo que ocurre con los `mockCertPem` de la versión anterior.
      return { ok: false, error: 'el contenido no es un certificado X.509 válido' };
    }
  }

  /** «CN=R11, O=Let's Encrypt, C=US» → «Let's Encrypt» (o el CN si no hay O). */
  extractName(dn) {
    const text = String(dn || '');
    const org = /(?:^|\n|,\s*)O=([^\n,]+)/.exec(text);
    if (org) return org[1].trim();
    const cn = /(?:^|\n|,\s*)CN=([^\n,]+)/.exec(text);
    return cn ? cn[1].trim() : null;
  }

  saveRegistry() {
    this.ensureDirectory();
    this.version++;
    atomicWriteJsonSync(REGISTRY_FILE, this.registry, 0o600);
  }

  /**
   * Lista los certificados.
   *
   * Nunca informa de uno que no exista: las entradas en disco se releen y se
   * verifican en cada llamada, y la que ya no parsea se elimina del registro
   * ahí mismo. Las entradas delegadas se publican como lo que son —una
   * declaración de quién gestiona el TLS— con caducidad `null`, porque nadie
   * aquí sabe cuándo caduca un certificado que emite Caddy.
   */
  listCertificates() {
    const out = [];
    let mutated = false;

    for (const cert of this.registry) {
      if (cert.managedBy === MANAGED_BY_CADDY) {
        out.push({
          ...cert,
          status: 'delegated',
          verified: false,
          issuer: null,
          expiresAt: null,
          fingerprint: null,
          keyType: null,
          certPath: null,
          keyPath: null,
          daysRemaining: null,
          isExpiringSoon: false,
          isExpired: false,
          managedBy: MANAGED_BY_CADDY,
          message: 'Lo emite Caddy en el primer handshake. Culkibo no guarda copia ni conoce su caducidad; el dato real está en /api/ingress/status.'
        });
        continue;
      }

      const real = this.readCertificateFile(cert.certPath);
      if (!real.ok) {
        // Se prometió que esta función no informa de certificados inexistentes:
        // si el fichero se ha ido, la entrada se va con él.
        mutated = true;
        continue;
      }

      const expires = real.notAfter ? new Date(real.notAfter) : null;
      const diffMs = expires ? expires.getTime() - Date.now() : null;
      out.push({
        ...cert,
        status: 'on_disk',
        verified: true,
        // Todo lo que sigue sale del X.509, no del JSON.
        issuer: real.issuer,
        subject: real.subject,
        sans: real.sans.length ? real.sans : (cert.sans || []),
        issuedAt: real.notBefore,
        expiresAt: real.notAfter,
        fingerprint: real.fingerprint,
        keyType: real.keyType,
        daysRemaining: diffMs === null ? null : Math.max(0, Math.floor(diffMs / 86400000)),
        isExpiringSoon: diffMs !== null && diffMs > 0 && diffMs <= 15 * 86400000,
        isExpired: diffMs !== null && diffMs <= 0
      });
    }

    if (mutated) {
      const surviving = new Set(out.map(c => c.id));
      this.registry = this.registry.filter(c => surviving.has(c.id));
      this.saveRegistry();
    }

    return out;
  }

  /**
   * Busca un certificado coincidente sobre una lista ya resuelta (evita
   * repetir `listCertificates()` en O(D×C) al proyectar todos los dominios).
   */
  matchCertificate(domain, certs) {
    const clean = String(domain || '').toLowerCase();
    return certs.find(c => {
      if (c.domain === clean || c.rootDomain === clean) return true;
      if (c.sans && c.sans.includes(clean)) return true;
      if (typeof c.domain === 'string' && c.domain.startsWith('*.')) {
        // Same boundary-dot rule as DomainManager.resolveRoute: a wildcard cert
        // for *.culkibo.dev must not be reported as covering evilculkibo.dev.
        const wildcardRoot = c.domain.slice(2);
        if (clean === wildcardRoot || clean.endsWith(`.${wildcardRoot}`)) return true;
      }
      return false;
    }) || undefined;
  }

  getCertificateByDomain(domain) {
    return this.matchCertificate(domain, this.listCertificates());
  }

  /**
   * Emisión de comodín: NO implementada, y lo dice.
   *
   * Se conserva la firma y la forma de la respuesta (`{ success, error }` y las
   * llamadas a `onProgress`) porque hay cuatro consumidores —API, MCP, CLI y el
   * migrador de Coolify— y ninguno debe romperse; lo que cambia es que ya no
   * miente. No escribe ficheros, no toca el registro y no crea el TXT en
   * Cloudflare: un TXT de desafío para una orden ACME que nunca va a existir es
   * basura en la zona DNS del usuario.
   */
  /**
   * @param {{ domain?: string, zoneId?: string | null, provider?: string, onProgress?: ((payload: any) => void) | null }} [opts]
   */
  async issueWildcardCertificate({ domain = '', zoneId = null, provider = 'lets_encrypt', onProgress = null } = {}) {
    const rootDomain = String(domain || '').replace(/^\*\./, '').toLowerCase();
    const wildcardDomain = rootDomain ? `*.${rootDomain}` : '*';

    const error =
      'La emisión de certificados comodín por ACME DNS-01 no está implementada en Culkibo. ' +
      'El TLS lo emite Caddy bajo demanda en el primer handshake de cada host, y el certificado ' +
      'vive en el volumen de Caddy, no en data/certs/. Para un comodín de verdad hace falta ' +
      'compilar Caddy con el módulo caddy-dns/cloudflare (xcaddy) y darle el token de Cloudflare. ' +
      'Antes esta llamada escribía un PEM inventado: se ha eliminado.';

    const payload = {
      jobId: `job_${Date.now()}`,
      domain: wildcardDomain,
      stage: 'no_implementado',
      progress: 100,
      message: error,
      code: 'WILDCARD_ACME_NO_IMPLEMENTADO',
      error
    };
    if (typeof onProgress === 'function') onProgress(payload);

    return {
      success: false,
      implemented: false,
      code: 'WILDCARD_ACME_NO_IMPLEMENTADO',
      error,
      alternative: 'on_demand_tls',
      domain: wildcardDomain,
      zoneId: zoneId || null,
      provider
    };
  }

  /**
   * Registra un host de sslip.io / nip.io para TLS bajo demanda.
   *
   * Antes esto también escribía un PEM fabricado y una caducidad de 90 días.
   * Ahora no genera ninguna clave ni escribe ningún fichero: sólo deja
   * constancia de que ese host existe y de que su certificado lo emite Caddy en
   * el primer handshake. La forma de la respuesta (`{ success, cert }`) se
   * mantiene porque el panel y el servidor MCP leen `cert.rootDomain`.
   */
  async issueOnDemandSslip({ ip = '127.0.0.1', service = 'sslip.io' } = {}) {
    const cleanIp = String(ip || '').trim();
    if (!net.isIPv4(cleanIp)) {
      throw new Error(`Dirección IPv4 inválida para sslip/nip.io: «${cleanIp}»`);
    }
    const cleanService = String(service || 'sslip.io').trim().toLowerCase();
    if (!ALLOWED_SSLIP_SERVICES.has(cleanService)) {
      throw new Error(`Servicio de DNS dinámico no soportado: «${cleanService}» (usa sslip.io o nip.io)`);
    }
    const formattedIp = cleanIp.replace(/\./g, '-');
    const domain = `${formattedIp}.${cleanService}`;
    const wildcardDomain = `*.${domain}`;

    const record = {
      id: `cert_ondemand_${Date.now()}`,
      domain: wildcardDomain,
      rootDomain: domain,
      type: 'ondemand_tls',
      provider: 'caddy_acme',
      managedBy: MANAGED_BY_CADDY,
      sans: [wildcardDomain, domain],
      // Ni emisor ni caducidad ni huella: no los sabemos y no se inventan.
      issuer: null,
      expiresAt: null,
      fingerprint: null,
      keyType: null,
      certPath: null,
      keyPath: null,
      status: 'delegated',
      registeredAt: new Date().toISOString(),
      autoRenew: true
    };

    this.registry = this.registry.filter(c => c.rootDomain !== domain);
    this.registry.unshift(record);
    this.saveRegistry();

    return {
      success: true,
      cert: this.listCertificates().find(c => c.id === record.id) || record,
      message: `Host ${domain} registrado. Caddy emitirá su certificado en la primera conexión HTTPS; comprueba el resultado real en /api/ingress/status.`
    };
  }

  /**
   * Da de baja una entrada del registro.
   *
   * No revoca nada en la CA: Culkibo no tiene la cuenta ACME. El nombre se
   * conserva por compatibilidad con la API, pero la respuesta lo aclara.
   */
  revokeCertificate(id) {
    const cert = this.registry.find(c => c.id === id);
    if (!cert) return { success: false, error: 'Certificado no encontrado en el registro' };

    // Un fichero en disco que el usuario pide retirar se borra; si es delegado
    // no hay nada que borrar, sólo la anotación.
    if (cert.certPath) this.deleteFabricatedFiles(cert);

    this.registry = this.registry.filter(c => c.id !== id);
    this.saveRegistry();
    return {
      success: true,
      revokedId: id,
      revokedAtCa: false,
      message: 'Entrada eliminada del registro local. No se ha revocado nada en la autoridad certificadora: Culkibo no gestiona la cuenta ACME.'
    };
  }
}

const sslManagerInstance = Object.assign(new SslManager(), { SslManager, MANAGED_BY_CADDY });
module.exports = sslManagerInstance;
