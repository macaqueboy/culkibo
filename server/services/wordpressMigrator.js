const dns = require('dns').promises;
const net = require('net');
const util = require('util');
const zlib = require('zlib');
const gunzipAsync = util.promisify(zlib.gunzip);
const catalogManager = require('./catalogManager');
const databaseManager = require('./databaseManager');
const { assertSafeUrl, safeFetch } = require('./ssrfGuard');

const DANGEROUS_MYSQL_META_RE = /^\s*(?:\\!|\\\.|system\b|source\b|tee\b|pager\b|edit\b)/i;

/**
 * Asistente real de análisis y migración de sitios WordPress hacia Culkibo.
 *
 * - Analiza el sitio de origen con peticiones HTTP reales (HTML + REST API
 *   `/wp-json`), protegido contra SSRF.
 * - Aprovisiona WordPress + MariaDB aislada mediante `catalogManager`.
 * - Permite importar un volcado `.sql` directo al contenedor MariaDB sin shell
 *   (`spawn` por argv) y reescribir `siteurl`/`home` al dominio nuevo.
 */

const MAX_HTML_BYTES = 1.5 * 1024 * 1024;
const MAX_SQL_BYTES = 50 * 1024 * 1024;

const KNOWN_WP_NAMESPACES = {
  'wc/v3': 'woocommerce',
  'wc/store': 'woocommerce',
  'yoast/v1': 'wordpress-seo',
  'elementor/v1': 'elementor',
  'rankmath/v1': 'seo-by-rank-math',
  'wpforms/v1': 'wpforms',
  'jetpack/v4': 'jetpack',
  'contact-form-7/v1': 'contact-form-7',
  'litespeed/v1': 'litespeed-cache',
  'redirection/v1': 'redirection',
  'acf/v3': 'advanced-custom-fields'
};

/** Lee hasta `maxBytes` de una respuesta fetch sin agotar memoria. */
async function readBoundedText(res, maxBytes = MAX_HTML_BYTES) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const buf = Buffer.from(value);
      if (total + buf.length > maxBytes) {
        chunks.push(buf.subarray(0, Math.max(0, maxBytes - total)));
        break;
      }
      chunks.push(buf);
      total += buf.length;
    }
  } finally {
    try { await reader.cancel(); } catch (e) {}
  }
  return Buffer.concat(chunks).toString('utf8');
}

function normalizeSiteUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) throw new Error('Indica la URL de tu web WordPress (por ejemplo https://mitienda.com)');
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

function slugifySiteName(name) {
  return String(name || 'wordpress')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32) || 'wordpress';
}

function isCloudflareIp(ip) {
  return ip.startsWith('104.21.') || ip.startsWith('104.20.') || ip.startsWith('104.18.') || ip.startsWith('172.67.') || ip.startsWith('188.114.');
}

/**
 * Detecta prefijo de tablas WordPress en un volcado SQL (por defecto `wp_`).
 * Prioriza tablas `*options` que contengan `option_name` (evita falsos positivos con otras tablas `*options`).
 */
function detectWpTablePrefix(sql) {
  const re = /(?:CREATE\s+TABLE|INSERT\s+INTO)\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)options`?/gi;
  /** @type {string | null} */
  let fallback = null;
  let m;
  while ((m = re.exec(sql)) !== null) {
    const candidate = m[1];
    if (!/^[a-zA-Z0-9_]{1,24}$/.test(candidate)) continue;
    if (!fallback) fallback = candidate;
    const windowSlice = sql.slice(m.index, m.index + 600);
    if (/\boption_name\b/i.test(windowSlice)) return candidate;
  }
  return fallback || 'wp_';
}

function normalizeOriginUrl(domainOrUrl) {
  const clean = String(domainOrUrl || '').trim().replace(/\/+$/, '');
  if (!clean) return '';
  if (/^https?:\/\//i.test(clean)) return clean;
  return `https://${clean}`;
}

/**
 * Añade de forma segura la actualización de `siteurl` y `home` en `wp_options`
 * sin corromper cadenas PHP serializadas (`s:N:"..."`).
 */
function prepareSqlForDomain(sql, oldDomain, newDomain) {
  const cleanNew = normalizeOriginUrl(newDomain);
  if (!cleanNew) return { sql, tablePrefix: detectWpTablePrefix(sql), urlsUpdated: false, serializedWarning: false };

  // P1-24: validación estricta de URL y escape de '\' antes de '\'' (MariaDB default mode)
  let parsedNew;
  try {
    parsedNew = new URL(cleanNew);
  } catch (e) {
    throw new Error(`Dominio de destino inválido: ${newDomain}`);
  }
  if ((parsedNew.protocol !== 'https:' && parsedNew.protocol !== 'http:') || /['"\\;\r\n\0]/.test(cleanNew)) {
    throw new Error(`Dominio de destino contiene caracteres no permitidos: ${newDomain}`);
  }
  const cleanOrigin = `${parsedNew.protocol}//${parsedNew.host}${parsedNew.pathname.replace(/\/+$/, '')}`;
  const prefix = detectWpTablePrefix(sql);
  const escapedUrl = cleanOrigin.replace(/\\/g, '\\\\').replace(/'/g, "''");

  // Limpiar BOM UTF-8, sentencias incompatibles con MariaDB (MySQL 8 collations, DEFINER, GTID_PURGED, CREATE DATABASE/USE)
  let output = String(sql || '')
    .replace(/^\uFEFF/, '')
    .replace(/utf8mb4_0900_ai_ci/gi, 'utf8mb4_unicode_ci')
    .replace(/utf8mb4_0900_as_ci/gi, 'utf8mb4_unicode_ci')
    .replace(/utf8mb4_0900_as_cs/gi, 'utf8mb4_unicode_520_ci')
    .replace(/\/\*!50013\s+DEFINER\s*=\s*[^*]+\*\//gi, '')
    .replace(/\bDEFINER\s*=\s*`?[^`\s@]+`?@`?[^`\s]+`?/gi, '')
    .replace(/^\s*SET\s+@@GLOBAL\.GTID_PURGED\s*=[\s\S]*?;\s*$/gim, '-- [Culkibo] GTID_PURGED omitido')
    .replace(/^\s*CREATE\s+DATABASE\b[^;\n]*;?\s*$/gim, '-- [Culkibo] CREATE DATABASE omitido')
    .replace(/^\s*USE\s+`?[a-zA-Z0-9_$-]+`?\s*;?\s*$/gim, '-- [Culkibo] USE omitido');

  const SERIALIZED_RE = /a:\d+:\{|s:\d+:\\?"|O:\d+:\\?"/;
  const hasSerialized = SERIALIZED_RE.test(output);

  let directReplaced = false;
  const cleanOldHost = String(oldDomain || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
  const cleanNewHost = parsedNew.host.toLowerCase();

  if (cleanOldHost && cleanNewHost && cleanOldHost !== cleanNewHost) {
    const escapedOld = cleanOldHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const urlRe = new RegExp(`https?://${escapedOld}(?=[/'"\\s\\\\;)]|$)`, 'gi');
    const jsonEscapedOldRe = new RegExp(`https?:\\\\/\\\\/${escapedOld}(?=[\\\\/'"\\s;)]|$)`, 'gi');
    const jsonEscapedNew = cleanOrigin.replace(/\//g, '\\/');
    if (!hasSerialized) {
      const next = output.replace(urlRe, cleanOrigin).replace(jsonEscapedOldRe, jsonEscapedNew);
      if (next !== output) {
        output = next;
        directReplaced = true;
      }
    } else {
      const lines = output.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (!SERIALIZED_RE.test(lines[i])) {
          let line = lines[i];
          if (urlRe.test(line)) {
            urlRe.lastIndex = 0;
            line = line.replace(urlRe, cleanOrigin);
            directReplaced = true;
          }
          urlRe.lastIndex = 0;
          if (jsonEscapedOldRe.test(line)) {
            jsonEscapedOldRe.lastIndex = 0;
            line = line.replace(jsonEscapedOldRe, jsonEscapedNew);
            directReplaced = true;
          }
          jsonEscapedOldRe.lastIndex = 0;
          lines[i] = line;
        }
      }
      output = lines.join('\n');
    }
  }

  output += `\n\n-- Actualización automática de URL de destino (Culkibo)\n` +
    `UPDATE \`${prefix}options\` SET option_value = '${escapedUrl}' WHERE option_name IN ('siteurl', 'home');\n`;

  return {
    sql: output,
    tablePrefix: prefix,
    urlsUpdated: true,
    directReplaced,
    serializedWarning: hasSerialized && Boolean(cleanOldHost && cleanOldHost !== cleanNewHost)
  };
}

class WordPressMigrator {
  /**
   * Analiza un sitio web en directo para confirmar si usa WordPress y extraer
   * versión, tema, plugins visibles, WooCommerce, DNS y plan de migración.
   *
   * @param {string} rawUrl
   * @param {{ allowPrivate?: boolean, timeoutMs?: number }} [opts]
   */
  async analyzeSite(rawUrl, { allowPrivate = false, timeoutMs = 8000 } = {}) {
    const normalized = normalizeSiteUrl(rawUrl);
    const { url: parsedUrl } = await assertSafeUrl(normalized, { allowPrivate });
    const baseOrigin = parsedUrl.origin;

    const headers = {
      'User-Agent': 'Culkibo-WordPress-Migrator/1.0 (+https://github.com/macaqueboy/culkibo)',
      'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8'
    };

    // P0-7: safeFetch valida CADA salto de redirección (corta SSRF por 302) y acota memoria.
    // Seguimos primero la home para descubrir el origen real tras redirecciones (http->https, apex->www).
    const [homeRes, dnsRes] = await Promise.allSettled([
      safeFetch(parsedUrl.toString(), { headers, maxRedirects: 4, maxBytes: MAX_HTML_BYTES, allowPrivate, timeoutMs }),
      dns.resolve4(parsedUrl.hostname).catch(() => [])
    ]);

    if (homeRes.status === 'rejected') {
      throw new Error(`No se pudo conectar con ${baseOrigin}: ${homeRes.reason?.message || 'sin respuesta'}`);
    }

    const res = homeRes.value;
    const finalUrl = res.url || parsedUrl.toString();
    const html = res.text();
    let probeOrigin = baseOrigin;
    try { probeOrigin = new URL(finalUrl).origin; } catch (e) {}

    // Detectar ruta real de la REST API (soporta instalaciones en subdirectorio como /blog/wp-json)
    const linkHeaderRaw = String(res.headers.link || '');
    const apiLinkHeaderMatch = linkHeaderRaw.match(/<([^>]+)>\s*;\s*rel=["']https:\/\/api\.w\.org\/["']/i);
    const apiLinkHtmlMatch = html.match(/<link[^>]+rel=["']https:\/\/api\.w\.org\/["'][^>]+href=["']([^"']+)["']/i)
      || html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']https:\/\/api\.w\.org\/["']/i);
    let wpJsonBase = `${probeOrigin}/wp-json`;
    const discoveredApi = (apiLinkHeaderMatch && apiLinkHeaderMatch[1]) || (apiLinkHtmlMatch && apiLinkHtmlMatch[1]);
    if (discoveredApi) {
      try {
        const u = new URL(discoveredApi, finalUrl);
        if (u.origin === probeOrigin) wpJsonBase = u.toString().replace(/\/+$/, '');
      } catch (e) {}
    }

    const [wpJsonRes, typesRes] = await Promise.allSettled([
      safeFetch(wpJsonBase, { headers: { ...headers, Accept: 'application/json' }, maxRedirects: 3, maxBytes: 512 * 1024, allowPrivate, timeoutMs: Math.min(timeoutMs, 5000) }),
      safeFetch(`${wpJsonBase}/wp/v2/types`, { headers: { ...headers, Accept: 'application/json' }, maxRedirects: 3, maxBytes: 256 * 1024, allowPrivate, timeoutMs: Math.min(timeoutMs, 5000) })
    ]);
    const resolvedIps = dnsRes.status === 'fulfilled' && Array.isArray(dnsRes.value) ? dnsRes.value : [];

    /** @type {any} */
    let wpJson = null;
    if (wpJsonRes.status === 'fulfilled' && wpJsonRes.value.ok) {
      try {
        const parsed = wpJsonRes.value.json();
        if (parsed && typeof parsed === 'object') wpJson = parsed;
      } catch (e) {}
    }

    /** @type {string[]} */
    let postTypes = [];
    if (typesRes.status === 'fulfilled' && typesRes.value.ok) {
      try {
        const parsed = typesRes.value.json();
        if (parsed && typeof parsed === 'object') postTypes = Object.keys(parsed);
      } catch (e) {}
    }

    const linkHeader = String(res.headers.link || '');
    const hasWpContent = /\/wp-content\//i.test(html);
    const hasWpIncludes = /\/wp-includes\//i.test(html);
    const generatorMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
    const generator = generatorMatch ? generatorMatch[1].trim() : null;
    const wpVersionMatch = (generator && generator.match(/WordPress\s+([0-9]+(?:\.[0-9]+){1,2})/i))
      || html.match(/wp-includes\/js\/[^"']+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
    const wpVersion = wpVersionMatch ? wpVersionMatch[1] : null;

    const namespaces = Array.isArray(wpJson?.namespaces) ? wpJson.namespaces : [];
    const restApiAvailable = Boolean(wpJson && (namespaces.includes('wp/v2') || wpJson.home || wpJson.url));
    const isWordPress = Boolean(
      restApiAvailable ||
      hasWpContent ||
      hasWpIncludes ||
      (generator && /wordpress/i.test(generator)) ||
      linkHeader.includes('api.w.org')
    );

    // Tema activo desde /wp-content/themes/<slug>/
    const themeMatches = new Set();
    for (const m of html.matchAll(/\/wp-content\/themes\/([a-zA-Z0-9_-]+)\//g)) {
      themeMatches.add(m[1]);
    }
    const themes = Array.from(themeMatches);

    // Plugins visibles en HTML + namespaces de /wp-json.
    const pluginSet = new Set();
    for (const m of html.matchAll(/\/wp-content\/plugins\/([a-zA-Z0-9_-]+)\//g)) {
      pluginSet.add(m[1]);
    }
    for (const ns of namespaces) {
      if (KNOWN_WP_NAMESPACES[ns]) pluginSet.add(KNOWN_WP_NAMESPACES[ns]);
    }
    const plugins = Array.from(pluginSet).sort();

    const hasWooCommerce = plugins.includes('woocommerce')
      || /woocommerce/i.test(html)
      || postTypes.includes('product');

    const titleMatch = html.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
    const siteName = (wpJson && typeof wpJson.name === 'string' && wpJson.name.trim())
      || (titleMatch ? titleMatch[1].trim().replace(/\s+/g, ' ') : parsedUrl.hostname);
    const siteDescription = (wpJson && typeof wpJson.description === 'string') ? wpJson.description.trim() : '';

    const getHeader = (name) => {
      if (!res.headers) return null;
      const val = typeof (/** @type {any} */ (res.headers)).get === 'function'
        ? (/** @type {any} */ (res.headers)).get(name)
        : res.headers[name.toLowerCase()];
      if (Array.isArray(val)) return val[0] || null;
      return typeof val === 'string' ? val : null;
    };

    const usesHttps = finalUrl.startsWith('https://');
    const usesCloudflare = Boolean(getHeader('cf-ray')) || resolvedIps.some(isCloudflareIp);
    const estimatedRamMb = hasWooCommerce ? 1536 : 1024;

    const migrationPlan = [
      '1. Creamos una copia limpia de WordPress 6.7 + MariaDB aislada en tu servidor con HTTPS automático (límite de subida 512 MB ya configurado).',
      '2. Te damos una URL temporal sslip.io o tu dominio para que pruebes el sitio sin cortar tu web actual.',
      hasWooCommerce
        ? '3. Detectamos WooCommerce: antes de exportar tu copia final, activa 5 minutos el modo mantenimiento en tu hosting actual para no perder pedidos.'
        : '3. Importa tu contenido con un solo archivo desde All-in-One WP Migration, Duplicator, o pega/sube tu volcado .sql aquí mismo.',
      usesCloudflare
        ? '4. Tu dominio ya pasa por Cloudflare: cuando verifiques la web, cambia el registro A a la IP de este servidor desde la pestaña Dominios (1 clic).'
        : '4. Cuando veas la web perfecta en tu servidor, apunta el registro A de tu dominio hacia esta IP y Caddy emitirá el candado HTTPS al instante.'
    ];

    return {
      success: true,
      url: finalUrl,
      hostname: parsedUrl.hostname,
      httpStatus: res.status,
      isWordPress,
      siteName,
      siteDescription,
      wpVersion,
      generator,
      restApiAvailable,
      theme: themes[0] || null,
      themes,
      plugins,
      hasWooCommerce,
      postTypes,
      usesHttps,
      usesCloudflare,
      serverHeader: getHeader('server'),
      resolvedIps,
      estimatedRamMb,
      suggestedSlug: slugifySiteName(siteName || parsedUrl.hostname),
      migrationPlan
    };
  }

  /**
   * Crea una nueva instancia aislada de WordPress + MariaDB a través del catálogo.
   *
   * @param {{ name?: string, domain?: string | null, sourceUrl?: string | null, useSslip?: boolean, serverIp?: string | null }} [opts]
   */
  async provisionWordPress({ name = 'Mi WordPress', domain = null, sourceUrl = null, useSslip = false, serverIp = null } = {}) {
    const cleanName = String(name || 'Mi WordPress').trim().slice(0, 80) || 'Mi WordPress';
    let effectiveDomain = domain ? String(domain).trim().toLowerCase() : null;

    if (!effectiveDomain && useSslip) {
      const ip = String(serverIp || '').trim();
      if (!net.isIPv4(ip)) {
        throw new Error('Para crear una URL temporal sslip.io necesitamos una IPv4 válida del servidor');
      }
      const slug = slugifySiteName(cleanName);
      effectiveDomain = `wp-${slug}.${ip.replace(/\./g, '-')}.sslip.io`;
    }

    const installation = await catalogManager.install({
      templateId: 'wordpress',
      name: cleanName,
      domain: effectiveDomain
    });

    const previewUrl = installation.url;
    return {
      success: true,
      installation,
      sourceUrl: sourceUrl || null,
      previewUrl,
      wpAdminUrl: `${previewUrl.replace(/\/+$/, '')}/wp-admin`,
      migrationChecklist: [
        `Espera unos segundos a que el estado cambie a «En marcha» y abre ${previewUrl}/wp-admin.`,
        'Opción rápida (sin tocar SQL): instala el plugin «All-in-One WP Migration» en tu WordPress viejo, exporta a Archivo e impórtalo en el nuevo (ya admite hasta 512 MB).',
        'Opción técnica (.sql): sube tu volcado .sql en el paso 4 de este asistente para restaurar la base de datos MariaDB directamente.',
        'Cuando verifiques que tu web se ve bien, conecta tu dominio definitivo desde la pestaña Dominios.'
      ]
    };
  }

  /**
   * Restaura un volcado `.sql` o `.sql.gz` (texto plano o Buffer) dentro de la base MariaDB de una instalación de WordPress.
   *
   * @param {{ installationId: string, sqlContent?: string, sqlBuffer?: Buffer | null, oldDomain?: string, newDomain?: string }} opts
   */
  async importSqlDump({ installationId, sqlContent = '', sqlBuffer = null, oldDomain = '', newDomain = '' }) {
    const record = catalogManager.mustGet(installationId);
    if (record.templateId !== 'wordpress') {
      throw new Error(`La instalación «${installationId}» no es de WordPress`);
    }
    if (!record.databaseId) {
      throw new Error('Esta instalación de WordPress no tiene una base de datos MariaDB asociada todavía');
    }

    let rawSql = typeof sqlContent === 'string' ? sqlContent : '';
    if (Buffer.isBuffer(sqlBuffer) && sqlBuffer.length > 0) {
      // Soportar archivos .sql.gz subidos directamente (descompresión asíncrona con límite estricto anti zip-bomb)
      const isGzip = sqlBuffer.length >= 2 && sqlBuffer[0] === 0x1f && sqlBuffer[1] === 0x8b;
      if (isGzip) {
        const inflated = await gunzipAsync(sqlBuffer, { maxOutputLength: MAX_SQL_BYTES + 1024 });
        if (inflated.length > MAX_SQL_BYTES) {
          throw new Error('El volcado .sql.gz descomprimido supera el límite de 50 MB');
        }
        rawSql = inflated.toString('utf8');
      } else {
        if (sqlBuffer.length > MAX_SQL_BYTES) {
          throw new Error('El volcado SQL supera el límite de 50 MB');
        }
        rawSql = sqlBuffer.toString('utf8');
      }
    }

    if (!rawSql.trim()) {
      throw new Error('El archivo SQL está vacío');
    }
    if (Buffer.byteLength(rawSql, 'utf8') > MAX_SQL_BYTES) {
      throw new Error('El volcado SQL supera el límite de 50 MB para importación directa; usa All-in-One WP Migration o restauración por CLI');
    }
    // Bloquear metacomandos de cliente MariaDB/MySQL (\\!, system, source, pager, tee, edit) antes de pasar por stdin
    const rawLines = rawSql.split(/\r?\n/);
    for (let i = 0; i < rawLines.length; i++) {
      if (DANGEROUS_MYSQL_META_RE.test(rawLines[i])) {
        throw new Error(`El volcado SQL contiene un metacomando de cliente bloqueado por seguridad en la línea ${i + 1}`);
      }
    }

    const dbRecord = databaseManager.mustGet(record.databaseId);
    const targetUrl = newDomain || record.url;
    const prepared = prepareSqlForDomain(rawSql, oldDomain, targetUrl);

    if (!(await databaseManager.isDockerAvailable())) {
      throw new Error('Docker no está disponible en este host para importar el volcado SQL');
    }

    // Sin shell interpolado: el SQL entra por stdin a `mariadb --sandbox` dentro del contenedor.
    const argv = ['exec', '-i', dbRecord.containerName, 'sh', '-c', 'MYSQL_PWD="$CULKIBO_MYSQL_PWD" exec "$@"', 'culkibo', 'mariadb', '--sandbox', '-u', 'root', dbRecord.dbName];
    await databaseManager.docker(argv, {
      input: Buffer.from(prepared.sql, 'utf8'),
      timeout: 300000
    });

    // Si el volcado usa un prefijo distinto de `wp_`, aplicarlo automáticamente al contenedor WordPress
    let tablePrefixApplied = false;
    if (prepared.tablePrefix && prepared.tablePrefix !== 'wp_' && typeof /** @type {any} */ (catalogManager).updateEnv === 'function') {
      try {
        await /** @type {any} */ (catalogManager).updateEnv(record.id, { WORDPRESS_TABLE_PREFIX: prepared.tablePrefix });
        tablePrefixApplied = true;
      } catch (e) {}
    }

    return {
      success: true,
      installationId: record.id,
      databaseId: dbRecord.id,
      tablePrefix: prepared.tablePrefix,
      tablePrefixApplied,
      urlsUpdated: prepared.urlsUpdated,
      directReplaced: prepared.directReplaced,
      serializedWarning: prepared.serializedWarning,
      message: prepared.serializedWarning
        ? 'Base de datos importada y siteurl/home actualizados. Detectamos cadenas PHP serializadas: si ves enlaces al dominio antiguo en widgets/Elementor, ejecuta «Better Search Replace» dentro de WordPress.'
        : 'Base de datos WordPress importada y URLs actualizadas correctamente.'
    };
  }
}

const instance = Object.assign(new WordPressMigrator(), {
  WordPressMigrator,
  helpers: { normalizeSiteUrl, slugifySiteName, detectWpTablePrefix, prepareSqlForDomain }
});

module.exports = instance;
