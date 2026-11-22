const dns = require('dns').promises;
const net = require('net');
const catalogManager = require('./catalogManager');
const databaseManager = require('./databaseManager');
const { assertSafeUrl } = require('./ssrfGuard');

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
 */
function detectWpTablePrefix(sql) {
  const m = sql.match(/(?:CREATE\s+TABLE|INSERT\s+INTO)\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)options`?/i);
  if (m && /^[a-zA-Z0-9_]{1,24}$/.test(m[1])) return m[1];
  return 'wp_';
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

  const prefix = detectWpTablePrefix(sql);
  const escapedUrl = cleanNew.replace(/'/g, "''");
  const hasSerialized = /a:\d+:\{|s:\d+:"/.test(sql);
  let output = sql;

  // Si conocemos el dominio viejo y no hay referencias serializadas del host,
  // reemplazamos URLs directas; en cualquier caso fijamos `siteurl` y `home`.
  let directReplaced = false;
  const cleanOldHost = String(oldDomain || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
  const cleanNewHost = cleanNew.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();

  if (cleanOldHost && cleanNewHost && cleanOldHost !== cleanNewHost && !hasSerialized) {
    const escapedOld = cleanOldHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    output = output.replace(new RegExp(`https?://${escapedOld}`, 'gi'), cleanNew);
    directReplaced = true;
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

    // Lanzar en paralelo: portada HTML, /wp-json, /wp-json/wp/v2/types y DNS A.
    const [homeRes, wpJsonRes, typesRes, dnsRes] = await Promise.allSettled([
      fetch(parsedUrl.toString(), { headers, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) }),
      fetch(`${baseOrigin}/wp-json`, { headers: { ...headers, Accept: 'application/json' }, redirect: 'follow', signal: AbortSignal.timeout(Math.min(timeoutMs, 5000)) }),
      fetch(`${baseOrigin}/wp-json/wp/v2/types`, { headers: { ...headers, Accept: 'application/json' }, redirect: 'follow', signal: AbortSignal.timeout(Math.min(timeoutMs, 5000)) }),
      dns.resolve4(parsedUrl.hostname).catch(() => [])
    ]);

    if (homeRes.status === 'rejected') {
      throw new Error(`No se pudo conectar con ${baseOrigin}: ${homeRes.reason?.message || 'sin respuesta'}`);
    }

    const res = homeRes.value;
    const finalUrl = res.url || parsedUrl.toString();
    const html = await readBoundedText(res, MAX_HTML_BYTES);
    const resolvedIps = dnsRes.status === 'fulfilled' && Array.isArray(dnsRes.value) ? dnsRes.value : [];

    // Parseo de /wp-json si está expuesto.
    /** @type {any} */
    let wpJson = null;
    if (wpJsonRes.status === 'fulfilled' && wpJsonRes.value.ok) {
      try {
        const text = await readBoundedText(wpJsonRes.value, 512 * 1024);
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') wpJson = parsed;
      } catch (e) {}
    }

    /** @type {string[]} */
    let postTypes = [];
    if (typesRes.status === 'fulfilled' && typesRes.value.ok) {
      try {
        const text = await readBoundedText(typesRes.value, 256 * 1024);
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') postTypes = Object.keys(parsed);
      } catch (e) {}
    }

    // Detectar señales reales de WordPress.
    const linkHeader = res.headers.get('link') || '';
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

    const usesHttps = finalUrl.startsWith('https://');
    const usesCloudflare = Boolean(res.headers.get('cf-ray')) || resolvedIps.some(isCloudflareIp);
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
      serverHeader: res.headers.get('server') || null,
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
   * Restaura un volcado `.sql` dentro de la base MariaDB de una instalación de WordPress.
   *
   * @param {{ installationId: string, sqlContent: string, oldDomain?: string, newDomain?: string }} opts
   */
  async importSqlDump({ installationId, sqlContent, oldDomain = '', newDomain = '' }) {
    const record = catalogManager.mustGet(installationId);
    if (record.templateId !== 'wordpress') {
      throw new Error(`La instalación «${installationId}» no es de WordPress`);
    }
    if (!record.databaseId) {
      throw new Error('Esta instalación de WordPress no tiene una base de datos MariaDB asociada todavía');
    }
    if (typeof sqlContent !== 'string' || !sqlContent.trim()) {
      throw new Error('El archivo SQL está vacío');
    }
    if (Buffer.byteLength(sqlContent, 'utf8') > MAX_SQL_BYTES) {
      throw new Error('El volcado SQL supera el límite de 50 MB para importación directa; usa All-in-One WP Migration o restauración por CLI');
    }

    const dbRecord = databaseManager.mustGet(record.databaseId);
    const targetUrl = newDomain || record.url;
    const prepared = prepareSqlForDomain(sqlContent, oldDomain, targetUrl);

    if (!(await databaseManager.isDockerAvailable())) {
      throw new Error('Docker no está disponible en este host para importar el volcado SQL');
    }

    // Sin shell interpolado: el SQL entra por stdin al proceso `mariadb` dentro del contenedor.
    const argv = ['exec', '-i', dbRecord.containerName, 'sh', '-c', 'MYSQL_PWD="$CULKIBO_MYSQL_PWD" exec "$@"', 'culkibo', 'mariadb', '-u', 'root', dbRecord.dbName];
    await databaseManager.docker(argv, {
      input: Buffer.from(prepared.sql, 'utf8'),
      timeout: 300000
    });

    return {
      success: true,
      installationId: record.id,
      databaseId: dbRecord.id,
      tablePrefix: prepared.tablePrefix,
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
