const net = require('net');
const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const localRunner = require('./localRunner');
const { assertSafeUrl, isPrivateIp, isMetadataIp } = require('./ssrfGuard');

/**
 * Importador Universal de Culkibo (cero dependencias externas).
 *
 * Permite traer aplicaciones desde prácticamente cualquier origen:
 *  1. `docker-compose.yml` / `compose.yaml` (pegado o subido)
 *  2. Cualquier URL Git pública o privada (GitHub, GitLab, Bitbucket, Gitea, genérico)
 *  3. Archivos de configuración de Vercel (`vercel.json`), Netlify (`netlify.toml`),
 *     Railway (`railway.json`), Render (`render.yaml`), Dokploy JSON y `.env`
 */

const DB_IMAGE_HINTS = [
  { pattern: /^(?:docker\.io\/library\/)?(?:postgres(?:ql)?|pgvector\/pgvector|postgis\/postgis|timescale\/timescaledb(?:-ha)?)(\b|:|\/)/i, engine: 'postgres', label: 'PostgreSQL' },
  { pattern: /\/(postgres|pgvector|postgis|timescaledb)(\b|:)/i, engine: 'postgres', label: 'PostgreSQL' },
  { pattern: /^(?:docker\.io\/library\/)?mysql(\b|:)/i, engine: 'mysql', label: 'MySQL' },
  { pattern: /^(?:docker\.io\/library\/)?mariadb(\b|:)/i, engine: 'mariadb', label: 'MariaDB' },
  { pattern: /^(?:docker\.io\/library\/)?(?:redis|valkey|valkey\/valkey|dragonflydb\/dragonfly|eqalpha\/keydb)(\b|:|\/)/i, engine: 'valkey', label: 'Valkey / Redis' },
  { pattern: /\/(redis|valkey)(\b|:)/i, engine: 'valkey', label: 'Valkey / Redis' },
  { pattern: /^(?:docker\.io\/library\/)?mongo(\b|:)/i, engine: 'mongodb', label: 'MongoDB' },
  { pattern: /^(?:docker\.io\/)?clickhouse\/clickhouse-server(\b|:)/i, engine: 'clickhouse', label: 'ClickHouse' },
  { pattern: /^(?:docker\.io\/)?qdrant\/qdrant(\b|:)/i, engine: 'qdrant', label: 'Qdrant' }
];

function stripYamlComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i).trimEnd();
    }
  }
  return line.trimEnd();
}

function unquote(val) {
  const s = String(val || '').trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function detectDbEngine(image) {
  const img = String(image || '').trim();
  if (!img) return null;
  for (const h of DB_IMAGE_HINTS) {
    if (h.pattern.test(img)) return { engine: h.engine, label: h.label };
  }
  return null;
}

/**
 * Parsea un bloque `.env` a un mapa clave -> valor y detecta si declara
 * bases de datos o cachés que conviene aprovisionar en Culkibo.
 */
function parseEnvText(envText) {
  /** @type {Record<string, string>} */
  const envVars = {};
  const lines = String(envText || '').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const cleaned = line.startsWith('export ') ? line.slice(7).trim() : line;
    const eq = cleaned.indexOf('=');
    if (eq <= 0) continue;
    const key = cleaned.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let rawVal = cleaned.slice(eq + 1).trim();
    // Eliminar comentarios `# ...` al final de valores sin comillas (convención .env)
    if (rawVal && !rawVal.startsWith('"') && !rawVal.startsWith("'")) {
      rawVal = rawVal.replace(/\s+#.*$/, '').trim();
    }
    const val = unquote(rawVal);
    envVars[key] = val;
  }

  /** @type {Array<{ engine: string, label: string, envKey: string }>} */
  const recommendedDatabases = [];
  const seenEngines = new Set();
  for (const [k, v] of Object.entries(envVars)) {
    const uk = k.toUpperCase();
    const uv = String(v || '').toLowerCase();
    /** @type {{ engine: string, label: string, envKey: string } | null} */
    let match = null;
    if (/POSTGRES|PGHOST|PGDATABASE/.test(uk) || uv.startsWith('postgres://') || uv.startsWith('postgresql://')) {
      match = { engine: 'postgres', label: 'PostgreSQL', envKey: k };
    } else if (/MYSQL|MARIADB/.test(uk) || uv.startsWith('mysql://')) {
      match = { engine: 'mysql', label: 'MySQL / MariaDB', envKey: k };
    } else if (/REDIS|VALKEY/.test(uk) || uv.startsWith('redis://') || uv.startsWith('rediss://')) {
      match = { engine: 'valkey', label: 'Valkey (Redis)', envKey: k };
    } else if (/MONGO/.test(uk) || uv.startsWith('mongodb://') || uv.startsWith('mongodb+srv://')) {
      match = { engine: 'mongodb', label: 'MongoDB', envKey: k };
    } else if (uk === 'DATABASE_URL') {
      match = { engine: 'postgres', label: 'PostgreSQL', envKey: k };
    }
    if (match && !seenEngines.has(match.engine)) {
      seenEngines.add(match.engine);
      recommendedDatabases.push(match);
    }
  }

  return { envVars, recommendedDatabases };
}

/** Parsea un array de flujo YAML inline como `["3000:3000", "8080:80"]` o `[db, redis]`. */
function parseFlowArray(raw) {
  const inner = String(raw || '').trim();
  if (!inner.startsWith('[') || !inner.endsWith(']')) return null;
  const body = inner.slice(1, -1).trim();
  if (!body) return [];
  const items = [];
  let cur = '';
  /** @type {string | null} */
  let q = null;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (q) {
      if (ch === q) q = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      q = ch;
    } else if (ch === ',') {
      if (cur.trim()) items.push(unquote(cur.trim()));
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) items.push(unquote(cur.trim()));
  return items;
}

/** Parsea un mapa de flujo YAML inline como `{ NODE_ENV: production, PORT: "3000" }`. */
function parseFlowMap(raw) {
  const inner = String(raw || '').trim();
  if (!inner.startsWith('{') || !inner.endsWith('}')) return null;
  const body = inner.slice(1, -1).trim();
  /** @type {Record<string, string>} */
  const out = {};
  if (!body) return out;
  const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);
  const parts = parseFlowArray(`[${body}]`) || [];
  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx > 0) {
      const k = unquote(part.slice(0, idx).trim());
      const v = unquote(part.slice(idx + 1).trim());
      if (k && !UNSAFE.has(k)) out[k] = v;
    }
  }
  return out;
}

/** Sustituye expresiones `${VAR:-default}` o `${VAR-default}` por su valor por defecto para extraer puertos reales. */
function expandComposeDefaults(str) {
  return String(str || '').replace(/\$\{[A-Za-z0-9_]+:-?([^}]+)\}/g, '$1');
}

/**
 * Parser ligero de `docker-compose.yml` sin dependencias externas.
 * Soporta listas con indentación cero, arrays/mapas inline (`[...]`, `{...}`),
 * sintaxis larga de `ports:`/`volumes:`, `expose:`, `${PORT:-3000}` y `depends_on` corto/largo.
 */
function parseDockerCompose(yamlText) {
  const text = String(yamlText || '');
  if (!text.trim()) throw new Error('Pega el contenido de tu archivo docker-compose.yml');
  if (text.length > 512 * 1024) throw new Error('El archivo Compose supera el límite de 512 KB');

  const lines = text.split(/\r?\n/);

  // Pre-pasada ligera: capturar anclas de extensión de nivel raíz (`x-common: &common`)
  // para resolver `<<: *common` dentro de los servicios sin dependencias YAML externas.
  /** @type {Map<string, Record<string, any>>} */
  const yamlAnchors = new Map();
  /** @type {string | null} */
  let curAnchor = null;
  let anchorPropIndent = -1;
  /** @type {string | null} */
  let anchorSection = null;
  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;
    const indent = line.search(/\S/);
    const trimmed = line.trim();
    if (indent === 0) {
      const am = trimmed.match(/^x-[a-zA-Z0-9_-]+\s*:\s*&([a-zA-Z0-9_-]+)\s*$/);
      if (am && am[1]) {
        const anchorName = am[1];
        curAnchor = anchorName;
        yamlAnchors.set(anchorName, { envVars: {}, restart: '', image: '', ports: [], volumes: [] });
        anchorPropIndent = -1;
        anchorSection = null;
      } else {
        curAnchor = null;
        anchorSection = null;
      }
      continue;
    }
    if (!curAnchor) continue;
    const target = yamlAnchors.get(curAnchor);
    if (!target) continue;
    if (anchorPropIndent === -1) anchorPropIndent = indent;
    if (indent === anchorPropIndent && !trimmed.startsWith('-')) {
      const m = trimmed.match(/^([a-zA-Z0-9_-]+)\s*:(.*)$/);
      if (!m) continue;
      anchorSection = m[1];
      const rest = m[2].trim();
      if (anchorSection === 'restart' && rest) target.restart = unquote(rest);
      else if (anchorSection === 'image' && rest) target.image = unquote(rest);
      else if (anchorSection === 'environment' && rest) {
        const map = parseFlowMap(rest);
        if (map) Object.assign(target.envVars, map);
      }
    } else if (anchorSection === 'environment') {
      if (trimmed.startsWith('-')) {
        const item = unquote(trimmed.slice(1).trim());
        const eq = item.indexOf('=');
        if (eq > 0) target.envVars[item.slice(0, eq).trim()] = unquote(item.slice(eq + 1));
      } else {
        const eq = trimmed.indexOf(':');
        if (eq > 0) {
          const k = trimmed.slice(0, eq).trim();
          if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) target.envVars[k] = unquote(trimmed.slice(eq + 1).trim());
        }
      }
    }
  }

  /** @type {any[]} */
  const services = [];
  let inServices = false;
  let servicesIndent = -1;
  let serviceIndent = -1;
  let propIndent = -1;
  /** @type {any} */
  let currentService = null;
  /** @type {string | null} */
  let currentSection = null;
  let dependsOnIndent = -1;
  /** @type {any} */
  let longFormItem = null;

  const flushLongForm = () => {
    if (!longFormItem || !currentService) { longFormItem = null; return; }
    if (longFormItem.section === 'ports' && longFormItem.target) {
      const pub = longFormItem.published ? `${longFormItem.host_ip ? `${longFormItem.host_ip}:` : ''}${longFormItem.published}:` : '';
      currentService.ports.push(`${pub}${longFormItem.target}`);
    } else if (longFormItem.section === 'volumes' && longFormItem.target) {
      currentService.volumes.push(`${longFormItem.source || currentService.name}:${longFormItem.target}`);
    }
    longFormItem = null;
  };

  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;
    const indent = line.search(/\S/);
    const trimmed = line.trim();

    if (indent === 0) {
      flushLongForm();
      if (/^services\s*:/.test(trimmed)) {
        inServices = true;
        servicesIndent = 0;
        serviceIndent = -1;
        currentService = null;
        currentSection = null;
      } else {
        inServices = false;
        currentService = null;
        currentSection = null;
      }
      continue;
    }

    if (!inServices) continue;

    if (serviceIndent === -1 && indent > servicesIndent && /^[a-zA-Z0-9_.-]+\s*:$/.test(trimmed)) {
      serviceIndent = indent;
    }

    if (indent === serviceIndent && /^[a-zA-Z0-9_.-]+\s*:$/.test(trimmed)) {
      flushLongForm();
      const name = trimmed.slice(0, -1).trim();
      currentService = {
        name,
        image: '',
        build: null,
        ports: [],
        expose: [],
        volumes: [],
        envVars: {},
        dependsOn: [],
        restart: '',
        command: '',
        warnings: []
      };
      services.push(currentService);
      currentSection = null;
      propIndent = -1;
      continue;
    }

    if (!currentService) continue;

    if (propIndent === -1 && indent > serviceIndent) {
      propIndent = indent;
    }

    // Listas con indentación cero respecto a su clave (p. ej. `ports:\n- "3000:3000"`)
    const isZeroIndentSeq = indent === propIndent && trimmed.startsWith('-') && Boolean(currentSection);

    if (indent === propIndent && !isZeroIndentSeq) {
      flushLongForm();
      const mergeMatch = trimmed.match(/^<<\s*:\s*\*([a-zA-Z0-9_-]+)$/);
      if (mergeMatch) {
        const anchor = yamlAnchors.get(mergeMatch[1]);
        if (anchor) {
          if (anchor.restart && !currentService.restart) currentService.restart = anchor.restart;
          if (anchor.image && !currentService.image) currentService.image = anchor.image;
          Object.assign(currentService.envVars, anchor.envVars);
        }
        continue;
      }
      const m = trimmed.match(/^([a-zA-Z0-9_-]+)\s*:(.*)$/);
      if (!m) continue;
      const key = m[1];
      const rest = m[2].trim();
      currentSection = key;
      dependsOnIndent = -1;

      if (key === 'image' && rest) currentService.image = unquote(rest);
      else if (key === 'restart' && rest) currentService.restart = unquote(rest);
      else if (key === 'command' && rest) {
        const arr = parseFlowArray(rest);
        currentService.command = arr ? arr.join(' ') : unquote(rest);
      } else if (key === 'build' && rest) currentService.build = unquote(rest);
      else if (key === 'ports' && rest) {
        const arr = parseFlowArray(rest);
        if (arr) currentService.ports.push(...arr);
      } else if (key === 'expose' && rest) {
        const arr = parseFlowArray(rest);
        if (arr) currentService.expose.push(...arr);
      } else if (key === 'volumes' && rest) {
        const arr = parseFlowArray(rest);
        if (arr) currentService.volumes.push(...arr);
      } else if (key === 'depends_on' && rest) {
        const arr = parseFlowArray(rest);
        if (arr) currentService.dependsOn.push(...arr);
      } else if (key === 'environment' && rest) {
        const map = parseFlowMap(rest);
        if (map) Object.assign(currentService.envVars, map);
        else {
          const arr = parseFlowArray(rest);
          if (arr) {
            for (const item of arr) {
              const eq = item.indexOf('=');
              if (eq > 0) currentService.envVars[item.slice(0, eq).trim()] = unquote(item.slice(eq + 1));
            }
          }
        }
      }
      continue;
    }

    if ((indent > propIndent || isZeroIndentSeq) && currentSection) {
      if (currentSection === 'build') {
        const ctx = trimmed.match(/^context\s*:\s*(.+)$/);
        if (ctx) currentService.build = unquote(ctx[1]);
      } else if (currentSection === 'ports') {
        if (trimmed.startsWith('-')) {
          flushLongForm();
          const item = trimmed.slice(1).trim();
          const kv = item.match(/^(target|published|host_ip|protocol)\s*:\s*(.+)$/);
          if (kv) {
            longFormItem = { section: 'ports', [kv[1]]: unquote(kv[2]) };
          } else {
            const val = unquote(item);
            if (val) currentService.ports.push(val);
          }
        } else if (longFormItem && longFormItem.section === 'ports') {
          const kv = trimmed.match(/^(target|published|host_ip|protocol)\s*:\s*(.+)$/);
          if (kv) longFormItem[kv[1]] = unquote(kv[2]);
        }
      } else if (currentSection === 'expose' && trimmed.startsWith('-')) {
        const val = unquote(trimmed.slice(1).trim());
        if (val) currentService.expose.push(val);
      } else if (currentSection === 'volumes') {
        if (trimmed.startsWith('-')) {
          flushLongForm();
          const item = trimmed.slice(1).trim();
          const kv = item.match(/^(type|source|target|read_only)\s*:\s*(.+)$/);
          if (kv) {
            longFormItem = { section: 'volumes', [kv[1]]: unquote(kv[2]) };
          } else {
            const val = unquote(item);
            if (val) currentService.volumes.push(val);
          }
        } else if (longFormItem && longFormItem.section === 'volumes') {
          const kv = trimmed.match(/^(type|source|target|read_only)\s*:\s*(.+)$/);
          if (kv) longFormItem[kv[1]] = unquote(kv[2]);
        }
      } else if (currentSection === 'depends_on') {
        if (trimmed.startsWith('-')) {
          const dep = unquote(trimmed.slice(1).trim());
          if (dep) currentService.dependsOn.push(dep);
        } else {
          if (dependsOnIndent === -1) dependsOnIndent = indent;
          if (indent === dependsOnIndent) {
            const dm = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:/);
            if (dm) currentService.dependsOn.push(dm[1]);
          }
        }
      } else if (currentSection === 'environment') {
        const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
        if (trimmed.startsWith('-')) {
          const item = unquote(trimmed.slice(1).trim());
          const eq = item.indexOf('=');
          if (eq > 0) {
            const k = item.slice(0, eq).trim();
            if (k && !UNSAFE_KEYS.has(k)) currentService.envVars[k] = unquote(item.slice(eq + 1));
          } else if (item && !UNSAFE_KEYS.has(item)) {
            currentService.envVars[item] = '';
          }
        } else {
          const eq = trimmed.indexOf(':');
          if (eq > 0) {
            const k = trimmed.slice(0, eq).trim();
            const v = unquote(trimmed.slice(eq + 1).trim());
            if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) && !UNSAFE_KEYS.has(k)) currentService.envVars[k] = v;
          }
        }
      }
    }
  }
  flushLongForm();

  if (services.length === 0) {
    throw new Error('No se encontró ningún servicio bajo la clave `services:` en el YAML proporcionado');
  }

  for (const svc of services) {
    const db = detectDbEngine(svc.image);
    svc.kind = db ? 'database' : 'app';
    svc.dbEngine = db ? db.engine : null;
    svc.dbLabel = db ? db.label : null;

    /** @type {number | null} */
    let containerPort = null;
    for (const p of svc.ports) {
      const clean = expandComposeDefaults(String(p)).replace(/\/(tcp|udp)$/i, '');
      const parts = clean.split(':');
      if (parts.length === 2 && !parts[0].startsWith('127.0.0.1')) {
        svc.warnings.push(`El puerto ${p} se expondría en 0.0.0.0; en Culkibo se aislará tras Caddy.`);
      } else if (parts.length === 3 && parts[0] === '0.0.0.0') {
        svc.warnings.push(`El puerto ${p} se expondría en 0.0.0.0; en Culkibo se aislará tras Caddy.`);
      }
      if (containerPort === null) {
        const last = parseInt(parts[parts.length - 1], 10);
        if (Number.isInteger(last) && last > 0 && last < 65536) {
          containerPort = last;
        }
      }
    }
    if (containerPort === null && Array.isArray(svc.expose) && svc.expose.length > 0) {
      const exp = parseInt(expandComposeDefaults(String(svc.expose[0])).replace(/\/(tcp|udp)$/i, ''), 10);
      if (Number.isInteger(exp) && exp > 0 && exp < 65536) containerPort = exp;
    }
    svc.containerPort = containerPort;

    for (const vol of svc.volumes || []) {
      const vStr = String(vol || '').trim();
      const hostSide = vStr.split(':')[0] || '';
      const isSensitiveMount = vStr.includes('/var/run/docker.sock')
        || vStr.startsWith('/:')
        || /^\/(?:etc|root|proc|sys|var\/lib\/docker)(?:\/|$)/.test(hostSide);
      if (isSensitiveMount) {
        svc.warnings.push(`Montaje privilegiado detectado (${vStr}): revisa si este servicio realmente necesita acceso al host.`);
      }
    }

    if (svc.image && (/:latest$/i.test(svc.image) || !svc.image.includes(':'))) {
      svc.warnings.push(`La imagen «${svc.image}» no tiene versión fijada (evita :latest en producción).`);
    }
    if (db) {
      svc.warnings.push(`Recomendación: puedes gestionar ${db.label} como Base de Datos nativa de Culkibo con copias automáticas y cifrado.`);
    }
  }

  return {
    success: true,
    servicesCount: services.length,
    appsCount: services.filter(s => s.kind === 'app').length,
    databasesCount: services.filter(s => s.kind === 'database').length,
    services
  };
}

/**
 * Parsea la configuración de plataformas externas (Vercel, Netlify, Railway, Render, Dokploy)
 * junto a variables `.env` opcionales.
 */
function parsePlatformConfig({ platform = 'auto', configText = '', envText = '' } = {}) {
  const raw = String(configText || '').trim();
  const { envVars: pastedEnv, recommendedDatabases } = parseEnvText(envText);

  let detectedPlatform = String(platform || 'auto').toLowerCase();
  if (detectedPlatform === 'auto') {
    if (raw.includes('[deploy]') && (raw.includes('startCommand') || raw.includes('healthcheckPath') || raw.includes('builder'))) detectedPlatform = 'railway';
    else if (raw.includes('[build]') || raw.includes('publish =')) detectedPlatform = 'netlify';
    else if (raw.includes('services:') && (raw.includes('buildCommand:') || raw.includes('startCommand:'))) detectedPlatform = 'render';
    else if (raw.startsWith('{')) {
      try {
        const obj = JSON.parse(raw);
        if (obj.rewrites || obj.builds || obj.outputDirectory || obj.framework) detectedPlatform = 'vercel';
        else if (obj.deploy || obj.build?.builder) detectedPlatform = 'railway';
        else if (obj.repository || obj.applicationId || obj.domains) detectedPlatform = 'dokploy';
      } catch (e) {}
    }
  }

  /** @type {any} */
  const result = {
    platform: detectedPlatform,
    name: '',
    gitRepo: '',
    gitBranch: 'main',
    framework: null,
    buildCommand: '',
    startCommand: '',
    outputDirectory: '',
    baseDirectory: '/',
    healthPath: '/',
    port: 3000,
    domains: [],
    envVars: { ...pastedEnv },
    recommendedDatabases,
    notes: []
  };

  if (raw && detectedPlatform === 'railway' && !raw.startsWith('{')) {
    // Soporte railway.toml
    const buildM = raw.match(/^\s*buildCommand\s*=\s*["']([^"']+)["']/m);
    const startM = raw.match(/^\s*startCommand\s*=\s*["']([^"']+)["']/m);
    const healthM = raw.match(/^\s*healthcheckPath\s*=\s*["']([^"']+)["']/m);
    if (buildM) result.buildCommand = buildM[1];
    if (startM) result.startCommand = startM[1];
    if (healthM) result.healthPath = healthM[1];
    result.notes.push('Culkibo leyó tu railway.toml y aplica límites de memoria, healthchecks y despliegue sin cortes.');
  } else if (raw && (detectedPlatform === 'vercel' || detectedPlatform === 'railway' || detectedPlatform === 'dokploy')) {
    let json;
    try {
      json = JSON.parse(raw);
    } catch (e) {
      throw new Error(`El archivo de configuración de ${detectedPlatform} no es un JSON válido`);
    }

    if (detectedPlatform === 'vercel') {
      result.framework = json.framework || null;
      result.buildCommand = json.buildCommand || 'npm run build';
      result.outputDirectory = json.outputDirectory || (json.framework === 'nextjs' ? '.next' : 'dist');
      if (json.rootDirectory) result.baseDirectory = String(json.rootDirectory);
      result.port = json.framework === 'nextjs' ? 3000 : 80;
      if (json.env && typeof json.env === 'object') {
        Object.assign(result.envVars, json.env);
      }
      result.notes.push('Las funciones serverless propietarias de Vercel se ejecutan en Culkibo como servidor Node/Next.js estándar sin límites de timeout.');
    } else if (detectedPlatform === 'railway') {
      result.buildCommand = json.build?.buildCommand || '';
      result.startCommand = json.deploy?.startCommand || '';
      result.healthPath = json.deploy?.healthcheckPath || '/';
      result.notes.push('Culkibo aplica automáticamente límites de memoria, healthchecks y despliegue sin cortes equivalentes a Railway.');
    } else if (detectedPlatform === 'dokploy') {
      result.name = json.name || json.appName || '';
      result.gitRepo = json.repository || json.customGitUrl || '';
      result.gitBranch = json.branch || json.customGitBranch || 'main';
      result.baseDirectory = json.buildPath || '/';
      result.buildCommand = json.buildCommand || '';
      result.startCommand = json.startCommand || '';
      if (typeof json.env === 'string') {
        Object.assign(result.envVars, parseEnvText(json.env).envVars);
      } else if (json.env && typeof json.env === 'object') {
        Object.assign(result.envVars, json.env);
      }
      if (Array.isArray(json.domains)) {
        result.domains = json.domains.map(d => (typeof d === 'string' ? d : d?.host)).filter(Boolean);
      }
    }
  } else if (raw && detectedPlatform === 'netlify') {
    const cmdMatch = raw.match(/^\s*command\s*=\s*["']([^"']+)["']/m);
    const pubMatch = raw.match(/^\s*publish\s*=\s*["']([^"']+)["']/m);
    const baseMatch = raw.match(/^\s*base\s*=\s*["']([^"']+)["']/m);
    if (cmdMatch) result.buildCommand = cmdMatch[1];
    if (pubMatch) result.outputDirectory = pubMatch[1];
    if (baseMatch) result.baseDirectory = baseMatch[1];
    result.port = 80;
    const envBlock = raw.match(/\[build\.environment\]([\s\S]*?)(\n\[|$)/);
    if (envBlock) {
      for (const m of envBlock[1].matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\r\n]+)["']?/gm)) {
        result.envVars[m[1]] = m[2].trim();
      }
    }
    result.notes.push('Los sitios estáticos de Netlify se empaquetan en Culkibo con Nginx + compresión + fallback SPA automático.');
  } else if (raw && detectedPlatform === 'render') {
    const nameMatch = raw.match(/^\s*-?\s*name\s*:\s*([^\r\n#]+)/m);
    const buildMatch = raw.match(/^\s*buildCommand\s*:\s*([^\r\n#]+)/m);
    const startMatch = raw.match(/^\s*startCommand\s*:\s*([^\r\n#]+)/m);
    const healthMatch = raw.match(/^\s*healthCheckPath\s*:\s*([^\r\n#]+)/m);
    const rootMatch = raw.match(/^\s*rootDir\s*:\s*([^\r\n#]+)/m);
    if (nameMatch) result.name = unquote(nameMatch[1]);
    if (buildMatch) result.buildCommand = unquote(buildMatch[1]);
    if (startMatch) result.startCommand = unquote(startMatch[1]);
    if (healthMatch) result.healthPath = unquote(healthMatch[1]);
    if (rootMatch) result.baseDirectory = unquote(rootMatch[1]);
    // Extraer pares key/value dentro de envVars en render.yaml
    for (const m of raw.matchAll(/-\s*key\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\r?\n\s*value\s*:\s*([^\r\n#]+)/g)) {
      result.envVars[m[1]] = unquote(m[2]);
    }
  }

  return { success: true, ...result };
}

class UniversalImporter {
  parseDockerCompose(yamlText) {
    return parseDockerCompose(yamlText);
  }

  parsePlatformConfig(opts) {
    return parsePlatformConfig(opts);
  }

  /**
   * Importa servicios de un `docker-compose.yml` como un proyecto Culkibo listo para gestionar.
   * @param {{ yamlText?: string, projectName?: string, selectedServices?: string[] }} [opts]
   */
  async importDockerCompose({ yamlText = '', projectName = '', selectedServices = [] } = {}) {
    const parsed = parseDockerCompose(yamlText);
    const chosen = Array.isArray(selectedServices) && selectedServices.length > 0
      ? parsed.services.filter(s => selectedServices.includes(s.name))
      : parsed.services;

    if (chosen.length === 0) {
      throw new Error('Selecciona al menos un servicio del archivo Compose para importar');
    }

    const primaryApp = chosen.find(s => s.kind === 'app') || chosen[0];
    // Aislamiento de variables por servicio: sólo las variables de la app principal van al Project raíz
    // (evita filtrar MYSQL_ROOT_PASSWORD o POSTGRES_PASSWORD de una BD hacia la app web).
    const primaryEnv = { ...(primaryApp.envVars || {}) };
    const mergedVolumes = [];
    for (const svc of chosen) {
      for (const vol of svc.volumes || []) {
        const [source, target] = String(vol).split(':');
        mergedVolumes.push({ name: source || svc.name, mount_path: target || source });
      }
    }

    const project = projectManager.create({
      name: String(projectName || primaryApp.name || 'Stack Docker Compose').slice(0, 80),
      description: `Stack importado desde Docker Compose (${chosen.length} servicio${chosen.length === 1 ? '' : 's'}).`,
      icon: '🐳',
      source: 'compose-import',
      containerPort: primaryApp.containerPort || 8080,
      citadelPort: primaryApp.containerPort || 8080,
      envVars: primaryEnv,
      volumes: mergedVolumes,
      resources: chosen.map((svc, idx) => ({
        id: `compose_${svc.name}`,
        type: svc.kind === 'database' ? 'database' : 'service',
        name: svc.name,
        description: svc.image ? `Imagen ${svc.image}` : `Build desde ${svc.build || '.'}`,
        image: svc.image,
        ports: svc.ports.join(', '),
        envVars: svc.envVars,
        volumes: svc.volumes,
        // Guardar el YAML una única vez (en el recurso principal) para no multiplicar el tamaño de projects.json
        ...(idx === 0 ? { dockerCompose: yamlText } : {}),
        warnings: svc.warnings,
        status: 'stopped'
      }))
    });

    return {
      success: true,
      project,
      importedServices: chosen.length,
      databasesDetected: chosen.filter(s => s.kind === 'database').map(s => ({ name: s.name, engine: s.dbEngine, label: s.dbLabel })),
      warnings: chosen.flatMap(s => s.warnings.map(w => `[${s.name}] ${w}`))
    };
  }

  /**
   * Inspecciona cualquier URL de repositorio Git (GitHub, GitLab, Bitbucket, Gitea, HTTPS)
   * sin exigir que el usuario tenga una cuenta de GitHub conectada previamente.
   */
  async inspectGitUrl(rawGitUrl, { branch = '' } = {}) {
    const input = String(rawGitUrl || '').trim();
    if (!input) throw new Error('Introduce la URL de un repositorio Git');

    let normalized = input;
    // Soportar atajo `owner/repo` -> GitHub HTTPS
    if (/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/.test(input)) {
      normalized = `https://github.com/${input.replace(/\.git$/, '')}`;
    } else {
      const sshM = input.match(/^git@([^:]+):(.+)$/);
      if (sshM) normalized = `https://${sshM[1]}/${sshM[2].replace(/\.git$/, '')}`;
    }

    const { url: parsed } = await assertSafeUrl(normalized);
    const host = parsed.hostname.toLowerCase();
    if (host === 'localhost' || isMetadataIp(host) || (net.isIP(host) && isPrivateIp(host))) {
      throw new Error('URL de repositorio bloqueada por protección SSRF');
    }

    let cleanPathname = parsed.pathname.replace(/^\/+|\/+$/g, '');
    let extractedBranch = branch || '';
    // Soportar URLs copiadas desde el navegador con `/tree/<branch>` (GitHub) o `/-/tree/<branch>` (GitLab)
    const ghTreeM = cleanPathname.match(/^([^/]+\/[^/]+)\/tree\/([^/?#]+)(?:\/.*)?$/);
    const glTreeM = cleanPathname.match(/^(.+?)\/-\/tree\/([^/?#]+)(?:\/.*)?$/);
    if (glTreeM) {
      cleanPathname = glTreeM[1];
      if (!extractedBranch) extractedBranch = decodeURIComponent(glTreeM[2]);
    } else if (ghTreeM) {
      cleanPathname = ghTreeM[1];
      if (!extractedBranch) extractedBranch = decodeURIComponent(ghTreeM[2]);
    }

    const segments = cleanPathname.replace(/\.git$/, '').split('/').filter(Boolean);
    const owner = segments[0] || '';
    const repo = segments[segments.length - 1] || 'app';

    let provider = 'git';
    if (host === 'github.com') provider = 'github';
    else if (host === 'gitlab.com' || host.includes('gitlab')) provider = 'gitlab';
    else if (host === 'bitbucket.org') provider = 'bitbucket';
    else if (host.includes('codeberg.org') || host.includes('gitea')) provider = 'gitea';

    const cleanRepoUrl = `${parsed.origin}/${cleanPathname.replace(/\.git$/, '')}.git`;
    /** @type {any} */
    const info = {
      success: true,
      provider,
      host,
      owner,
      repo,
      suggestedName: repo,
      cloneUrl: cleanRepoUrl,
      defaultBranch: extractedBranch || 'main',
      description: '',
      language: null,
      isPrivate: false,
      framework: null,
      buildCommand: '',
      startCommand: '',
      port: 3000,
      icon: '🚀',
      verifiedPublic: false
    };

    // Autodetección en vivo para repos públicos (y privados si hay PAT de GitHub conectado).
    if (provider === 'github' && owner && repo) {
      try {
        /** @type {Record<string, string>} */
        const ghHeaders = { 'User-Agent': 'Culkibo-Importer/1.0', Accept: 'application/vnd.github.v3+json' };
        try {
          const gh = require('./githubService');
          if (gh && gh.config && gh.config.token && !gh.isMockToken(gh.config.token)) {
            ghHeaders.Authorization = `Bearer ${gh.config.token}`;
          }
        } catch (e) {}
        const metaRes = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
          headers: ghHeaders,
          signal: AbortSignal.timeout(6000)
        });
        if (metaRes.ok) {
          /** @type {any} */
          const meta = await metaRes.json();
          info.verifiedPublic = true;
          info.defaultBranch = branch || meta.default_branch || 'main';
          info.description = meta.description || '';
          info.language = meta.language || null;
          info.isPrivate = Boolean(meta.private);

          const filesRes = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents?ref=${encodeURIComponent(info.defaultBranch)}`, {
            headers: ghHeaders,
            signal: AbortSignal.timeout(6000)
          });
          if (filesRes.ok) {
            const files = await filesRes.json();
            if (Array.isArray(files)) {
              const names = new Set(files.map(f => String(f.name || '').toLowerCase()));
              this.inferStackFromFiles(names, info);
            }
          }
        } else if (metaRes.status === 404) {
          info.isPrivate = true;
        }
      } catch (e) {}
    } else if (provider === 'gitlab' && host === 'gitlab.com' && segments.length >= 2) {
      try {
        const projectPath = encodeURIComponent(segments.join('/'));
        const metaRes = await fetch(`https://gitlab.com/api/v4/projects/${projectPath}`, {
          signal: AbortSignal.timeout(6000)
        });
        if (metaRes.ok) {
          /** @type {any} */
          const meta = await metaRes.json();
          info.verifiedPublic = true;
          info.defaultBranch = branch || meta.default_branch || 'main';
          info.description = meta.description || '';
          info.isPrivate = meta.visibility !== 'public';
        }
      } catch (e) {}
    }

    return info;
  }

  inferStackFromFiles(names, info) {
    if (names.has('docker-compose.yml') || names.has('compose.yaml')) {
      info.framework = 'Docker Compose';
      info.port = 8080;
      info.icon = '🐳';
    } else if (names.has('dockerfile')) {
      info.framework = 'Dockerfile';
      info.port = 8080;
      info.icon = '🐳';
    } else if (names.has('next.config.js') || names.has('next.config.mjs') || names.has('next.config.ts')) {
      info.framework = 'Next.js';
      info.buildCommand = 'npm run build';
      info.startCommand = 'npm start';
      info.port = 3000;
      info.icon = '▲';
    } else if (names.has('vite.config.ts') || names.has('vite.config.js') || names.has('vite.config.mjs')) {
      info.framework = 'Vite / React';
      info.buildCommand = 'npm run build';
      info.startCommand = 'npx vite preview --host 0.0.0.0 --port 4173';
      info.port = 4173;
      info.icon = '⚡';
    } else if (names.has('package.json')) {
      info.framework = 'Node.js';
      info.buildCommand = 'npm run build';
      info.startCommand = 'npm start';
      info.port = 3000;
      info.icon = '🟢';
    } else if (names.has('requirements.txt') || names.has('pyproject.toml')) {
      info.framework = 'Python';
      info.buildCommand = 'pip install -r requirements.txt';
      info.startCommand = 'python main.py';
      info.port = 8000;
      info.icon = '🐍';
    } else if (names.has('go.mod')) {
      info.framework = 'Go';
      info.buildCommand = 'go build -o server .';
      info.startCommand = './server';
      info.port = 8080;
      info.icon = '🔷';
    } else if (names.has('cargo.toml')) {
      info.framework = 'Rust';
      info.buildCommand = 'cargo build --release';
      info.port = 8080;
      info.icon = '🦀';
    } else if (names.has('index.html')) {
      info.framework = 'Web estática';
      info.port = 80;
      info.icon = '🌐';
    }
  }

  /**
   * Crea un proyecto a partir de la importación de plataforma / URL Git, opcionalmente
   * pre-clonando el repositorio y registrando dominios.
   */
  async createImportedProject(payload = {}) {
    const cleanName = String(payload.name || 'Proyecto Importado').trim().slice(0, 80);
    const gitRepo = String(payload.gitRepo || '').trim();
    if (gitRepo) {
      const normalized = localRunner.normalizeGitUrl(gitRepo);
      if (!normalized) throw new Error('La URL de repositorio Git no es válida o está bloqueada');
    }

    const project = projectManager.create({
      name: cleanName,
      description: String(payload.description || `Importado desde ${payload.platform || 'Git'}`).slice(0, 300),
      icon: payload.icon || '🚀',
      source: payload.source || 'universal-import',
      gitRepo,
      gitBranch: String(payload.gitBranch || 'main').trim() || 'main',
      buildCommand: String(payload.buildCommand || ''),
      startCommand: String(payload.startCommand || ''),
      baseDirectory: String(payload.baseDirectory || '/'),
      healthPath: String(payload.healthPath || '/'),
      containerPort: Number(payload.port) || 3000,
      citadelPort: Number(payload.port) || 3000,
      envVars: payload.envVars && typeof payload.envVars === 'object' ? payload.envVars : {},
      domains: []
    });

    if (Array.isArray(payload.domains)) {
      for (const rawHost of payload.domains.slice(0, 10)) {
        const host = String(rawHost || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
        if (!host) continue;
        try {
          await domainManager.addDomain({
            hostname: host,
            projectId: project.id,
            targetPod: 'citadel',
            targetPort: project.citadelPort,
            cloudflareProxied: false,
            routingMode: 'direct_dns'
          });
          project.domains.push(host);
        } catch (e) {}
      }
      if (project.domains.length > 0) {
        projectManager.update(project.id, { domains: project.domains });
        try { await require('./ingressManager').reconcile(); } catch (e) {}
      }
    }

    return { success: true, project };
  }
}

const instance = Object.assign(new UniversalImporter(), {
  UniversalImporter,
  parseDockerCompose,
  parsePlatformConfig,
  parseEnvText
});

module.exports = instance;
