const crypto = require('crypto');
const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const localRunner = require('./localRunner');
const { assertSafeUrl, safeFetch } = require('./ssrfGuard');
const { parseCron } = require('./cronParser');
const { parseSafeCommandArgv } = require('./safeCommand');
const { isBcryptHash } = require('./bcryptHash');

/** Carga perezosa de módulos opcionales para mantener 0 MB RAM extra en arranque. */
/** @type {any} */
let _caddyManager = null;
function getCaddyManager() {
  if (!_caddyManager) _caddyManager = require('./caddyManager');
  return _caddyManager;
}

/** @type {any} */
let _cronManager = null;
function getCronManager() {
  if (!_cronManager) {
    try { _cronManager = require('./cronManager'); } catch (e) {}
  }
  return _cronManager;
}

/** @type {any} */
let _bundleArchiver = null;
function getBundleArchiver() {
  if (!_bundleArchiver) _bundleArchiver = require('./bundleArchiver');
  return _bundleArchiver;
}

const COOLIFY_SENSITIVE_META_RE = /(password|passwd|secret|token|private_key|api_key|apikey|credential|environment_variables|docker_compose_raw)/i;
const SENSITIVE_ENV_KEY_RE = /(secret|token|pass(word|wd|phrase)?|apikey|api_key|private|auth|cred(ential)?|jwt|cookie|session|cert|pem|dsn|database_url|db_url|redis_url|mongo_url|smtp|webhook|stripe|openai|anthropic|gemini|aws_|s3_|r2_|encryption|signing|master)/i;
const HOP_BY_HOP_HEADER_RE = /^(host|content-length|transfer-encoding|connection|keep-alive|upgrade|proxy-authenticate|proxy-authorization|te|trailer)$/i;
const HEADER_NAME_RE = /^[A-Za-z0-9-]+$/;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Frecuencias simbólicas de Scheduled Tasks de Coolify v4 → expresión cron de 5 campos. */
const COOLIFY_CRON_ALIASES = Object.freeze({
  every_minute: '* * * * *',
  'every_five_minutes': '*/5 * * * *',
  'every_ten_minutes': '*/10 * * * *',
  'every_fifteen_minutes': '*/15 * * * *',
  'every_thirty_minutes': '*/30 * * * *',
  hourly: '0 * * * *',
  daily: '0 0 * * *',
  weekly: '0 0 * * 0',
  monthly: '0 0 1 * *',
  yearly: '0 0 1 1 *',
  '@hourly': '0 * * * *',
  '@daily': '0 0 * * *',
  '@midnight': '0 0 * * *',
  '@weekly': '0 0 * * 0',
  '@monthly': '0 0 1 * *',
  '@yearly': '0 0 1 1 *',
  '@annually': '0 0 1 1 *'
});

/** Metadatos de paridad y volcado para los 8 motores de BD de Coolify v4. */
const DB_ENGINE_CATALOG = Object.freeze({
  postgres: {
    engine: 'postgres',
    label: 'PostgreSQL',
    defaultPort: 5432,
    defaultImage: 'postgres:18-alpine',
    parity: 'full',
    dumpHint: (db) => `docker exec -t <coolify_pg_container> pg_dump -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} -F c -b -f /tmp/${db.slug}.dump`,
    restoreHint: (db) => `pg_restore -h 127.0.0.1 -p 5432 -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} --no-owner --no-privileges /tmp/${db.slug}.dump`
  },
  pgvector: {
    engine: 'pgvector',
    label: 'PostgreSQL + pgvector',
    defaultPort: 5432,
    defaultImage: 'pgvector/pgvector:0.8.0-pg17',
    parity: 'full',
    dumpHint: (db) => `docker exec -t <coolify_pg_container> pg_dump -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} -F c -b -f /tmp/${db.slug}.dump`,
    restoreHint: (db) => `pg_restore -h 127.0.0.1 -p 5432 -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} --no-owner /tmp/${db.slug}.dump`
  },
  timescaledb: {
    engine: 'timescaledb',
    label: 'TimescaleDB',
    defaultPort: 5432,
    defaultImage: 'timescale/timescaledb:2.19.3-pg17',
    parity: 'full',
    dumpHint: (db) => `docker exec -t <coolify_ts_container> pg_dump -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} -F c -b -f /tmp/${db.slug}.dump`,
    restoreHint: (db) => `pg_restore -h 127.0.0.1 -p 5432 -U ${db.user || 'postgres'} -d ${db.dbName || 'postgres'} --no-owner /tmp/${db.slug}.dump`
  },
  mysql: {
    engine: 'mysql',
    label: 'MySQL',
    defaultPort: 3306,
    defaultImage: 'mysql:9',
    parity: 'full',
    dumpHint: (db) => `docker exec <coolify_mysql_container> mysqldump -u ${db.user || 'root'} -p --single-transaction --quick --set-gtid-purged=OFF ${db.dbName || '<db>'} > ${db.slug}.sql`,
    restoreHint: (db) => `mysql -h 127.0.0.1 -P 3306 -u ${db.user || 'root'} -p ${db.dbName || '<db>'} < ${db.slug}.sql`
  },
  mariadb: {
    engine: 'mariadb',
    label: 'MariaDB',
    defaultPort: 3306,
    defaultImage: 'mariadb:12.3',
    parity: 'full',
    dumpHint: (db) => `docker exec <coolify_mariadb_container> mariadb-dump -u ${db.user || 'root'} -p --single-transaction --quick ${db.dbName || '<db>'} > ${db.slug}.sql`,
    restoreHint: (db) => `mariadb -h 127.0.0.1 -P 3306 -u ${db.user || 'root'} -p ${db.dbName || '<db>'} < ${db.slug}.sql`
  },
  mongodb: {
    engine: 'mongodb',
    label: 'MongoDB',
    defaultPort: 27017,
    defaultImage: 'mongo:8.0',
    parity: 'full',
    dumpHint: (db) => `docker exec <coolify_mongo_container> mongodump --archive=/tmp/${db.slug}.archive --gzip`,
    restoreHint: (db) => `mongorestore --archive=/tmp/${db.slug}.archive --gzip`
  },
  valkey: {
    engine: 'valkey',
    label: 'Valkey (Redis / KeyDB / Dragonfly compatible)',
    defaultPort: 6379,
    defaultImage: 'valkey/valkey:8-alpine',
    parity: 'full',
    dumpHint: () => `docker exec <coolify_kv_container> redis-cli BGSAVE && cp <volume>/dump.rdb /tmp/dump.rdb`,
    restoreHint: () => `Copiar dump.rdb al volumen persistente de Valkey en Culkibo y reiniciar el contenedor.`
  },
  clickhouse: {
    engine: 'clickhouse',
    label: 'ClickHouse',
    defaultPort: 8123,
    defaultImage: 'clickhouse/clickhouse-server:24.8-alpine',
    parity: 'full',
    dumpHint: (db) => `docker exec <coolify_ch_container> clickhouse-client --query="BACKUP DATABASE ${db.dbName || 'default'} TO Disk('backups', '${db.slug}.zip')"`,
    restoreHint: (db) => `docker exec <culkibo_ch_container> clickhouse-client --query="RESTORE DATABASE ${db.dbName || 'default'} FROM Disk('backups', '${db.slug}.zip')"`
  }
});

/** Elimina secretos de `rawMeta` antes de persistir recursos migrados en `projects.json`. */
function sanitizeCoolifyMeta(obj, depth = 0) {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (depth > 3) return undefined;
  if (Array.isArray(obj)) return obj.slice(0, 50).map((item) => sanitizeCoolifyMeta(item, depth + 1));
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (COOLIFY_SENSITIVE_META_RE.test(k)) continue;
    out[k] = sanitizeCoolifyMeta(v, depth + 1);
  }
  return out;
}

/** Genera una huella corta determinista sin revelar el texto en claro. */
function redactSecretPreview(value) {
  const s = String(value ?? '');
  if (!s) return '';
  const hash = crypto.createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 10);
  return `[REDACTED:sha256:${hash}]`;
}

/** Detecta si un par clave/valor de entorno contiene un secreto. */
function isSensitiveEnv(key, value) {
  const v = String(value ?? '');
  if (/^\$\{vault\.[A-Za-z_][A-Za-z0-9_]{0,127}\}$/.test(v.trim())) return false;
  if (SENSITIVE_ENV_KEY_RE.test(String(key || ''))) return true;
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(v)) return true;
  if (/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s/@]+:[^@\s/]+@/i.test(v)) return true;
  if (/\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/.test(v)) return true;
  return false;
}

/** Normaliza un identificador para nombre de clave de Vault `[A-Za-z_][A-Za-z0-9_]{0,127}`. */
function toVaultKey(raw) {
  const cleaned = String(raw || '')
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120);
  if (!cleaned) return 'COOLIFY_SECRET';
  return /^[0-9]/.test(cleaned) ? `S_${cleaned}` : cleaned;
}

/** Intenta decodificar Base64 si Coolify devolvió `custom_labels` o `docker_compose_raw` codificado. */
function maybeDecodeBase64Text(raw) {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  // Si ya contiene saltos de línea, signos `=` de asignación o prefijos YAML/Traefik evidentes, es texto plano.
  if (trimmed.includes('\n') || trimmed.includes('traefik.') || /^\s*services\s*:/m.test(trimmed) || /^\s*version\s*:/m.test(trimmed)) {
    return trimmed;
  }
  if (trimmed.length >= 16 && trimmed.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    try {
      const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
      if (decoded && !/[\x00-\x08\x0e-\x1f]/.test(decoded) && (decoded.includes('=') || decoded.includes(':'))) {
        return decoded;
      }
    } catch (e) {}
  }
  return trimmed;
}

/** Normaliza un nombre de recurso a slug seguro. */
function slugify(str) {
  return String(str || 'app')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'app';
}

/** Extrae etiquetas `labels:` de un bloque Docker Compose YAML (formato lista o mapa). */
function extractLabelsFromComposeYaml(composeText) {
  const text = maybeDecodeBase64Text(composeText);
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  /** @type {string[]} */
  const labels = [];
  let inLabels = false;
  let labelsIndent = -1;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const indent = rawLine.search(/\S/);

    if (inLabels) {
      if (indent <= labelsIndent && !trimmed.startsWith('-')) {
        inLabels = false;
      } else {
        let entry = trimmed;
        if (entry.startsWith('- ')) entry = entry.slice(2).trim();
        else if (entry.startsWith('-')) entry = entry.slice(1).trim();
        // Quitar comillas envolventes
        if ((entry.startsWith('"') && entry.endsWith('"')) || (entry.startsWith("'") && entry.endsWith("'"))) {
          entry = entry.slice(1, -1);
        }
        // Soportar formato mapa YAML: `traefik.http...: "valor"` -> `traefik.http...=valor`
        if (!entry.includes('=') && entry.includes(':')) {
          const colonIdx = entry.indexOf(':');
          const k = entry.slice(0, colonIdx).trim().replace(/^["']|["']$/g, '');
          let v = entry.slice(colonIdx + 1).trim();
          if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
          }
          if (k) entry = `${k}=${v}`;
        }
        if (entry.includes('=')) labels.push(entry);
        continue;
      }
    }

    if (/^labels\s*:\s*$/.test(trimmed)) {
      inLabels = true;
      labelsIndent = indent;
    }
  }
  return labels;
}

/** Extrae sub-servicios básicos (nombre, imagen, puertos) de un Docker Compose YAML de Coolify. */
function inspectComposeServices(composeText) {
  const text = maybeDecodeBase64Text(composeText);
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  /** @type {Array<{ name: string, image: string, ports: string[], hasHealthcheck: boolean }>} */
  const services = [];
  let inServices = false;
  let servicesIndent = -1;
  let serviceKeyIndent = -1;
  /** @type {{ name: string, image: string, ports: string[], hasHealthcheck: boolean } | null} */
  let current = null;
  let inPorts = false;
  let portsIndent = -1;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const indent = rawLine.search(/\S/);

    if (indent === 0) {
      if (/^services\s*:\s*$/.test(trimmed)) {
        inServices = true;
        servicesIndent = 0;
        serviceKeyIndent = -1;
        current = null;
        inPorts = false;
      } else {
        inServices = false;
        current = null;
        inPorts = false;
      }
      continue;
    }
    if (!inServices) continue;

    if (serviceKeyIndent === -1 && indent > servicesIndent && !trimmed.startsWith('-')) {
      serviceKeyIndent = indent;
    }
    if (indent === serviceKeyIndent && !trimmed.startsWith('-')) {
      const m = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:/);
      if (m && !FORBIDDEN_PROTO_KEYS.has(m[1])) {
        current = { name: m[1], image: '', ports: [], hasHealthcheck: false };
        services.push(current);
        inPorts = false;
      }
      continue;
    }
    if (!current || indent <= serviceKeyIndent) continue;

    if (inPorts) {
      if (indent <= portsIndent && !trimmed.startsWith('-')) {
        inPorts = false;
      } else if (trimmed.startsWith('-')) {
        const p = trimmed.replace(/^-\s*/, '').replace(/^["']|["']$/g, '').trim();
        if (p) current.ports.push(p);
        continue;
      }
    }

    const imgMatch = trimmed.match(/^image\s*:\s*(.+)$/);
    if (imgMatch) {
      current.image = imgMatch[1].trim().replace(/^["']|["']$/g, '');
      continue;
    }
    if (/^healthcheck\s*:/.test(trimmed)) {
      current.hasHealthcheck = true;
      continue;
    }
    if (/^ports\s*:\s*$/.test(trimmed)) {
      inPorts = true;
      portsIndent = indent;
    }
  }
  return services;
}

class CoolifyMigrator {
  async fetchFromApi(apiUrl, apiToken, endpoint) {
    try {
      const { url: safeBase } = await assertSafeUrl(apiUrl, { blockSearchAndHash: true });
      const url = `${safeBase.origin}${safeBase.pathname.replace(/\/+$/, '')}${endpoint}`;
      const response = await safeFetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Accept': 'application/json'
        },
        maxRedirects: 0,
        maxBytes: 20 * 1024 * 1024,
        timeoutMs: 30000
      });
      if (!response.ok) {
        const httpErr = new Error(
          response.status === 401 || response.status === 403
            ? `Token de API de Coolify rechazado (HTTP ${response.status}). Verifica que el token tiene permisos de lectura.`
            : `Coolify respondió HTTP ${response.status}`
        );
        /** @type {any} */ (httpErr).status = response.status;
        throw httpErr;
      }
      const rawText = response.text().trim();
      return rawText ? JSON.parse(rawText) : [];
    } catch (err) {
      if (err && /SSRF|inválida|protocolo|metadatos|privada/i.test(String(err.message || ''))) {
        throw err;
      }
      if (err && (err.status === 401 || err.status === 403)) {
        throw err;
      }
      console.error(`Coolify fetch error on ${endpoint}:`, err.message);
      if (endpoint === '/api/v1/applications' && (!err.status || err.status >= 500)) {
        throw new Error('No se pudo conectar a la API de Coolify. Verifica URL y Token.');
      }
      return [];
    }
  }

  async fetchListWithDetails(apiUrl, apiToken, endpoint, detailEndpointPrefix) {
    const list = await this.fetchFromApi(apiUrl, apiToken, endpoint);
    if (!Array.isArray(list)) return [];

    const results = new Array(list.length);
    const CONCURRENCY = 3;
    let cursor = 0;

    const worker = async () => {
      while (cursor < list.length) {
        const idx = cursor++;
        const item = list[idx];
        try {
          const safeUuid = encodeURIComponent(String(item.uuid || ''));
          const supportsTasks = detailEndpointPrefix === '/api/v1/applications' || detailEndpointPrefix === '/api/v1/services';
          const [details, envs, storages, scheduledTasks] = await Promise.all([
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}`),
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/envs`).catch((e) => {
              if (e && (e.status === 401 || e.status === 403)) return { _authWarning: e.message };
              return [];
            }),
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/storages`).catch(() => null),
            supportsTasks
              ? this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/scheduled-tasks`).catch(() => [])
              : Promise.resolve([])
          ]);

          const detailsObj = Array.isArray(details) ? {} : (details || {});
          const fullItem = { ...item, ...detailsObj };
          if (envs && typeof envs === 'object' && !Array.isArray(envs) && envs._authWarning) {
            fullItem._warnings = [...(fullItem._warnings || []), `Sin permiso para leer variables: ${envs._authWarning}`];
          }
          fullItem.environment_variables = (Array.isArray(envs) && envs.length > 0) ? envs : (fullItem.environment_variables || []);

          if (Array.isArray(scheduledTasks) && scheduledTasks.length > 0) {
            fullItem.scheduled_tasks = scheduledTasks;
          } else if (!Array.isArray(fullItem.scheduled_tasks)) {
            fullItem.scheduled_tasks = [];
          }

          if (storages && typeof storages === 'object') {
            const persistent = Array.isArray(storages.persistent_storages) ? storages.persistent_storages : [];
            const files = Array.isArray(storages.file_storages) ? storages.file_storages : [];
            fullItem.persistent_storages = persistent;
            fullItem.file_storages = files;
            fullItem.local_persistent_volumes = persistent.map(s => ({
              name: s.name,
              mount_path: s.mount_path,
              host_path: s.host_path || null
            }));
            fullItem.persistent_volumes = fullItem.local_persistent_volumes;
            fullItem.volumes = fullItem.local_persistent_volumes;
            fullItem.local_file_volumes = files.map(f => ({
              fs_path: f.fs_path || null,
              mount_path: f.mount_path,
              content: f.content || ''
            }));
            fullItem.file_volumes = fullItem.local_file_volumes;
          } else {
            fullItem.local_persistent_volumes = fullItem.local_persistent_volumes || fullItem.persistent_volumes || fullItem.volumes || [];
            fullItem.local_file_volumes = fullItem.local_file_volumes || fullItem.file_volumes || [];
          }

          results[idx] = fullItem;
        } catch (err) {
          if (err && (err.status === 401 || err.status === 403)) throw err;
          results[idx] = item;
        }
      }
    };

    const workers = Array.from({ length: Math.min(CONCURRENCY, list.length) }, () => worker());
    await Promise.all(workers);
    return results.filter(Boolean);
  }

  async fetchApplications(apiUrl, apiToken) {
    return this.fetchListWithDetails(apiUrl, apiToken, '/api/v1/applications', '/api/v1/applications');
  }

  async fetchDatabases(apiUrl, apiToken) {
    return this.fetchListWithDetails(apiUrl, apiToken, '/api/v1/databases', '/api/v1/databases');
  }

  async fetchServices(apiUrl, apiToken) {
    return this.fetchListWithDetails(apiUrl, apiToken, '/api/v1/services', '/api/v1/services');
  }

  async fetchProjects(apiUrl, apiToken) {
    return this.fetchFromApi(apiUrl, apiToken, '/api/v1/projects');
  }

  async previewMigration(apiUrl, apiToken) {
    const apps = await this.fetchApplications(apiUrl, apiToken);
    const databases = await this.fetchDatabases(apiUrl, apiToken);
    const services = await this.fetchServices(apiUrl, apiToken);
    const projects = await this.fetchProjects(apiUrl, apiToken);
    const plan = this.buildMigrationPlan({ apps, databases, services, projects });
    return {
      apps,
      databases,
      services,
      projects,
      plan
    };
  }

  /** Extrae hostnames limpios desde un campo `fqdn` de Coolify (lista CSV de URLs o dominios). */
  parseFqdnHosts(fqdn) {
    if (!fqdn) return [];
    const hosts = [];
    for (const raw of String(fqdn).split(',')) {
      const token = raw.trim();
      if (!token) continue;
      try {
        const parsed = new URL(/^https?:\/\//i.test(token) ? token : `https://${token}`);
        const host = parsed.hostname.toLowerCase();
        if (host && host.includes('.')) hosts.push(host);
      } catch (e) {
        const clean = token.replace(/^https?:\/\//i, '').replace(/[:/].*$/, '').toLowerCase();
        if (clean && clean.includes('.')) hosts.push(clean);
      }
    }
    return Array.from(new Set(hosts));
  }

  /** Extrae esquema + host por entrada desde un `fqdn` CSV de Coolify. */
  parseFqdnUrls(fqdn) {
    if (!fqdn) return [];
    /** @type {Array<{ url: string, host: string, protocol: string, port: string }>} */
    const out = [];
    for (const raw of String(fqdn).split(',')) {
      const token = raw.trim();
      if (!token) continue;
      try {
        const parsed = new URL(/^https?:\/\//i.test(token) ? token : `https://${token}`);
        const host = parsed.hostname.toLowerCase();
        if (host && host.includes('.')) {
          out.push({
            url: `${parsed.protocol}//${parsed.host}`,
            host,
            protocol: parsed.protocol,
            port: parsed.port || ''
          });
        }
      } catch (e) {}
    }
    return out;
  }

  /** Normaliza estados compuestos de Coolify v4 (`running:healthy`, `running:unknown`, `exited:unhealthy`). */
  normalizeCoolifyStatus(status) {
    return String(status || '').toLowerCase().startsWith('running') ? 'active' : 'stopped';
  }

  /** Parsea límites de memoria de Coolify (`512m`, `1g`, `536870912`) a MB enteros. */
  parseMemoryMb(raw) {
    if (!raw || raw === '0') return null;
    const s = String(raw).trim().toLowerCase();
    const m = s.match(/^(\d+(?:\.\d+)?)\s*(b|k|kb|m|mb|g|gb)?$/);
    if (!m) return null;
    const n = parseFloat(m[1]);
    const unit = m[2] || 'b';
    if (unit === 'g' || unit === 'gb') return Math.round(n * 1024);
    if (unit === 'm' || unit === 'mb') return Math.round(n);
    if (unit === 'k' || unit === 'kb') return Math.max(64, Math.round(n / 1024));
    return n > 1024 * 1024 ? Math.round(n / (1024 * 1024)) : Math.round(n);
  }

  /** Resuelve el motor nativo de Culkibo para cualquiera de las 8 BDs de Coolify v4. */
  resolveDatabaseEngine(db) {
    const rawType = String(db.database_type || db.type || 'database').toLowerCase();
    const img = String(db.image || '').toLowerCase();
    if (rawType.includes('postgres') || img.includes('postgres') || img.includes('pgvector') || img.includes('timescaledb')) {
      if (img.includes('pgvector')) return { engine: 'pgvector', originalType: rawType || 'postgresql', note: null };
      if (img.includes('timescaledb')) return { engine: 'timescaledb', originalType: rawType || 'postgresql', note: null };
      return { engine: 'postgres', originalType: rawType || 'postgresql', note: null };
    }
    if (rawType.includes('mariadb') || img.includes('mariadb')) {
      return { engine: 'mariadb', originalType: rawType || 'mariadb', note: null };
    }
    if (rawType.includes('mysql') || img.includes('mysql')) {
      return { engine: 'mysql', originalType: rawType || 'mysql', note: null };
    }
    if (rawType.includes('dragonfly') || img.includes('dragonfly')) {
      return {
        engine: 'valkey',
        originalType: 'dragonfly',
        note: 'Dragonfly mapeado a Valkey (protocolo RESP3 compatible); puedes conservar la imagen docker.dragonflydb.io/dragonflydb/dragonfly si usas extensiones específicas.'
      };
    }
    if (rawType.includes('keydb') || img.includes('keydb')) {
      return {
        engine: 'valkey',
        originalType: 'keydb',
        note: 'KeyDB mapeado a Valkey (protocolo Redis compatible, multi-hilo moderno bajo licencia BSD-3).'
      };
    }
    if (rawType.includes('redis') || rawType.includes('valkey') || img.includes('redis') || img.includes('valkey')) {
      return { engine: 'valkey', originalType: rawType || 'redis', note: null };
    }
    if (rawType.includes('mongo') || img.includes('mongo')) {
      return { engine: 'mongodb', originalType: rawType || 'mongodb', note: null };
    }
    if (rawType.includes('clickhouse') || img.includes('clickhouse')) {
      return {
        engine: 'clickhouse',
        originalType: 'clickhouse',
        note: 'ClickHouse preservado como servicio/recurso OLAP dedicado con volumen y puerto HTTP 8123 / nativo 9000.'
      };
    }
    return { engine: rawType || 'database', originalType: rawType, note: `Motor personalizado "${rawType}" preservado como contenedor dedicado.` };
  }

  // ===========================================================================
  // 1. COOLIFY v4 MAGIC VARIABLE RESOLVER & TRANSLATOR
  // ===========================================================================

  /**
   * Traduce variables mágicas de Coolify v4 (`${SERVICE_FQDN_*}`, `${SERVICE_URL_*}`,
   * `${SERVICE_PASSWORD_*}`, `${SERVICE_PASSWORD_64_*}`, `${SERVICE_USER_*}`,
   * `${SERVICE_BASE64_*}`, `${COOLIFY_FQDN}`, `${COOLIFY_URL}`, `${COOLIFY_BRANCH}`,
   * `${COOLIFY_CONTAINER_NAME}`) a expresiones nativas de Culkibo (`${vault.*}` o
   * host/URL/runtime resuelto), generando además una vista previa 100% redactada.
   *
   * @param {Record<string, string>} envVars
   * @param {{
   *   resourceName?: string,
   *   fqdn?: string,
   *   hosts?: string[],
   *   serviceHostMap?: Record<string, { host: string, url: string }>,
   *   gitBranch?: string,
   *   containerName?: string,
   *   uuid?: string,
   *   projectUuid?: string,
   *   environmentName?: string,
   *   dockerCompose?: string
   * }} [context]
   */
  translateMagicVariables(envVars, context = {}) {
    const hosts = Array.isArray(context.hosts) && context.hosts.length > 0
      ? context.hosts
      : this.parseFqdnHosts(context.fqdn);
    const urls = this.parseFqdnUrls(context.fqdn);
    const primaryHost = hosts[0] || '';
    const primaryUrl = (urls[0] && urls[0].url) || (primaryHost ? `https://${primaryHost}` : '');
    const gitBranch = String(context.gitBranch || 'main').trim() || 'main';
    const containerName = String(context.containerName || `culkibo-${slugify(context.resourceName || 'app')}`);
    const serviceHostMap = context.serviceHostMap || {};

    /** @type {Record<string, string>} */
    const translatedEnv = {};
    /** @type {Record<string, string>} */
    const redactedPreviewEnv = {};
    /** @type {Array<{ envKey: string, original: string, variable: string, kind: 'magic_secret' | 'magic_domain' | 'magic_runtime', translated: string, vaultKey: string | null, resolvedPreview: string, autoGeneratable: boolean, secretLength?: number }>} */
    const magicVarsFound = [];
    /** @type {Set<string>} */
    const vaultRefs = new Set();
    /** @type {string[]} */
    const secretWarnings = [];
    /** @type {string[]} */
    const unmappedMagicVars = [];

    // Mapa auxiliar de lookup de host por sufijo de servicio (p. ej. WORDPRESS, APP, API_8080)
    /** @param {string} suffix */
    const resolveServiceEndpoint = (suffix) => {
      const upper = suffix.toUpperCase();
      // 1. Exact match en serviceHostMap (ej. WORDPRESS, API_8080)
      if (serviceHostMap[upper]) return serviceHostMap[upper];
      // 2. Strip trailing _PORT (ej. APP_3000 -> APP)
      const portStripped = upper.replace(/_\d{2,5}$/, '');
      if (serviceHostMap[portStripped]) return serviceHostMap[portStripped];
      // 3. Match parcial contra hosts disponibles
      const lowerSlug = portStripped.toLowerCase().replace(/_/g, '-');
      const matchedHost = hosts.find((h) => h.startsWith(`${lowerSlug}.`) || h.includes(lowerSlug)) || primaryHost;
      if (matchedHost) {
        const matchedUrlObj = urls.find((u) => u.host === matchedHost);
        return { host: matchedHost, url: matchedUrlObj ? matchedUrlObj.url : `https://${matchedHost}` };
      }
      return null;
    };

    const MAGIC_TOKEN_RE = /\$\{((?:SERVICE|COOLIFY)_[A-Za-z0-9_]+)(?::?-([^}]*))?\}|\$((?:SERVICE|COOLIFY)_[A-Za-z0-9_]+)/g;

    /**
     * Traduce todos los tokens mágicos dentro de una cadena.
     * @param {string} envKey
     * @param {string} rawVal
     */
    const translateString = (envKey, rawVal) => {
      const str = String(rawVal ?? '');
      MAGIC_TOKEN_RE.lastIndex = 0;
      return str.replace(MAGIC_TOKEN_RE, (fullMatch, bracedVar, fallbackVal, bareVar) => {
        const varName = String(bracedVar || bareVar || '').trim();
        if (!varName) return fullMatch;

        // A. SERVICE_FQDN_* / SERVICE_URL_*
        const fqdnMatch = varName.match(/^SERVICE_(FQDN|URL)_([A-Za-z0-9_]+)$/);
        if (fqdnMatch) {
          const isUrl = fqdnMatch[1] === 'URL';
          const suffix = fqdnMatch[2];
          const resolved = resolveServiceEndpoint(suffix);
          const translated = resolved
            ? (isUrl ? resolved.url : resolved.host)
            : (fallbackVal || (isUrl ? `https://\${domain.${slugify(suffix)}}` : `\${domain.${slugify(suffix)}}`));
          if (!resolved && !fallbackVal) {
            unmappedMagicVars.push(`${envKey}: ${fullMatch} (sin FQDN asignado en origen; usa dominio de Culkibo)`);
          }
          magicVarsFound.push({
            envKey,
            original: fullMatch,
            variable: varName,
            kind: 'magic_domain',
            translated,
            vaultKey: null,
            resolvedPreview: translated,
            autoGeneratable: false
          });
          return translated;
        }

        // B. SERVICE_PASSWORD_64_* / SERVICE_PASSWORD_ENCRYPTION_* / SERVICE_PASSWORD_*
        const pwdMatch = varName.match(/^SERVICE_PASSWORD(?:_(64|ENCRYPTION))?_([A-Za-z0-9_]+)$/);
        if (pwdMatch) {
          const variant = pwdMatch[1] || '';
          const secretLength = variant === '64' ? 64 : 32;
          const vaultKey = toVaultKey(varName);
          const translated = `\${vault.${vaultKey}}`;
          vaultRefs.add(vaultKey);
          magicVarsFound.push({
            envKey,
            original: fullMatch,
            variable: varName,
            kind: 'magic_secret',
            translated,
            vaultKey,
            resolvedPreview: translated,
            autoGeneratable: true,
            secretLength
          });
          return translated;
        }

        // C. SERVICE_USER_*
        const userMatch = varName.match(/^SERVICE_USER_([A-Za-z0-9_]+)$/);
        if (userMatch) {
          const vaultKey = toVaultKey(varName);
          const translated = `\${vault.${vaultKey}}`;
          vaultRefs.add(vaultKey);
          magicVarsFound.push({
            envKey,
            original: fullMatch,
            variable: varName,
            kind: 'magic_secret',
            translated,
            vaultKey,
            resolvedPreview: translated,
            autoGeneratable: true,
            secretLength: 16
          });
          return translated;
        }

        // D. SERVICE_BASE64_* / SERVICE_BASE64_64_* / SERVICE_BASE64_128_* / SERVICE_REALBASE64_*
        const b64Match = varName.match(/^SERVICE_(?:REAL)?BASE64(?:_(32|64|128))?_([A-Za-z0-9_]+)$/);
        if (b64Match) {
          const secretLength = b64Match[1] ? Number(b64Match[1]) : 32;
          const vaultKey = toVaultKey(varName);
          const translated = `\${vault.${vaultKey}}`;
          vaultRefs.add(vaultKey);
          magicVarsFound.push({
            envKey,
            original: fullMatch,
            variable: varName,
            kind: 'magic_secret',
            translated,
            vaultKey,
            resolvedPreview: translated,
            autoGeneratable: true,
            secretLength
          });
          return translated;
        }

        // E. COOLIFY_* built-in runtime variables
        if (varName === 'COOLIFY_FQDN') {
          const translated = hosts.length > 0 ? hosts.join(',') : (fallbackVal || '${domain.primary}');
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_domain',
            translated, vaultKey: null, resolvedPreview: translated, autoGeneratable: false
          });
          return translated;
        }
        if (varName === 'COOLIFY_URL') {
          const translated = primaryUrl || (fallbackVal || 'https://${domain.primary}');
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_domain',
            translated, vaultKey: null, resolvedPreview: translated, autoGeneratable: false
          });
          return translated;
        }
        if (varName === 'COOLIFY_BRANCH') {
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_runtime',
            translated: gitBranch, vaultKey: null, resolvedPreview: gitBranch, autoGeneratable: false
          });
          return gitBranch;
        }
        if (varName === 'COOLIFY_CONTAINER_NAME') {
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_runtime',
            translated: containerName, vaultKey: null, resolvedPreview: containerName, autoGeneratable: false
          });
          return containerName;
        }
        if (varName === 'COOLIFY_RESOURCE_UUID') {
          const translated = String(context.uuid || slugify(context.resourceName || 'app'));
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_runtime',
            translated, vaultKey: null, resolvedPreview: translated, autoGeneratable: false
          });
          return translated;
        }
        if (varName === 'COOLIFY_PROJECT_UUID') {
          const translated = String(context.projectUuid || 'coolify_import');
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_runtime',
            translated, vaultKey: null, resolvedPreview: translated, autoGeneratable: false
          });
          return translated;
        }
        if (varName === 'COOLIFY_ENVIRONMENT_NAME') {
          const translated = String(context.environmentName || 'production');
          magicVarsFound.push({
            envKey, original: fullMatch, variable: varName, kind: 'magic_runtime',
            translated, vaultKey: null, resolvedPreview: translated, autoGeneratable: false
          });
          return translated;
        }

        // Variable mágica desconocida -> preservar y advertir
        unmappedMagicVars.push(`${envKey}: ${fullMatch}`);
        return fullMatch;
      });
    };

    const sourceMap = envVars && typeof envVars === 'object' ? envVars : {};
    for (const [k, rawV] of Object.entries(sourceMap)) {
      if (FORBIDDEN_PROTO_KEYS.has(k)) continue;
      const valStr = rawV == null ? '' : String(rawV);
      const translatedVal = translateString(k, valStr);
      translatedEnv[k] = translatedVal;

      // Vista previa estrictamente redactada (jamás expone secretos en claro en dry-run)
      if (/^\$\{vault\.[A-Za-z_][A-Za-z0-9_]{0,127}\}$/.test(translatedVal.trim())) {
        redactedPreviewEnv[k] = translatedVal;
      } else if (isSensitiveEnv(k, translatedVal) && translatedVal.length > 0) {
        // Si mezcla texto plano con ${vault.*} (p. ej. DATABASE_URL), redactar completamente en preview
        redactedPreviewEnv[k] = redactSecretPreview(translatedVal);
        secretWarnings.push(
          `Variable sensible "${k}" detectada en ${context.resourceName || 'recurso'}: se recomienda migrarla a \${vault.${toVaultKey(k)}} en el Vault cifrado AES-256-GCM.`
        );
      } else {
        redactedPreviewEnv[k] = translatedVal;
      }
    }

    // Escanear y traducir también magic vars dentro de docker_compose si se proporcionó
    let translatedCompose = '';
    if (context.dockerCompose) {
      const decodedCompose = maybeDecodeBase64Text(context.dockerCompose);
      translatedCompose = translateString('docker_compose', decodedCompose);
    }

    return {
      translatedEnv,
      redactedPreviewEnv,
      translatedCompose,
      magicVarsFound,
      vaultRefs: Array.from(vaultRefs).sort(),
      secretWarnings,
      unmappedMagicVars
    };
  }

  // ===========================================================================
  // 2. TRAEFIK LABEL → CULKIBO NATIVE CADDY / EDGE TRANSLATOR
  // ===========================================================================

  /**
   * Parsea etiquetas Docker/Compose de Traefik v2/v3 (`custom_labels` texto plano o Base64,
   * o `labels:` dentro de `docker_compose`) y las traduce a configuración nativa de
   * `domainManager` / `caddyManager`: `pathRoutes`, `pathRedirects`, `forwardAuth`,
   * `cors`, `hstsPreload`, `hstsMaxAge`, `basicAuth`, `customHeaders`, `ipAllowlist`,
   * `rateLimit`, `maxBodySizeMb`, `canonicalRedirect`, `protocol`, `targetPort`.
   *
   * @param {string | string[] | Record<string, string> | null | undefined} rawLabels
   * @param {{ defaultPort?: number, defaultHosts?: string[], composeYaml?: string }} [opts]
   */
  parseTraefikLabels(rawLabels, opts = {}) {
    const cm = getCaddyManager();
    /** @type {Record<string, string>} */
    const labelMap = Object.create(null);

    /** @param {string} line */
    const ingestLine = (line) => {
      const trimmed = String(line || '').trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eq = trimmed.indexOf('=');
      if (eq <= 0) return;
      const k = trimmed.slice(0, eq).trim().replace(/^["']|["']$/g, '');
      let v = trimmed.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (k && !FORBIDDEN_PROTO_KEYS.has(k)) {
        labelMap[k] = v;
      }
    };

    if (typeof rawLabels === 'string') {
      const decoded = maybeDecodeBase64Text(rawLabels);
      for (const line of decoded.split(/\r?\n/)) ingestLine(line);
    } else if (Array.isArray(rawLabels)) {
      for (const item of rawLabels) ingestLine(String(item || ''));
    } else if (rawLabels && typeof rawLabels === 'object') {
      for (const [k, v] of Object.entries(rawLabels)) {
        if (!FORBIDDEN_PROTO_KEYS.has(k)) labelMap[k] = String(v ?? '');
      }
    }

    if (opts.composeYaml) {
      for (const line of extractLabelsFromComposeYaml(opts.composeYaml)) {
        ingestLine(line);
      }
    }

    /** @type {Record<string, { hosts: string[], pathPrefixes: string[], middlewares: string[], service: string | null, rule: string, tls: boolean }>} */
    const routers = Object.create(null);
    /** @type {Record<string, { port: number | null, scheme: string | null }>} */
    const services = Object.create(null);
    /** @type {Record<string, Record<string, Record<string, string>>>} */
    const middlewares = Object.create(null);
    /** @type {string[]} */
    const warnings = [];
    /** @type {string[]} */
    const unsupportedLabels = [];

    const ensureRouter = (name) => {
      if (!routers[name]) routers[name] = { hosts: [], pathPrefixes: [], middlewares: [], service: null, rule: '', tls: false };
      return routers[name];
    };
    const ensureService = (name) => {
      if (!services[name]) services[name] = { port: null, scheme: null };
      return services[name];
    };
    const ensureMiddleware = (name, type) => {
      if (!middlewares[name]) middlewares[name] = Object.create(null);
      if (!middlewares[name][type]) middlewares[name][type] = Object.create(null);
      return middlewares[name][type];
    };

    const parseRuleHosts = (rule) => {
      /** @type {string[]} */
      const found = [];
      const hostRe = /Host\(([^)]+)\)/gi;
      let m;
      while ((m = hostRe.exec(rule)) !== null) {
        const inner = m[1];
        const parts = inner.match(/[`"']([^`"']+)[`"']/g) || [];
        for (const p of parts) {
          const h = p.slice(1, -1).trim().toLowerCase();
          if (h && h.includes('.')) found.push(h);
        }
      }
      return Array.from(new Set(found));
    };

    const parseRulePaths = (rule) => {
      /** @type {string[]} */
      const found = [];
      const pathRe = /Path(?:Prefix)?\(([^)]+)\)/gi;
      let m;
      while ((m = pathRe.exec(rule)) !== null) {
        const parts = m[1].match(/[`"']([^`"']+)[`"']/g) || [];
        for (const p of parts) {
          const val = p.slice(1, -1).trim();
          if (val.startsWith('/')) found.push(val);
        }
      }
      return Array.from(new Set(found));
    };

    let traefikLabelCount = 0;

    for (const [key, val] of Object.entries(labelMap)) {
      if (!key.toLowerCase().startsWith('traefik.')) continue;
      traefikLabelCount++;

      // Ignore traefik.enable / traefik.docker.network metadata labels
      if (/^traefik\.(enable|docker\.network|constraint)$/i.test(key)) continue;

      // Router labels
      const rMatch = key.match(/^traefik\.http\.routers\.([^.]+)\.(.+)$/i);
      if (rMatch) {
        const rName = rMatch[1];
        const prop = rMatch[2].toLowerCase();
        const r = ensureRouter(rName);
        if (prop === 'rule') {
          r.rule = val;
          r.hosts.push(...parseRuleHosts(val));
          r.pathPrefixes.push(...parseRulePaths(val));
        } else if (prop === 'middlewares') {
          const mws = val.split(',').map((s) => s.trim().replace(/@[a-z0-9_-]+$/i, '')).filter(Boolean);
          r.middlewares.push(...mws);
        } else if (prop === 'service') {
          r.service = val.trim();
        } else if (prop === 'tls' || prop.startsWith('tls.')) {
          r.tls = val.toLowerCase() !== 'false';
        } else if (prop === 'entrypoints' || prop === 'priority') {
          // Handled implicitly by Caddy HTTPS auto-routing
        } else {
          unsupportedLabels.push(`${key}=${val}`);
        }
        continue;
      }

      // Service loadbalancer labels
      const sMatch = key.match(/^traefik\.http\.services\.([^.]+)\.loadbalancer\.server\.(.+)$/i);
      if (sMatch) {
        const sName = sMatch[1];
        const prop = sMatch[2].toLowerCase();
        const s = ensureService(sName);
        if (prop === 'port') {
          const p = parseInt(val, 10);
          if (Number.isInteger(p) && p >= 1 && p <= 65535) s.port = p;
          else warnings.push(`Puerto inválido en etiqueta Traefik ${key}: "${val}"`);
        } else if (prop === 'scheme') {
          s.scheme = val.trim().toLowerCase();
        }
        continue;
      }

      // Middleware labels
      const mMatch = key.match(/^traefik\.http\.middlewares\.([^.]+)\.([^.]+)\.(.+)$/i);
      if (mMatch) {
        const mwName = mMatch[1];
        const mwType = mMatch[2].toLowerCase();
        const mwProp = mMatch[3];
        if (['stripprefix', 'redirectregex', 'headers', 'forwardauth', 'basicauth', 'ipallowlist', 'ipwhitelist', 'ratelimit', 'buffering', 'compress', 'gzip'].includes(mwType)) {
          const mw = ensureMiddleware(mwName, mwType);
          mw[mwProp] = val;
        } else {
          unsupportedLabels.push(`${key}=${val}`);
        }
        continue;
      }

      unsupportedLabels.push(`${key}=${val}`);
    }

    // Determinar puerto destino principal y protocolo
    const servicePorts = Object.values(services).map((s) => s.port).filter((p) => Number.isInteger(p));
    let targetPort = /** @type {number | null} */ (servicePorts[0] || (Number.isInteger(Number(opts.defaultPort)) && Number(opts.defaultPort) > 0 ? Number(opts.defaultPort) : null));
    let protocol = /** @type {'http' | 'grpc' | 'h2c'} */ ('http');
    if (Object.values(services).some((s) => s.scheme === 'h2c')) protocol = 'h2c';

    // Consolidar config Edge nativa de Culkibo
    /** @type {Array<{ path: string, upstreams: string[], stripPrefix: string | boolean, protocol: string }>} */
    const pathRoutes = [];
    /** @type {Array<{ pattern: string, target: string, status: number, isRegex: boolean }>} */
    const pathRedirects = [];
    /** @type {any} */
    let forwardAuth = null;
    /** @type {any} */
    let cors = null;
    /** @type {any} */
    let basicAuth = null;
    /** @type {any} */
    let basicAuthPreview = null;
    /** @type {{ response?: Record<string, string>, request?: Record<string, string> }} */
    const customHeaders = {};
    /** @type {boolean | undefined} */
    let hstsPreload;
    /** @type {number | undefined} */
    let hstsMaxAge;
    /** @type {'DENY' | 'SAMEORIGIN' | 'ALLOW' | undefined} */
    let framePolicy;
    /** @type {string | undefined} */
    let csp;
    /** @type {string | undefined} */
    let permissionsPolicy;
    /** @type {'none' | 'www_to_apex' | 'apex_to_www' | undefined} */
    let canonicalRedirect;
    /** @type {string[]} */
    const ipAllowlist = [];
    /** @type {any} */
    let rateLimit = null;
    /** @type {number | undefined} */
    let maxBodySizeMb;
    /** @type {Array<{ source: string, target: string, summary: string }>} */
    const translatedRules = [];

    const effectiveUpstreamPort = targetPort || 3000;
    const defaultUpstream = `127.0.0.1:${effectiveUpstreamPort}`;

    // Mapear routers con PathPrefix + middleware stripprefix
    const handledStripMiddlewares = new Set();
    for (const [rName, r] of Object.entries(routers)) {
      const rSvc = r.service && services[r.service];
      const rPort = (rSvc && rSvc.port) || effectiveUpstreamPort;
      const rProto = (rSvc && rSvc.scheme === 'h2c') ? 'h2c' : protocol;
      const rUpstream = `127.0.0.1:${rPort}`;

      /** @type {string[]} */
      const stripPrefixesFromRouter = [];
      for (const mwName of r.middlewares) {
        const mw = middlewares[mwName];
        if (mw && mw.stripprefix && mw.stripprefix.prefixes) {
          handledStripMiddlewares.add(mwName);
          const list = String(mw.stripprefix.prefixes).split(',').map((s) => s.trim()).filter((s) => s.startsWith('/') && !s.includes('..'));
          stripPrefixesFromRouter.push(...list);
        }
      }

      const paths = r.pathPrefixes.length > 0 ? r.pathPrefixes : stripPrefixesFromRouter;
      for (const p of paths) {
        if (!p.startsWith('/') || p.includes('..') || /[\s\r\n\0]/.test(p)) {
          warnings.push(`Ruta PathPrefix insegura omitida en router "${rName}": "${p}"`);
          continue;
        }
        const matchedStrip = stripPrefixesFromRouter.find((sp) => sp === p || p.startsWith(sp)) || false;
        pathRoutes.push({
          path: p,
          upstreams: [rUpstream],
          stripPrefix: matchedStrip,
          protocol: rProto
        });
        translatedRules.push({
          source: `traefik.http.routers.${rName}`,
          target: 'domain.pathRoutes',
          summary: `${p} → ${rUpstream}${matchedStrip ? ` (stripPrefix: ${matchedStrip})` : ''}`
        });
      }
    }

    // Procesar todos los middlewares declarados
    for (const [mwName, typesMap] of Object.entries(middlewares)) {
      // 1. stripprefix no consumido aún por un router PathPrefix
      if (typesMap.stripprefix && !handledStripMiddlewares.has(mwName)) {
        const rawPrefixes = typesMap.stripprefix.prefixes || '';
        for (const p of String(rawPrefixes).split(',').map((s) => s.trim()).filter(Boolean)) {
          if (!p.startsWith('/') || p.includes('..') || /[\s\r\n\0]/.test(p)) {
            warnings.push(`Prefijo stripprefix inválido en "${mwName}": "${p}"`);
            continue;
          }
          pathRoutes.push({
            path: p,
            upstreams: [defaultUpstream],
            stripPrefix: p,
            protocol
          });
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.stripprefix`,
            target: 'domain.pathRoutes',
            summary: `stripPrefix ${p} → ${defaultUpstream}`
          });
        }
      }

      // 2. redirectregex
      if (typesMap.redirectregex) {
        const rr = typesMap.redirectregex;
        const regex = String(rr.regex || '').trim();
        const replacement = String(rr.replacement || '').trim();
        const permanent = String(rr.permanent || '').toLowerCase() === 'true';
        const status = permanent ? 301 : 302;

        if (regex && replacement) {
          // Detectar redirecciones canónicas www ↔ apex típicas de Coolify
          if (/www\\\./i.test(regex) && !/www\./i.test(replacement)) {
            canonicalRedirect = 'www_to_apex';
            translatedRules.push({
              source: `traefik.http.middlewares.${mwName}.redirectregex`,
              target: 'domain.canonicalRedirect',
              summary: `www → apex (${status})`
            });
          } else if (!/www\\\./i.test(regex) && /:\/\/www\./i.test(replacement)) {
            canonicalRedirect = 'apex_to_www';
            translatedRules.push({
              source: `traefik.http.middlewares.${mwName}.redirectregex`,
              target: 'domain.canonicalRedirect',
              summary: `apex → www (${status})`
            });
          } else {
            // Convertir sustitución Traefik `${1}` / `$1` a Caddy `{http.regexp.r0.1}` o destino limpio
            const normalizedTarget = replacement.replace(/\$\{(\d+)\}/g, '$$$1');
            const safeCheck = cm.validateSafeRedirectRegex(regex);
            if (!safeCheck.ok) {
              warnings.push(`Middleware redirectregex "${mwName}" bloqueado por guardia anti-ReDoS: ${safeCheck.error}`);
            } else if (/^(?:javascript|data|vbscript):/i.test(normalizedTarget) || (!normalizedTarget.startsWith('/') && !/^https?:\/\//i.test(normalizedTarget))) {
              warnings.push(`Destino redirectregex no permitido en "${mwName}": "${normalizedTarget.slice(0, 60)}"`);
            } else {
              pathRedirects.push({ pattern: regex, target: normalizedTarget, status, isRegex: true });
              translatedRules.push({
                source: `traefik.http.middlewares.${mwName}.redirectregex`,
                target: 'domain.pathRedirects',
                summary: `/${regex}/ → ${normalizedTarget} (${status})`
              });
            }
          }
        }
      }

      // 3. headers (CORS + HSTS + Security + Custom Headers)
      if (typesMap.headers) {
        const hdr = typesMap.headers;
        /** @type {Record<string, string>} */
        const lowerHdr = Object.create(null);
        for (const [hk, hv] of Object.entries(hdr)) {
          lowerHdr[hk.toLowerCase()] = hv;
        }

        // CORS
        const rawOrigins = lowerHdr.accesscontrolalloworiginlist || lowerHdr.accesscontrolalloworigin || '';
        if (rawOrigins) {
          const candidateOrigins = String(rawOrigins).split(',').map((s) => s.trim()).filter(Boolean);
          /** @type {string[]} */
          const validOrigins = [];
          for (const orig of candidateOrigins) {
            try {
              validOrigins.push(cm.validateCorsOrigin(orig));
            } catch (e) {
              warnings.push(`Origen CORS inválido en "${mwName}": ${e.message}`);
            }
          }
          const allowCredentials = String(lowerHdr.accesscontrolallowcredentials || '').toLowerCase() === 'true';
          if (validOrigins.length > 0) {
            if (allowCredentials && validOrigins.includes('*')) {
              warnings.push(`CORS inseguro en "${mwName}": allowCredentials=true con origen "*" bloqueado por Culkibo; desactivado allowCredentials.`);
            }
            const allowedMethods = lowerHdr.accesscontrolallowmethods
              ? String(lowerHdr.accesscontrolallowmethods).split(',').map((m) => m.trim().toUpperCase()).filter((m) => /^[A-Z]{2,16}$/.test(m))
              : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
            const allowedHeaders = lowerHdr.accesscontrolallowheaders
              ? String(lowerHdr.accesscontrolallowheaders).split(',').map((h) => h.trim()).filter((h) => HEADER_NAME_RE.test(h))
              : ['Authorization', 'Content-Type', 'X-Requested-With'];
            const exposedHeaders = lowerHdr.accesscontrolexposeheaders
              ? String(lowerHdr.accesscontrolexposeheaders).split(',').map((h) => h.trim()).filter((h) => HEADER_NAME_RE.test(h))
              : [];
            const maxAgeRaw = Number(lowerHdr.accesscontrolmaxage);
            const maxAge = Number.isFinite(maxAgeRaw) ? Math.min(86400, Math.max(0, Math.round(maxAgeRaw))) : 3600;

            cors = {
              enabled: true,
              allowedOrigins: Array.from(new Set(validOrigins)),
              allowedMethods,
              allowedHeaders,
              exposedHeaders,
              allowCredentials: allowCredentials && !validOrigins.includes('*'),
              maxAge
            };
            translatedRules.push({
              source: `traefik.http.middlewares.${mwName}.headers (CORS)`,
              target: 'domain.cors',
              summary: `origins=[${cors.allowedOrigins.join(', ')}] methods=[${cors.allowedMethods.join(',')}]`
            });
          }
        }

        // HSTS
        if (lowerHdr.stspreload !== undefined) {
          hstsPreload = String(lowerHdr.stspreload).toLowerCase() === 'true';
        }
        if (lowerHdr.stsseconds !== undefined) {
          const secs = Number(lowerHdr.stsseconds);
          if (Number.isFinite(secs) && secs >= 0 && secs <= 63072000) {
            hstsMaxAge = Math.round(secs);
          }
        }
        if (hstsPreload || hstsMaxAge !== undefined) {
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.headers (HSTS)`,
            target: 'domain.hstsPreload',
            summary: `maxAge=${hstsMaxAge ?? 31536000}s preload=${Boolean(hstsPreload)}`
          });
        }

        // Frame / CSP / Permissions-Policy
        if (String(lowerHdr.framedeny || '').toLowerCase() === 'true') {
          framePolicy = 'DENY';
        } else if (lowerHdr.customframeoptionsvalue) {
          const fv = String(lowerHdr.customframeoptionsvalue).trim().toUpperCase();
          if (fv === 'DENY' || fv === 'SAMEORIGIN') framePolicy = fv;
        }
        if (lowerHdr.contentsecuritypolicy && !/[\r\n\0]/.test(lowerHdr.contentsecuritypolicy)) {
          csp = String(lowerHdr.contentsecuritypolicy).trim().slice(0, 2048);
        }
        if (lowerHdr.permissionspolicy && !/[\r\n\0]/.test(lowerHdr.permissionspolicy)) {
          permissionsPolicy = String(lowerHdr.permissionspolicy).trim().slice(0, 512);
        }

        // Custom response / request headers
        for (const [hk, hv] of Object.entries(hdr)) {
          const respMatch = hk.match(/^customresponseheaders\.(.+)$/i);
          const reqMatch = hk.match(/^customrequestheaders\.(.+)$/i);
          const match = respMatch || reqMatch;
          if (!match) continue;
          const section = respMatch ? 'response' : 'request';
          const hName = match[1].trim();
          const hVal = String(hv ?? '');
          if (!HEADER_NAME_RE.test(hName) || HOP_BY_HOP_HEADER_RE.test(hName) || /[\r\n\0]/.test(hVal)) {
            warnings.push(`Cabecera insegura o reservada omitida en "${mwName}": "${hName}"`);
            continue;
          }
          if (!customHeaders[section]) customHeaders[section] = {};
          customHeaders[section][hName] = hVal.slice(0, 1024);
        }
        if (customHeaders.response || customHeaders.request) {
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.headers`,
            target: 'domain.customHeaders',
            summary: `${Object.keys(customHeaders.response || {}).length} response / ${Object.keys(customHeaders.request || {}).length} request headers`
          });
        }
      }

      // 4. forwardauth (Authelia / Authentik / Keycloak / OAuth2-Proxy)
      if (typesMap.forwardauth) {
        const fa = typesMap.forwardauth;
        /** @type {Record<string, string>} */
        const lowerFa = Object.create(null);
        for (const [fk, fv] of Object.entries(fa)) lowerFa[fk.toLowerCase()] = fv;
        const addr = String(lowerFa.address || '').trim();
        if (addr) {
          try {
            const parsed = new URL(addr);
            const dial = cm.sanitizeUpstreamDial(`${parsed.protocol}//${parsed.host}`, `forwardAuth(${mwName})`);
            const uri = (parsed.pathname || '/api/verify') + (parsed.search || '');
            if (uri.includes('..') || /[\s\r\n\0]/.test(uri)) {
              throw new Error(`URI inválida: ${uri}`);
            }
            const rawCopy = lowerFa.authresponseheaders
              ? String(lowerFa.authresponseheaders).split(',').map((h) => h.trim()).filter((h) => HEADER_NAME_RE.test(h) && !HOP_BY_HOP_HEADER_RE.test(h))
              : ['Remote-User', 'Remote-Groups', 'Remote-Name', 'Remote-Email'];
            forwardAuth = {
              enabled: true,
              upstream: dial,
              uri: parsed.pathname || '/api/verify',
              copyHeaders: rawCopy.length > 0 ? Array.from(new Set(rawCopy)) : ['Remote-User', 'Remote-Groups', 'Remote-Name', 'Remote-Email']
            };
            translatedRules.push({
              source: `traefik.http.middlewares.${mwName}.forwardauth`,
              target: 'domain.forwardAuth',
              summary: `${forwardAuth.upstream}${forwardAuth.uri} (${forwardAuth.copyHeaders.length} headers)`
            });
          } catch (err) {
            warnings.push(`Middleware forwardauth "${mwName}" bloqueado o inválido: ${err.message}`);
          }
        }
      }

      // 5. basicauth (htpasswd bcrypt -> Caddy basicAuth)
      if (typesMap.basicauth) {
        const ba = typesMap.basicauth;
        /** @type {Record<string, string>} */
        const lowerBa = Object.create(null);
        for (const [bk, bv] of Object.entries(ba)) lowerBa[bk.toLowerCase()] = bv;
        const rawUsers = String(lowerBa.users || '').trim();
        const realm = String(lowerBa.realm || 'Acceso protegido').replace(/[\r\n\0"]/g, '').slice(0, 80);
        if (rawUsers) {
          /** @type {Array<{ username: string, passwordHash: string }>} */
          const accounts = [];
          /** @type {string[]} */
          const legacyUsers = [];
          for (const entry of rawUsers.split(',')) {
            const cleaned = entry.trim().replace(/\$\$/g, '$');
            const sep = cleaned.indexOf(':');
            if (sep <= 0) continue;
            const username = cleaned.slice(0, sep).trim();
            const hash = cleaned.slice(sep + 1).trim();
            if (!/^[A-Za-z0-9._@+-]{1,64}$/.test(username)) continue;
            if (isBcryptHash(hash)) {
              accounts.push({ username, passwordHash: hash });
            } else {
              legacyUsers.push(username);
            }
          }
          if (legacyUsers.length > 0) {
            warnings.push(
              `Basic Auth "${mwName}": usuario(s) [${legacyUsers.join(', ')}] usan hash no-bcrypt (APR1/SHA1). Caddy exige bcrypt ($2a$/$2b$); regenera su contraseña en Culkibo.`
            );
          }
          if (accounts.length > 0) {
            basicAuth = { enabled: true, realm, accounts };
            basicAuthPreview = { enabled: true, realm, usernames: accounts.map((a) => a.username), accountCount: accounts.length };
            translatedRules.push({
              source: `traefik.http.middlewares.${mwName}.basicauth`,
              target: 'domain.basicAuth',
              summary: `${accounts.length} cuenta(s) bcrypt preservadas (realm="${realm}")`
            });
          }
        }
      }

      // 6. ipallowlist / ipwhitelist
      const ipMw = typesMap.ipallowlist || typesMap.ipwhitelist;
      if (ipMw && ipMw.sourcerange) {
        const cidrs = String(ipMw.sourcerange).split(',').map((s) => s.trim()).filter(Boolean);
        ipAllowlist.push(...cidrs);
        if (cidrs.length > 0) {
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.ipallowlist`,
            target: 'domain.ipAllowlist',
            summary: `${cidrs.length} rango(s) IP/CIDR`
          });
        }
      }

      // 7. ratelimit
      if (typesMap.ratelimit && typesMap.ratelimit.average) {
        const avg = Math.round(Number(typesMap.ratelimit.average));
        if (Number.isFinite(avg) && avg > 0) {
          // Traefik average es req/s por defecto; period puede ser 1m
          const period = String(typesMap.ratelimit.period || '1s').trim().toLowerCase();
          const windowSeconds = period.endsWith('m') ? (parseInt(period, 10) || 1) * 60 : (parseInt(period, 10) || 1);
          rateLimit = {
            enabled: true,
            requests: Math.min(100000, Math.max(1, avg)),
            windowSeconds: Math.min(3600, Math.max(1, windowSeconds))
          };
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.ratelimit`,
            target: 'domain.rateLimit',
            summary: `${rateLimit.requests} req / ${rateLimit.windowSeconds}s`
          });
        }
      }

      // 8. buffering (maxBodySizeMb)
      if (typesMap.buffering && typesMap.buffering.maxrequestbodybytes) {
        const bytes = Number(typesMap.buffering.maxrequestbodybytes);
        if (Number.isFinite(bytes) && bytes > 0) {
          maxBodySizeMb = Math.min(10240, Math.max(1, Math.ceil(bytes / (1024 * 1024))));
          translatedRules.push({
            source: `traefik.http.middlewares.${mwName}.buffering`,
            target: 'domain.maxBodySizeMb',
            summary: `${maxBodySizeMb} MB`
          });
        }
      }
    }

    const routerHosts = Array.from(new Set([
      ...(Array.isArray(opts.defaultHosts) ? opts.defaultHosts : []),
      ...Object.values(routers).flatMap((r) => r.hosts)
    ]));

    /** @type {Record<string, any>} */
    const edgeConfig = {};
    if (targetPort) edgeConfig.targetPort = targetPort;
    if (protocol !== 'http') edgeConfig.protocol = protocol;
    if (pathRoutes.length > 0) edgeConfig.pathRoutes = pathRoutes;
    if (pathRedirects.length > 0) edgeConfig.pathRedirects = pathRedirects;
    if (forwardAuth) edgeConfig.forwardAuth = forwardAuth;
    if (cors) edgeConfig.cors = cors;
    if (basicAuth) edgeConfig.basicAuth = basicAuth;
    if (hstsPreload !== undefined) edgeConfig.hstsPreload = hstsPreload;
    if (hstsMaxAge !== undefined) edgeConfig.hstsMaxAge = hstsMaxAge;
    if (framePolicy) edgeConfig.framePolicy = framePolicy;
    if (csp) edgeConfig.csp = csp;
    if (permissionsPolicy) edgeConfig.permissionsPolicy = permissionsPolicy;
    if (canonicalRedirect) edgeConfig.canonicalRedirect = canonicalRedirect;
    if (customHeaders.response || customHeaders.request) edgeConfig.customHeaders = customHeaders;
    if (ipAllowlist.length > 0) edgeConfig.ipAllowlist = Array.from(new Set(ipAllowlist));
    if (rateLimit) edgeConfig.rateLimit = rateLimit;
    if (maxBodySizeMb !== undefined) edgeConfig.maxBodySizeMb = maxBodySizeMb;

    // Vista pública redactada (sin hashes bcrypt)
    const previewEdgeConfig = {
      ...edgeConfig,
      ...(basicAuthPreview ? { basicAuth: basicAuthPreview } : {})
    };

    return {
      traefikLabelCount,
      hosts: routerHosts,
      targetPort,
      edgeConfig,
      previewEdgeConfig,
      translatedRules,
      warnings,
      unsupportedLabels
    };
  }

  // ===========================================================================
  // 3. SCHEDULED TASKS → CULKIBO CRONS TRANSLATOR
  // ===========================================================================

  /**
   * Traduce `scheduled_tasks` de Coolify v4 a definiciones nativas de `cronManager`.
   * @param {any[]} tasks
   * @param {string} resourceName
   */
  translateScheduledTasks(tasks, resourceName) {
    /** @type {Array<{ name: string, schedule: string, mode: 'exec', command: string, container: string | null, enabled: boolean, valid: boolean, warning: string | null, sourceResource: string }>} */
    const mapped = [];
    /** @type {string[]} */
    const warnings = [];

    if (!Array.isArray(tasks)) return { crons: mapped, warnings };

    for (const task of tasks) {
      if (!task || typeof task !== 'object') continue;
      const name = String(task.name || `${resourceName} task`).trim().slice(0, 80);
      const rawFreq = String(task.frequency || task.schedule || '').trim();
      const lowerFreq = rawFreq.toLowerCase();
      const schedule = Object.prototype.hasOwnProperty.call(COOLIFY_CRON_ALIASES, lowerFreq)
        ? COOLIFY_CRON_ALIASES[/** @type {keyof typeof COOLIFY_CRON_ALIASES} */ (lowerFreq)]
        : rawFreq;
      const command = String(task.command || '').trim();
      const enabled = task.enabled !== false;
      const container = task.container ? String(task.container).trim() : null;

      /** @type {string | null} */
      let warning = null;
      let valid = true;
      try {
        parseCron(schedule);
      } catch (err) {
        valid = false;
        warning = `Expresión cron inválida "${rawFreq}" en tarea "${name}": ${err.message}`;
      }
      if (valid) {
        try {
          parseSafeCommandArgv(command);
        } catch (err) {
          valid = false;
          warning = `Tarea programada "${name}" usa sintaxis de shell no permitida por el invariante zero-shell de Culkibo ("${command.slice(0, 80)}"): divídela en comando argv directo o endpoint HTTP cron.`;
        }
      }

      if (warning) warnings.push(warning);
      mapped.push({
        name,
        schedule,
        mode: 'exec',
        command,
        container,
        enabled,
        valid,
        warning,
        sourceResource: resourceName
      });
    }

    return { crons: mapped, warnings };
  }

  // ===========================================================================
  // 4. PRE-FLIGHT DIFF & MIGRATION READINESS REPORT (`planMigration`)
  // ===========================================================================

  /**
   * Construye un informe determinista de paridad y pre-vuelo a partir de un snapshot
   * de Coolify v4 (API en vivo o JSON offline) sin mutar ningún estado ni filtrar secretos.
   *
   * @param {{
   *   apps?: any[],
   *   databases?: any[],
   *   services?: any[],
   *   projects?: any[],
   *   sharedEnvs?: any[]
   * }} snapshot
   * @param {{
   *   selectedApps?: string[] | null,
   *   selectedDbs?: string[] | null,
   *   selectedServices?: string[] | null
   * }} [options]
   */
  buildMigrationPlan(snapshot, options = {}) {
    /** @type {any[]} */
    const apps = Array.isArray(snapshot && snapshot.apps) ? (snapshot.apps || []) : [];
    /** @type {any[]} */
    const databases = Array.isArray(snapshot && snapshot.databases) ? (snapshot.databases || []) : [];
    /** @type {any[]} */
    const services = Array.isArray(snapshot && snapshot.services) ? (snapshot.services || []) : [];
    /** @type {any[]} */
    const projects = Array.isArray(snapshot && snapshot.projects) ? (snapshot.projects || []) : [];
    /** @type {any[]} */
    const sharedEnvs = Array.isArray(snapshot && snapshot.sharedEnvs) ? (snapshot.sharedEnvs || []) : [];

    const appsToPlan = Array.isArray(options.selectedApps) ? apps.filter((a) => options.selectedApps && options.selectedApps.includes(a.uuid)) : apps;
    const dbsToPlan = Array.isArray(options.selectedDbs) ? databases.filter((d) => options.selectedDbs && options.selectedDbs.includes(d.uuid)) : databases;
    const svcsToPlan = Array.isArray(options.selectedServices) ? services.filter((s) => options.selectedServices && options.selectedServices.includes(s.uuid)) : services;

    /** @type {Record<string, string>} */
    const sharedEnvMap = {};
    for (const ev of sharedEnvs) {
      if (ev && ev.key && !FORBIDDEN_PROTO_KEYS.has(ev.key)) {
        sharedEnvMap[ev.key] = ev.value ?? '';
      }
    }

    /** @type {any[]} */
    const magicVariables = [];
    /** @type {any[]} */
    const traefikTranslations = [];
    /** @type {any[]} */
    const crons = [];
    /** @type {any[]} */
    const databasePlans = [];
    /** @type {string[]} */
    const secretWarnings = [];
    /** @type {string[]} */
    const warnings = [];
    /** @type {Set<string>} */
    const allVaultRefs = new Set();
    /** @type {Array<{ hostname: string, resourceName: string, targetPort: number, hasEdgeRules: boolean, healthPath: string }>} */
    const domainTargets = [];
    /** @type {Map<string, { id: string, name: string, resources: any[] }>} */
    const projectMap = new Map();

    let totalVolumes = 0;
    let totalFileMounts = 0;
    let totalHealthchecks = 0;
    let totalTraefikRules = 0;
    let totalUnsupportedTraefik = 0;
    let totalUnmappedMagic = 0;
    let totalInvalidCrons = 0;

    const getProjectBucket = (res) => {
      let id = 'coolify_import';
      let name = 'Importado de Coolify';
      if (res.environment && res.environment.project) {
        id = String(res.environment.project.uuid || res.environment.project.id || id);
        name = res.environment.project.name || name;
      } else if (res.project_id && projects.length > 0) {
        const match = projects.find((p) => p.id === res.project_id || p.uuid === res.project_id);
        if (match) {
          id = String(match.uuid || match.id || id);
          name = match.name || name;
        }
      }
      let bucket = projectMap.get(id);
      if (!bucket) {
        bucket = { id, name, resources: [] };
        projectMap.set(id, bucket);
      }
      return bucket;
    };

    const extractEnvMaps = (res) => {
      /** @type {Record<string, string>} */
      const runtime = { ...sharedEnvMap };
      /** @type {Record<string, string>} */
      const preview = {};
      if (Array.isArray(res.environment_variables)) {
        for (const ev of res.environment_variables) {
          if (!ev || !ev.key || FORBIDDEN_PROTO_KEYS.has(ev.key)) continue;
          if (ev.is_preview) preview[ev.key] = ev.value ?? '';
          else runtime[ev.key] = ev.value ?? '';
        }
      }
      return { runtime, preview };
    };

    // 1. Plan Apps
    for (const app of appsToPlan) {
      const hosts = this.parseFqdnHosts(app.fqdn);
      const { runtime, preview } = extractEnvMaps(app);
      const firstPort = parseInt(String(app.ports_exposes || app.port || '').split(',')[0], 10);
      const defaultPort = Number.isInteger(firstPort) && firstPort > 0 && firstPort < 65536 ? firstPort : 3000;

      const magic = this.translateMagicVariables(runtime, {
        resourceName: app.name || app.uuid,
        fqdn: app.fqdn,
        hosts,
        gitBranch: app.git_branch || 'main',
        uuid: app.uuid,
        projectUuid: app.project_id ? String(app.project_id) : undefined,
        dockerCompose: app.docker_compose || app.docker_compose_raw || ''
      });
      const traefik = this.parseTraefikLabels(app.custom_labels, {
        defaultPort,
        defaultHosts: hosts,
        composeYaml: app.docker_compose || app.docker_compose_raw || ''
      });
      const taskPlan = this.translateScheduledTasks(app.scheduled_tasks || [], app.name || 'App');

      const vols = (app.local_persistent_volumes || app.persistent_volumes || app.volumes || []).length;
      const mounts = (app.local_file_volumes || app.file_volumes || []).length;
      const hasHealth = Boolean(app.health_check_enabled || app.health_check_path);
      totalVolumes += vols;
      totalFileMounts += mounts;
      if (hasHealth) totalHealthchecks++;
      totalTraefikRules += traefik.translatedRules.length;
      totalUnsupportedTraefik += traefik.unsupportedLabels.length;
      totalUnmappedMagic += magic.unmappedMagicVars.length;

      for (const mv of magic.magicVarsFound) magicVariables.push({ resourceName: app.name || app.uuid, resourceId: app.uuid, ...mv });
      for (const vr of magic.vaultRefs) allVaultRefs.add(vr);
      secretWarnings.push(...magic.secretWarnings);
      warnings.push(...traefik.warnings, ...taskPlan.warnings, ...magic.unmappedMagicVars);

      if (traefik.traefikLabelCount > 0) {
        traefikTranslations.push({
          resourceId: app.uuid,
          resourceName: app.name || 'Coolify App',
          hosts: traefik.hosts,
          labelCount: traefik.traefikLabelCount,
          translatedRules: traefik.translatedRules,
          edgeConfig: traefik.previewEdgeConfig,
          unsupportedLabels: traefik.unsupportedLabels,
          warnings: traefik.warnings
        });
      }

      for (const c of taskPlan.crons) {
        crons.push(c);
        if (!c.valid) totalInvalidCrons++;
      }

      const effectivePort = traefik.targetPort || defaultPort;
      for (const host of Array.from(new Set([...hosts, ...traefik.hosts]))) {
        domainTargets.push({
          hostname: host,
          resourceName: app.name || 'Coolify App',
          targetPort: effectivePort,
          hasEdgeRules: traefik.translatedRules.length > 0,
          healthPath: app.health_check_path || '/'
        });
      }

      const bucket = getProjectBucket(app);
      bucket.resources.push({
        id: app.uuid,
        type: 'app',
        name: app.name || 'Coolify App',
        buildPack: app.build_pack || (app.docker_registry_image_name ? 'dockerimage' : 'nixpacks'),
        hosts,
        targetPort: effectivePort,
        envCount: Object.keys(runtime).length,
        previewEnvCount: Object.keys(preview).length,
        magicVarsCount: magic.magicVarsFound.length,
        traefikRulesCount: traefik.translatedRules.length,
        cronsCount: taskPlan.crons.length,
        volumesCount: vols,
        fileMountsCount: mounts,
        hasHealthcheck: hasHealth,
        redactedEnvPreview: magic.redactedPreviewEnv
      });
    }

    // 2. Plan Databases
    for (const db of dbsToPlan) {
      const resolved = this.resolveDatabaseEngine(db);
      const catalog = DB_ENGINE_CATALOG[/** @type {keyof typeof DB_ENGINE_CATALOG} */ (resolved.engine)] || {
        engine: resolved.engine,
        label: resolved.engine,
        defaultPort: Number(db.port) || 5432,
        defaultImage: db.image || '',
        parity: 'partial',
        dumpHint: () => `Volcar datos desde contenedor Coolify (${resolved.engine})`,
        restoreHint: () => `Restaurar volcado en instancia destino de Culkibo`
      };
      const vols = (db.local_persistent_volumes || db.persistent_volumes || db.volumes || []).length;
      const mounts = (db.local_file_volumes || db.file_volumes || []).length;
      totalVolumes += vols;
      totalFileMounts += mounts;

      const dbSlug = slugify(db.name || db.uuid || 'db');
      const dbUser = db.database_user || db.postgres_user || db.mysql_user || db.mariadb_user || db.mongo_initdb_root_username || db.clickhouse_admin_user || '';
      const dbName = db.database_name || db.postgres_db || db.mysql_database || db.mariadb_database || '';
      const hasPassword = Boolean(
        db.database_password || db.postgres_password || db.mysql_password || db.mariadb_password
        || db.mongo_initdb_root_password || db.redis_password || db.keydb_password || db.dragonfly_password
        || db.clickhouse_admin_password
      );
      if (hasPassword) {
        allVaultRefs.add(toVaultKey(`${dbSlug}_PASSWORD`));
      }
      if (db.is_public) {
        warnings.push(`Base de datos "${db.name}" tenía puerto público expuesto en Coolify; Culkibo la aislará en red privada (127.0.0.1) por seguridad.`);
      }
      if (resolved.note) warnings.push(`${db.name}: ${resolved.note}`);

      databasePlans.push({
        id: db.uuid,
        name: db.name || 'Coolify DB',
        originalType: resolved.originalType,
        culkiboEngine: catalog.engine,
        label: catalog.label,
        image: db.image || catalog.defaultImage,
        port: Number(db.public_port || db.port) || catalog.defaultPort,
        dbName,
        username: dbUser,
        hasPassword,
        isPublicInCoolify: Boolean(db.is_public),
        volumesCount: vols,
        parity: catalog.parity,
        note: resolved.note,
        dumpCommand: catalog.dumpHint({ slug: dbSlug, user: dbUser, dbName }),
        restoreCommand: catalog.restoreHint({ slug: dbSlug, user: dbUser, dbName })
      });

      const bucket = getProjectBucket(db);
      bucket.resources.push({
        id: db.uuid,
        type: 'database',
        name: db.name || 'Coolify DB',
        engine: catalog.engine,
        originalType: resolved.originalType,
        volumesCount: vols,
        fileMountsCount: mounts
      });
    }

    // 3. Plan Services (Multi-container Compose stacks)
    for (const svc of svcsToPlan) {
      const composeRaw = maybeDecodeBase64Text(svc.docker_compose || svc.docker_compose_raw || '');
      const subServices = inspectComposeServices(composeRaw);
      /** @type {Record<string, { host: string, url: string }>} */
      const serviceHostMap = Object.create(null);
      const svcHosts = [...this.parseFqdnHosts(svc.fqdn)];
      if (Array.isArray(svc.applications)) {
        for (const subApp of svc.applications) {
          const subUrls = this.parseFqdnUrls(subApp && subApp.fqdn);
          const subKey = toVaultKey(subApp && (subApp.name || subApp.service_name) || '');
          if (subUrls[0] && subKey) {
            serviceHostMap[subKey] = { host: subUrls[0].host, url: subUrls[0].url };
          }
          svcHosts.push(...this.parseFqdnHosts(subApp && subApp.fqdn));
        }
      }
      const uniqueHosts = Array.from(new Set(svcHosts));
      const { runtime } = extractEnvMaps(svc);

      const magic = this.translateMagicVariables(runtime, {
        resourceName: svc.name || svc.uuid,
        fqdn: svc.fqdn || (uniqueHosts[0] ? `https://${uniqueHosts[0]}` : ''),
        hosts: uniqueHosts,
        serviceHostMap,
        uuid: svc.uuid,
        dockerCompose: composeRaw
      });
      const traefik = this.parseTraefikLabels(svc.custom_labels, {
        defaultPort: 3000,
        defaultHosts: uniqueHosts,
        composeYaml: composeRaw
      });
      const taskPlan = this.translateScheduledTasks(svc.scheduled_tasks || [], svc.name || 'Service');

      const vols = (svc.local_persistent_volumes || svc.persistent_volumes || svc.volumes || []).length;
      const mounts = (svc.local_file_volumes || svc.file_volumes || []).length;
      totalVolumes += vols;
      totalFileMounts += mounts;
      if (subServices.some((s) => s.hasHealthcheck)) totalHealthchecks++;
      totalTraefikRules += traefik.translatedRules.length;
      totalUnsupportedTraefik += traefik.unsupportedLabels.length;
      totalUnmappedMagic += magic.unmappedMagicVars.length;

      for (const mv of magic.magicVarsFound) magicVariables.push({ resourceName: svc.name || svc.uuid, resourceId: svc.uuid, ...mv });
      for (const vr of magic.vaultRefs) allVaultRefs.add(vr);
      secretWarnings.push(...magic.secretWarnings);
      warnings.push(...traefik.warnings, ...taskPlan.warnings, ...magic.unmappedMagicVars);

      if (traefik.traefikLabelCount > 0) {
        traefikTranslations.push({
          resourceId: svc.uuid,
          resourceName: svc.name || 'Coolify Service',
          hosts: traefik.hosts,
          labelCount: traefik.traefikLabelCount,
          translatedRules: traefik.translatedRules,
          edgeConfig: traefik.previewEdgeConfig,
          unsupportedLabels: traefik.unsupportedLabels,
          warnings: traefik.warnings
        });
      }
      for (const c of taskPlan.crons) {
        crons.push(c);
        if (!c.valid) totalInvalidCrons++;
      }

      for (const host of Array.from(new Set([...uniqueHosts, ...traefik.hosts]))) {
        domainTargets.push({
          hostname: host,
          resourceName: svc.name || 'Coolify Service',
          targetPort: traefik.targetPort || 3000,
          hasEdgeRules: traefik.translatedRules.length > 0,
          healthPath: '/'
        });
      }

      const bucket = getProjectBucket(svc);
      bucket.resources.push({
        id: svc.uuid,
        type: 'service',
        name: svc.name || 'Coolify Service',
        composeServices: subServices.map((s) => ({ name: s.name, image: s.image })),
        hosts: uniqueHosts,
        magicVarsCount: magic.magicVarsFound.length,
        traefikRulesCount: traefik.translatedRules.length,
        cronsCount: taskPlan.crons.length,
        volumesCount: vols,
        fileMountsCount: mounts,
        redactedEnvPreview: magic.redactedPreviewEnv
      });
    }

    // Calcular Parity Score determinista (0..100%)
    const totalResources = appsToPlan.length + dbsToPlan.length + svcsToPlan.length;
    let penalty = 0;
    penalty += Math.min(20, totalUnsupportedTraefik * 4);
    penalty += Math.min(15, totalUnmappedMagic * 3);
    penalty += Math.min(15, totalInvalidCrons * 5);
    const partialDbs = databasePlans.filter((d) => d.parity !== 'full').length;
    penalty += Math.min(20, partialDbs * 8);
    const parityScore = totalResources === 0 ? 100 : Math.max(40, Math.min(100, 100 - penalty));
    const readinessLevel = parityScore >= 90 ? 'ready' : (parityScore >= 70 ? 'ready_with_warnings' : 'manual_review_needed');

    // Deduplicar dominios para checklist DNS
    /** @type {Map<string, { hostname: string, resourceName: string, targetPort: number, hasEdgeRules: boolean, healthPath: string }>} */
    const uniqueDomainMap = new Map();
    for (const dt of domainTargets) {
      if (!uniqueDomainMap.has(dt.hostname)) uniqueDomainMap.set(dt.hostname, dt);
    }
    const uniqueDomains = Array.from(uniqueDomainMap.values());

    const dnsCutoverChecklist = [
      {
        step: 1,
        id: 'lower_ttl',
        title: 'Reducir TTL DNS a 60 segundos (si no usas Cloudflare Proxy)',
        detail: uniqueDomains.length > 0
          ? `Aplica a ${uniqueDomains.length} dominio(s): ${uniqueDomains.map((d) => d.hostname).join(', ')}`
          : 'Sin dominios públicos detectados; paso opcional.',
        required: uniqueDomains.length > 0
      },
      {
        step: 2,
        id: 'populate_vault',
        title: `Cargar ${allVaultRefs.size} clave(s) en el Vault cifrado AES-256-GCM`,
        detail: allVaultRefs.size > 0
          ? `Claves requeridas: ${Array.from(allVaultRefs).sort().join(', ')}`
          : 'No se requieren claves adicionales en el Vault.',
        required: allVaultRefs.size > 0
      },
      {
        step: 3,
        id: 'sync_data',
        title: `Volcar y sincronizar ${databasePlans.length} BD(s) y ${totalVolumes} volumen(es)`,
        detail: databasePlans.length > 0
          ? `Motores: ${Array.from(new Set(databasePlans.map((d) => d.label))).join(', ')}`
          : 'Sin bases de datos o volúmenes stateful.',
        required: databasePlans.length > 0 || totalVolumes > 0
      },
      {
        step: 4,
        id: 'smoke_verify',
        title: 'Ejecutar verificación pre-cutover (Host header contra IP de Culkibo)',
        detail: 'Valida HTTP 200, cabeceras CORS/HSTS y rutas Caddy antes de mover tráfico real.',
        required: true
      },
      {
        step: 5,
        id: 'dns_flip',
        title: 'Conmutación DNS atómica (Cloudflare API o registro A)',
        detail: 'Culkibo emite certificados TLS automáticos y enruta tráfico con 0 ms de caída.',
        required: uniqueDomains.length > 0
      }
    ];

    const rollbackPlan = {
      sourceUntouched: true,
      estimatedRollbackSeconds: 30,
      steps: [
        'Tu servidor Coolify v4 original NO ha sido modificado (migración 100% solo-lectura).',
        'Mantén los contenedores de Coolify arrancados en paralelo durante 24-48 h tras el cutover.',
        uniqueDomains.length > 0
          ? `Para revertir al instante: apunta el registro A de [${uniqueDomains.map((d) => d.hostname).join(', ')}] de vuelta a la IP del VPS de Coolify.`
          : 'Para revertir: reactiva el servicio correspondiente en el panel de Coolify.',
        'Si hubo escrituras en BD tras el cutover, ejecuta un dump incremental antes de volver atrás.'
      ]
    };

    return {
      generatedAt: new Date().toISOString(),
      parityScore,
      readinessLevel,
      parityBreakdown: {
        apps: { total: appsToPlan.length, supported: appsToPlan.length },
        databases: { total: dbsToPlan.length, fullParity: dbsToPlan.length - partialDbs, partial: partialDbs },
        services: { total: svcsToPlan.length, supported: svcsToPlan.length },
        magicVariables: { total: magicVariables.length, translated: magicVariables.length, unmapped: totalUnmappedMagic },
        traefikRules: { translated: totalTraefikRules, unsupported: totalUnsupportedTraefik },
        crons: { total: crons.length, valid: crons.length - totalInvalidCrons, needsReview: totalInvalidCrons }
      },
      summary: {
        projects: projectMap.size,
        apps: appsToPlan.length,
        databases: dbsToPlan.length,
        services: svcsToPlan.length,
        domains: uniqueDomains.length,
        magicVarsTranslated: magicVariables.length,
        traefikRulesTranslated: totalTraefikRules,
        cronsMapped: crons.length,
        volumesCount: totalVolumes,
        fileMountsCount: totalFileMounts,
        healthchecksCount: totalHealthchecks,
        vaultRefsNeeded: allVaultRefs.size
      },
      projects: Array.from(projectMap.values()),
      domains: uniqueDomains,
      databases: databasePlans,
      magicVariables,
      traefikTranslations,
      crons,
      vaultRefs: Array.from(allVaultRefs).sort(),
      secretWarnings: Array.from(new Set(secretWarnings)),
      warnings: Array.from(new Set(warnings)),
      dnsCutoverChecklist,
      rollbackPlan
    };
  }

  /**
   * Planifica una migración conectándose en vivo a la API de Coolify v4.
   * @param {string} apiUrl
   * @param {string} apiToken
   * @param {{ apps?: string[] | null, dbs?: string[] | null, services?: string[] | null }} [options]
   */
  async planMigration(apiUrl, apiToken, options = {}) {
    const apps = await this.fetchApplications(apiUrl, apiToken);
    const databases = await this.fetchDatabases(apiUrl, apiToken);
    const services = await this.fetchServices(apiUrl, apiToken);
    const projects = await this.fetchProjects(apiUrl, apiToken);
    return this.buildMigrationPlan(
      { apps, databases, services, projects },
      {
        selectedApps: options.apps !== undefined ? options.apps : null,
        selectedDbs: options.dbs !== undefined ? options.dbs : null,
        selectedServices: options.services !== undefined ? options.services : null
      }
    );
  }

  // ===========================================================================
  // 5. EXECUTION ENGINE (`executeMigration`, `migrate`, `migrateFromSnapshot`)
  // ===========================================================================

  async executeMigration(apiUrl, apiToken, options = {}) {
    return this.migrate(
      apiUrl,
      apiToken,
      options.apps !== undefined ? options.apps : null,
      options.dbs !== undefined ? options.dbs : null,
      options.services !== undefined ? options.services : null,
      options
    );
  }

  /**
   * @param {string} apiUrl
   * @param {string} apiToken
   * @param {string[] | null} [selectedApps]
   * @param {string[] | null} [selectedDbs]
   * @param {string[] | null} [selectedServices]
   * @param {Record<string, any>} [extraOpts]
   */
  async migrate(apiUrl, apiToken, selectedApps = null, selectedDbs = null, selectedServices = null, extraOpts = {}) {
    const apps = await this.fetchApplications(apiUrl, apiToken);
    const databases = await this.fetchDatabases(apiUrl, apiToken);
    const services = await this.fetchServices(apiUrl, apiToken);
    const projects = await this.fetchProjects(apiUrl, apiToken);

    return this.migrateFromSnapshot(
      { apps, databases, services, projects },
      {
        ...extraOpts,
        selectedApps,
        selectedDbs,
        selectedServices
      }
    );
  }

  /**
   * Ejecuta la migración completa desde un snapshot de Coolify v4 (API o JSON offline).
   *
   * @param {{ apps?: any[], databases?: any[], services?: any[], projects?: any[], sharedEnvs?: any[] }} snapshot
   * @param {{
   *   selectedApps?: string[] | null,
   *   selectedDbs?: string[] | null,
   *   selectedServices?: string[] | null,
   *   syncCrons?: boolean,
   *   projectManager?: any,
   *   domainManager?: any,
   *   cronManager?: any
   * }} [options]
   */
  async migrateFromSnapshot(snapshot, options = {}) {
    const pm = options.projectManager || projectManager;
    const dm = options.domainManager || domainManager;
    const cm = options.cronManager !== undefined ? options.cronManager : getCronManager();

    /** @type {any[]} */
    const apps = Array.isArray(snapshot && snapshot.apps) ? (snapshot.apps || []) : [];
    /** @type {any[]} */
    const databases = Array.isArray(snapshot && snapshot.databases) ? (snapshot.databases || []) : [];
    /** @type {any[]} */
    const services = Array.isArray(snapshot && snapshot.services) ? (snapshot.services || []) : [];
    /** @type {any[]} */
    const projects = Array.isArray(snapshot && snapshot.projects) ? (snapshot.projects || []) : [];
    /** @type {any[]} */
    const sharedEnvs = Array.isArray(snapshot && snapshot.sharedEnvs) ? (snapshot.sharedEnvs || []) : [];

    const selectedApps = options.selectedApps !== undefined ? options.selectedApps : null;
    const selectedDbs = options.selectedDbs !== undefined ? options.selectedDbs : null;
    const selectedServices = options.selectedServices !== undefined ? options.selectedServices : null;

    const plan = this.buildMigrationPlan(snapshot, { selectedApps, selectedDbs, selectedServices });

    const results = {
      importedApps: 0,
      importedDbs: 0,
      importedServices: 0,
      importedCrons: 0,
      domainsLinked: 0,
      traefikRulesApplied: 0,
      magicVarsTranslated: plan.summary.magicVarsTranslated,
      vaultRefs: plan.vaultRefs,
      parityScore: plan.parityScore,
      createdProjects: /** @type {Array<{ id: string, name: string, domains: string[] }>} */ ([]),
      dnsCutoverChecklist: plan.dnsCutoverChecklist,
      rollbackPlan: plan.rollbackPlan,
      warnings: [...plan.warnings],
      errors: /** @type {string[]} */ ([])
    };

    // Semántica estricta: null/undefined = importar todos; array explícito (incluido []) = sólo los seleccionados.
    const appsToImport = Array.isArray(selectedApps) ? apps.filter(app => selectedApps.includes(app.uuid)) : apps;
    const dbsToImport = Array.isArray(selectedDbs) ? databases.filter(db => selectedDbs.includes(db.uuid)) : databases;
    const servicesToImport = Array.isArray(selectedServices) ? services.filter(svc => selectedServices.includes(svc.uuid)) : services;

    /** @type {Record<string, string>} */
    const sharedEnvMap = {};
    for (const ev of sharedEnvs) {
      if (ev && ev.key && !FORBIDDEN_PROTO_KEYS.has(ev.key)) {
        sharedEnvMap[ev.key] = ev.value ?? '';
      }
    }

    const culkiboProjects = new Map();

    const getProjectForResource = (resource) => {
      let projectName = 'Importado de Coolify';
      let projectDesc = 'Recursos migrados de Coolify';
      let projectId = 'coolify_import';

      if (resource.environment && resource.environment.project) {
        projectName = resource.environment.project.name || projectName;
        projectDesc = resource.environment.project.description || projectDesc;
        projectId = resource.environment.project.uuid || resource.environment.project.id || projectId;
      } else if (resource.project_id && projects.length) {
        const p = projects.find(proj => proj.id === resource.project_id || proj.uuid === resource.project_id);
        if (p) {
          projectName = p.name;
          projectDesc = p.description || projectDesc;
          projectId = p.uuid || p.id || projectId;
        }
      }

      const key = String(projectId);
      if (!culkiboProjects.has(key)) {
        culkiboProjects.set(key, {
          id: key,
          name: projectName,
          description: projectDesc,
          icon: '🚀',
          status: 'active',
          source: 'coolify-import',
          resources: [],
          domains: [],
          pendingHosts: [],
          domainEdgeConfigs: new Map(),
          pendingCrons: [],
          smokeTests: [],
          envVars: {},
          volumes: [],
          fileMounts: []
        });
      }
      return culkiboProjects.get(key);
    };

    const extractCommonFields = (res) => {
      /** @type {Record<string, string>} */
      const envVars = { ...sharedEnvMap };
      /** @type {Record<string, string>} */
      const previewEnvVars = {};
      if (res.environment_variables && Array.isArray(res.environment_variables)) {
        res.environment_variables.forEach(ev => {
          if (!ev || !ev.key || FORBIDDEN_PROTO_KEYS.has(ev.key)) return;
          if (ev.is_preview) {
            previewEnvVars[ev.key] = ev.value ?? '';
          } else {
            envVars[ev.key] = ev.value ?? '';
          }
        });
      }

      const volumes = res.local_persistent_volumes || res.persistent_volumes || res.volumes || [];
      const fileMounts = res.local_file_volumes || res.file_volumes || [];

      const resourceLimits = {
        limits_memory: res.limits_memory,
        limits_cpus: res.limits_cpus,
        limits_cpuset: res.limits_cpuset,
        limits_cpu_shares: res.limits_cpu_shares,
        limits_memory_swap: res.limits_memory_swap
      };

      const healthCheck = {
        health_check_path: res.health_check_path,
        health_check_port: res.health_check_port,
        health_check_enabled: res.health_check_enabled,
        health_check_interval: res.health_check_interval,
        health_check_timeout: res.health_check_timeout,
        health_check_retries: res.health_check_retries,
        health_check_method: res.health_check_method
      };

      const networkConfig = {
        redirect: res.redirect,
        custom_nginx_configuration: res.custom_nginx_configuration,
        custom_network_aliases: res.custom_network_aliases,
        custom_labels: res.custom_labels
      };

      return { envVars, previewEnvVars, volumes, fileMounts, resourceLimits, healthCheck, networkConfig };
    };

    // 1. Migrate Apps
    for (const app of appsToImport) {
      try {
        const hosts = this.parseFqdnHosts(app.fqdn);
        const common = extractCommonFields(app);
        const firstPort = parseInt(String(app.ports_exposes || app.port || '').split(',')[0], 10);
        const validFirstPort = Number.isInteger(firstPort) && firstPort > 0 && firstPort < 65536 ? firstPort : null;

        const magic = this.translateMagicVariables(common.envVars, {
          resourceName: app.name || app.uuid,
          fqdn: app.fqdn,
          hosts,
          gitBranch: app.git_branch || 'main',
          uuid: app.uuid,
          projectUuid: app.project_id ? String(app.project_id) : undefined,
          dockerCompose: app.docker_compose || app.docker_compose_raw || ''
        });
        const traefik = this.parseTraefikLabels(app.custom_labels, {
          defaultPort: validFirstPort || 3000,
          defaultHosts: hosts,
          composeYaml: app.docker_compose || app.docker_compose_raw || ''
        });
        const taskPlan = this.translateScheduledTasks(app.scheduled_tasks || [], app.name || 'Coolify App');

        const buildConfig = {
          install_command: app.install_command,
          build_command: app.build_command,
          start_command: app.start_command,
          base_directory: app.base_directory,
          publish_directory: app.publish_directory,
          dockerfile: app.dockerfile,
          dockerfile_location: app.dockerfile_location,
          build_pack: app.build_pack
        };

        const deployCommands = {
          pre_deployment_command: app.pre_deployment_command,
          post_deployment_command: app.post_deployment_command
        };

        const imageName = app.docker_registry_image_name
          ? (app.docker_registry_image_tag ? `${app.docker_registry_image_name}:${app.docker_registry_image_tag}` : app.docker_registry_image_name)
          : '';
        const gitDetails = {
          git_full_url: app.git_full_url,
          git_commit_sha: app.git_commit_sha,
          private_key_id: app.private_key_id,
          docker_registry_image_name: app.docker_registry_image_name,
          docker_registry_image_tag: app.docker_registry_image_tag
        };

        const proj = getProjectForResource(app);
        const rawRepo = String(app.git_repository || app.git_full_url || '').trim();
        const isCoolifyDummyRepo = app.build_pack === 'dockerimage'
          || (Boolean(app.docker_registry_image_name) && /^(?:https?:\/\/github\.com\/)?coollabsio\/coolify(?:\.git)?$/i.test(rawRepo));
        const effectiveGitRepo = isCoolifyDummyRepo ? '' : rawRepo;

        const effectivePort = traefik.targetPort || validFirstPort;
        if (!proj.gitRepo && effectiveGitRepo) proj.gitRepo = effectiveGitRepo;
        if (!proj.gitBranch && app.git_branch) proj.gitBranch = app.git_branch;
        if (!proj.buildCommand && app.build_command) proj.buildCommand = app.build_command;
        if (!proj.startCommand && app.start_command) proj.startCommand = app.start_command;
        if (!proj.baseDirectory && app.base_directory) proj.baseDirectory = app.base_directory;
        if (!proj.preDeployCommand && app.pre_deployment_command) proj.preDeployCommand = app.pre_deployment_command;
        if (!proj.postDeployCommand && app.post_deployment_command) proj.postDeployCommand = app.post_deployment_command;
        if (!proj.healthPath && app.health_check_path) proj.healthPath = app.health_check_path;
        if (!proj.containerPort && effectivePort) {
          proj.containerPort = effectivePort;
          proj.citadelPort = effectivePort;
        }
        const memMb = this.parseMemoryMb(app.limits_memory);
        if (!proj.memoryMb && memMb) {
          proj.memoryMb = memMb;
          proj.memoryLimitMb = memMb;
        }
        if (!proj.cpus && app.limits_cpus && Number(app.limits_cpus) > 0) {
          proj.cpus = Number(app.limits_cpus);
          proj.cpuLimit = Number(app.limits_cpus);
        }

        // Auto-generar Smoke Test nativo de Culkibo desde el healthcheck de Coolify
        if (app.health_check_path && String(app.health_check_path).startsWith('/')) {
          proj.smokeTests.push({
            name: `${app.name || 'App'} healthcheck`,
            method: String(app.health_check_method || 'GET').toUpperCase() === 'HEAD' ? 'HEAD' : 'GET',
            path: String(app.health_check_path).trim(),
            expectStatus: '2xx',
            timeoutMs: Math.min(30000, Math.max(1000, (Number(app.health_check_timeout) || 5) * 1000))
          });
        }

        // Propagar variables traducidas, volúmenes y fileMounts al proyecto raíz
        if (Object.keys(proj.envVars).length === 0 && Object.keys(magic.translatedEnv).length > 0) {
          Object.assign(proj.envVars, magic.translatedEnv);
        }
        if (Array.isArray(common.volumes) && common.volumes.length > 0 && proj.volumes.length === 0) {
          proj.volumes.push(...common.volumes);
        }
        if (Array.isArray(common.fileMounts) && common.fileMounts.length > 0 && proj.fileMounts.length === 0) {
          proj.fileMounts.push(...common.fileMounts);
        }

        for (const c of taskPlan.crons) {
          if (c.valid) proj.pendingCrons.push(c);
        }

        const mergedHosts = Array.from(new Set([...hosts, ...traefik.hosts]));
        proj.resources.push({
          id: app.uuid,
          type: 'app',
          name: app.name || 'Coolify App',
          description: app.description || `App migrada de Coolify (${app.uuid})`,
          gitRepo: effectiveGitRepo,
          image: imageName || undefined,
          domains: mergedHosts,
          envVars: magic.translatedEnv,
          previewEnvVars: common.previewEnvVars,
          magicVarsTranslated: magic.magicVarsFound.length,
          vaultRefs: magic.vaultRefs,
          traefikEdgeConfig: traefik.previewEdgeConfig,
          volumes: common.volumes,
          fileMounts: common.fileMounts,
          resourceLimits: common.resourceLimits,
          healthCheck: common.healthCheck,
          networkConfig: common.networkConfig,
          buildConfig: buildConfig,
          deployCommands: deployCommands,
          gitDetails: gitDetails,
          scheduledTasks: taskPlan.crons,
          ports: app.ports_exposes || app.ports_mappings || app.port || '',
          status: this.normalizeCoolifyStatus(app.status),
          rawMeta: sanitizeCoolifyMeta(app)
        });

        for (const host of mergedHosts) {
          proj.pendingHosts.push(host);
          proj.domains.push(host);
          if (Object.keys(traefik.edgeConfig).length > 0) {
            proj.domainEdgeConfigs.set(host, {
              edgeConfig: traefik.edgeConfig,
              ruleCount: traefik.translatedRules.length
            });
          }
        }
        results.importedApps++;
      } catch (e) {
        results.errors.push(`App ${app.name}: ${e.message}`);
      }
    }

    // 2. Migrate DBs (PostgreSQL/pgvector/TimescaleDB, MySQL, MariaDB, MongoDB, Redis, KeyDB, Dragonfly, ClickHouse)
    for (const db of dbsToImport) {
      try {
        const proj = getProjectForResource(db);
        const common = extractCommonFields(db);
        const resolved = this.resolveDatabaseEngine(db);
        const catalog = DB_ENGINE_CATALOG[/** @type {keyof typeof DB_ENGINE_CATALOG} */ (resolved.engine)];

        proj.resources.push({
          id: db.uuid,
          type: 'database',
          engine: resolved.engine,
          originalEngine: resolved.originalType,
          image: db.image || (catalog && catalog.defaultImage) || undefined,
          name: db.name || 'Coolify DB',
          description: db.description || `Base de datos (${db.database_type || db.type || 'DB'}). Importada de Coolify.`,
          status: this.normalizeCoolifyStatus(db.status),
          envVars: common.envVars,
          port: db.public_port || db.port || (catalog && catalog.defaultPort) || null,
          credentials: {
            user: db.database_user || db.postgres_user || db.mysql_user || db.mariadb_user || db.mongo_initdb_root_username || db.clickhouse_admin_user || '',
            password: db.database_password || db.postgres_password || db.mysql_password || db.mariadb_password || db.mongo_initdb_root_password || db.redis_password || db.keydb_password || db.dragonfly_password || db.clickhouse_admin_password || '',
            rootPassword: db.database_root_password || db.mysql_root_password || db.mariadb_root_password || '',
            dbName: db.database_name || db.postgres_db || db.mysql_database || db.mariadb_database || ''
          },
          volumes: common.volumes,
          fileMounts: common.fileMounts,
          resourceLimits: common.resourceLimits,
          healthCheck: common.healthCheck,
          networkConfig: common.networkConfig,
          rawMeta: sanitizeCoolifyMeta(db)
        });
        results.importedDbs++;
      } catch (e) {
        results.errors.push(`DB ${db.name}: ${e.message}`);
      }
    }

    // 3. Migrate Services (incluyendo dominios en svc.applications[].fqdn, magic vars y Traefik labels)
    for (const svc of servicesToImport) {
      try {
        const proj = getProjectForResource(svc);
        const common = extractCommonFields(svc);
        const composeRaw = maybeDecodeBase64Text(svc.docker_compose || svc.docker_compose_raw || '');

        /** @type {Record<string, { host: string, url: string }>} */
        const serviceHostMap = Object.create(null);
        const svcHosts = [...this.parseFqdnHosts(svc.fqdn)];
        if (Array.isArray(svc.applications)) {
          for (const subApp of svc.applications) {
            const subUrls = this.parseFqdnUrls(subApp?.fqdn);
            const subKey = toVaultKey(subApp && (subApp.name || subApp.service_name) || '');
            if (subUrls[0] && subKey) serviceHostMap[subKey] = { host: subUrls[0].host, url: subUrls[0].url };
            svcHosts.push(...this.parseFqdnHosts(subApp?.fqdn));
          }
        }
        const uniqueSvcHosts = Array.from(new Set(svcHosts));

        const magic = this.translateMagicVariables(common.envVars, {
          resourceName: svc.name || svc.uuid,
          fqdn: svc.fqdn || (uniqueSvcHosts[0] ? `https://${uniqueSvcHosts[0]}` : ''),
          hosts: uniqueSvcHosts,
          serviceHostMap,
          uuid: svc.uuid,
          dockerCompose: composeRaw
        });
        const traefik = this.parseTraefikLabels(svc.custom_labels, {
          defaultPort: 3000,
          defaultHosts: uniqueSvcHosts,
          composeYaml: composeRaw
        });
        const taskPlan = this.translateScheduledTasks(svc.scheduled_tasks || [], svc.name || 'Coolify Service');

        for (const c of taskPlan.crons) {
          if (c.valid) proj.pendingCrons.push(c);
        }

        const mergedHosts = Array.from(new Set([...uniqueSvcHosts, ...traefik.hosts]));
        proj.resources.push({
          id: svc.uuid,
          type: 'service',
          name: svc.name || 'Coolify Service',
          description: svc.description || `Servicio Docker Compose migrado (${svc.uuid})`,
          status: this.normalizeCoolifyStatus(svc.status),
          domains: mergedHosts,
          envVars: magic.translatedEnv,
          vaultRefs: magic.vaultRefs,
          dockerCompose: magic.translatedCompose || composeRaw,
          traefikEdgeConfig: traefik.previewEdgeConfig,
          scheduledTasks: taskPlan.crons,
          volumes: common.volumes,
          fileMounts: common.fileMounts,
          resourceLimits: common.resourceLimits,
          healthCheck: common.healthCheck,
          networkConfig: common.networkConfig,
          rawMeta: sanitizeCoolifyMeta(svc)
        });
        for (const host of mergedHosts) {
          proj.pendingHosts.push(host);
          proj.domains.push(host);
          if (Object.keys(traefik.edgeConfig).length > 0) {
            proj.domainEdgeConfigs.set(host, {
              edgeConfig: traefik.edgeConfig,
              ruleCount: traefik.translatedRules.length
            });
          }
        }
        results.importedServices++;
      } catch (e) {
        results.errors.push(`Service ${svc.name}: ${e.message}`);
      }
    }

    // Save projects, link domains with translated Traefik→Caddy edge config, and register crons
    for (const [key, projData] of culkiboProjects.entries()) {
      try {
        const pendingHosts = Array.from(new Set(projData.pendingHosts || []));
        /** @type {Map<string, { edgeConfig: Record<string, any>, ruleCount: number }>} */
        const domainEdgeConfigs = projData.domainEdgeConfigs || new Map();
        /** @type {any[]} */
        const pendingCrons = projData.pendingCrons || [];
        delete projData.pendingHosts;
        delete projData.domainEdgeConfigs;
        delete projData.pendingCrons;
        projData.domains = pendingHosts;

        const created = pm.create(projData);
        const realProjectId = (created && created.id) || projData.id;
        results.createdProjects.push({ id: realProjectId, name: projData.name, domains: pendingHosts });

        for (const host of pendingHosts) {
          const edgeEntry = domainEdgeConfigs.get(host);
          const edgeConfig = edgeEntry ? edgeEntry.edgeConfig : {};
          const baseDomainPayload = {
            hostname: host,
            projectId: realProjectId,
            targetPod: 'citadel',
            targetPort: edgeConfig.targetPort || (created && created.citadelPort) || projData.citadelPort || 3000,
            cloudflareProxied: false,
            sslStatus: 'pending_migration',
            sslProvider: 'lets_encrypt',
            migrationSource: 'coolify'
          };
          try {
            await dm.addDomain({
              ...baseDomainPayload,
              ...edgeConfig
            });
            results.domainsLinked++;
            if (edgeEntry && edgeEntry.ruleCount > 0) {
              results.traefikRulesApplied += edgeEntry.ruleCount;
            }
          } catch (e) {
            // Si falló alguna política Edge avanzada, reintentar registro base del dominio y avisar
            if (Object.keys(edgeConfig).length > 0 && !/already configured/i.test(String(e.message || ''))) {
              try {
                await dm.addDomain(baseDomainPayload);
                results.domainsLinked++;
                results.warnings.push(`Dominio ${host}: registrado sin algunas reglas Traefik (${e.message}).`);
                continue;
              } catch (_) {}
            }
            // Si el dominio ya existía, enlazarlo al proyecto migrado si no tenía propietario
            try {
              const existing = dm.getByHostname ? dm.getByHostname(host) : null;
              if (existing && !existing.projectId) {
                await dm.updateDomain(existing.id, { projectId: realProjectId });
                results.domainsLinked++;
              }
            } catch (_) {}
          }
        }

        // Registrar tareas programadas (Crons) en Culkibo
        if (options.syncCrons !== false && pendingCrons.length > 0 && cm && typeof cm.create === 'function') {
          for (const task of pendingCrons) {
            try {
              cm.create(realProjectId, {
                name: task.name,
                schedule: task.schedule,
                mode: 'exec',
                command: task.command,
                enabled: task.enabled
              });
              results.importedCrons++;
            } catch (cronErr) {
              results.warnings.push(`Cron "${task.name}" omitido: ${cronErr.message}`);
            }
          }
        }

        if (created && created.gitRepo) {
          localRunner.prepareProject(created).catch(() => {});
        }
      } catch (e) {
        results.errors.push(`Error guardando proyecto ${key}: ${e.message}`);
      }
    }

    try {
      if (typeof pm.flushToDisk === 'function') await pm.flushToDisk();
    } catch (e) {}

    if (results.domainsLinked > 0) {
      try {
        await require('./ingressManager').reconcile();
      } catch (e) {}
    }

    return results;
  }

  // ===========================================================================
  // 6. POST-MIGRATION PARITY VERIFIER (`verifyMigratedStack`)
  // ===========================================================================

  /**
   * Planifica o ejecuta verificaciones smoke de paridad entre los endpoints de origen
   * en Coolify y los endpoints destino en Culkibo ANTES del cambio de DNS.
   *
   * @param {Array<{
   *   name?: string,
   *   hostname?: string,
   *   sourceUrl: string,
   *   targetUrl: string,
   *   healthPath?: string,
   *   expectedStatus?: number | number[],
   *   expectedHeaders?: string[],
   *   maxLatencyMs?: number
   * }> | { domains?: any[] }} targetsOrPlan
   * @param {{
   *   dryRun?: boolean,
   *   targetIp?: string,
   *   timeoutMs?: number,
   *   probeFn?: (url: string, opts: { hostHeader?: string, timeoutMs: number }) => Promise<{ ok: boolean, status: number, latencyMs: number, headers: Record<string, string>, bodySnippet?: string, error?: string }>
   * }} [opts]
   */
  async verifyMigratedStack(targetsOrPlan, opts = {}) {
    const dryRun = Boolean(opts.dryRun);
    const timeoutMs = Math.min(30000, Math.max(1000, Number(opts.timeoutMs) || 8000));
    const targetIp = String(opts.targetIp || '').trim();

    /** @type {Array<{ name: string, hostname: string, sourceUrl: string, targetUrl: string, healthPath: string, expectedStatus: number[], expectedHeaders: string[], maxLatencyMs: number }>} */
    let checksSpec = [];

    if (Array.isArray(targetsOrPlan)) {
      checksSpec = targetsOrPlan.map((t, idx) => {
        const hp = String(t.healthPath || '/').startsWith('/') ? String(t.healthPath || '/') : `/${t.healthPath}`;
        const expStatus = Array.isArray(t.expectedStatus)
          ? t.expectedStatus.map(Number)
          : (typeof t.expectedStatus === 'number' ? [t.expectedStatus] : [200, 204, 301, 302]);
        let host = String(t.hostname || '').trim();
        if (!host && t.sourceUrl) {
          try { host = new URL(t.sourceUrl).hostname; } catch (e) {}
        }
        return {
          name: String(t.name || host || `endpoint-${idx + 1}`),
          hostname: host,
          sourceUrl: String(t.sourceUrl || '').trim(),
          targetUrl: String(t.targetUrl || '').trim(),
          healthPath: hp,
          expectedStatus: expStatus,
          expectedHeaders: Array.isArray(t.expectedHeaders) ? t.expectedHeaders.map((h) => String(h).toLowerCase()) : [],
          maxLatencyMs: Number(t.maxLatencyMs) || 2000
        };
      });
    } else if (targetsOrPlan && Array.isArray(targetsOrPlan.domains)) {
      checksSpec = targetsOrPlan.domains.map((d) => {
        const host = String(d.hostname || '');
        const hp = String(d.healthPath || '/').startsWith('/') ? String(d.healthPath || '/') : '/';
        const port = Number(d.targetPort) || 3000;
        return {
          name: String(d.resourceName || host),
          hostname: host,
          sourceUrl: `https://${host}${hp}`,
          targetUrl: targetIp ? `http://${targetIp}:${port}${hp}` : `http://127.0.0.1:${port}${hp}`,
          healthPath: hp,
          expectedStatus: [200, 204, 301, 302],
          expectedHeaders: d.hasEdgeRules ? ['strict-transport-security'] : [],
          maxLatencyMs: 2000
        };
      });
    }

    const smokePlan = checksSpec.map((spec) => ({
      ...spec,
      preDnsCurlCommand: spec.hostname && targetIp
        ? `curl -fsS -I --resolve ${spec.hostname}:443:${targetIp} https://${spec.hostname}${spec.healthPath}`
        : `curl -fsS -I ${spec.targetUrl}`
    }));

    if (dryRun) {
      return {
        ok: true,
        dryRun: true,
        cutoverReady: null,
        checkedAt: new Date().toISOString(),
        summary: { total: smokePlan.length, passed: 0, warnings: 0, failed: 0 },
        checks: smokePlan,
        recommendation: 'Ejecuta verifyMigratedStack sin dryRun o los comandos --resolve indicados antes de cambiar tus registros DNS.'
      };
    }

    /**
     * Sonda HTTP por defecto usando `safeFetch` con protección SSRF.
     * @param {string} targetUrl
     * @param {{ hostHeader?: string, timeoutMs: number }} pOpts
     */
    const defaultProbe = async (targetUrl, pOpts) => {
      const started = Date.now();
      try {
        const headers = /** @type {Record<string, string>} */ ({ 'User-Agent': 'Culkibo-Migration-Verifier/1.1' });
        if (pOpts.hostHeader) headers.Host = pOpts.hostHeader;
        const res = await safeFetch(targetUrl, {
          method: 'GET',
          headers,
          maxRedirects: 0,
          maxBytes: 256 * 1024,
          timeoutMs: pOpts.timeoutMs
        });
        /** @type {Record<string, string>} */
        const lowerHeaders = {};
        if (res.headers && typeof res.headers === 'object') {
          for (const [k, v] of Object.entries(res.headers)) {
            lowerHeaders[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
          }
        }
        return {
          ok: res.status >= 200 && res.status < 400,
          status: res.status,
          latencyMs: Date.now() - started,
          headers: lowerHeaders,
          bodySnippet: typeof res.text === 'function' ? res.text().slice(0, 512) : ''
        };
      } catch (err) {
        return {
          ok: false,
          status: 0,
          latencyMs: Date.now() - started,
          headers: {},
          error: err.message || 'Error de conexión'
        };
      }
    };

    const probe = typeof opts.probeFn === 'function' ? opts.probeFn : defaultProbe;

    /** @type {any[]} */
    const results = [];
    let passed = 0;
    let warnCount = 0;
    let failed = 0;

    for (const spec of smokePlan) {
      const [srcRes, tgtRes] = await Promise.all([
        spec.sourceUrl ? probe(spec.sourceUrl, { timeoutMs }) : Promise.resolve(null),
        spec.targetUrl ? probe(spec.targetUrl, { hostHeader: spec.hostname || undefined, timeoutMs }) : Promise.resolve(null)
      ]);

      /** @type {string[]} */
      const issues = [];
      /** @type {string[]} */
      const checkWarnings = [];

      if (!tgtRes || tgtRes.status === 0) {
        issues.push(`Destino Culkibo inalcanzable: ${(tgtRes && tgtRes.error) || 'sin respuesta'}`);
      } else {
        if (!spec.expectedStatus.includes(tgtRes.status) && !(tgtRes.status >= 200 && tgtRes.status < 300)) {
          issues.push(`HTTP ${tgtRes.status} inesperado en destino Culkibo (esperado: ${spec.expectedStatus.join('/')})`);
        }
        if (srcRes && srcRes.status > 0 && srcRes.status !== tgtRes.status) {
          issues.push(`Discrepancia de estado HTTP: Coolify=${srcRes.status} vs Culkibo=${tgtRes.status}`);
        }
        if (tgtRes.latencyMs > spec.maxLatencyMs) {
          checkWarnings.push(`Latencia destino (${tgtRes.latencyMs} ms) superior al umbral (${spec.maxLatencyMs} ms)`);
        }
        const tgtHeaders = tgtRes.headers || {};
        for (const reqHdr of spec.expectedHeaders) {
          if (!tgtHeaders[reqHdr]) {
            checkWarnings.push(`Cabecera esperada ausente en destino Culkibo: ${reqHdr}`);
          }
        }
        if (srcRes && srcRes.headers) {
          for (const parityHdr of ['access-control-allow-origin', 'strict-transport-security']) {
            if (srcRes.headers[parityHdr] && !tgtHeaders[parityHdr]) {
              checkWarnings.push(`Paridad de cabecera: Coolify emitía "${parityHdr}" pero Culkibo aún no.`);
            }
          }
        }
      }

      const status = issues.length > 0 ? 'fail' : (checkWarnings.length > 0 ? 'warn' : 'pass');
      if (status === 'pass') passed++;
      else if (status === 'warn') warnCount++;
      else failed++;

      results.push({
        name: spec.name,
        hostname: spec.hostname,
        sourceUrl: spec.sourceUrl,
        targetUrl: spec.targetUrl,
        status,
        source: srcRes ? { status: srcRes.status, latencyMs: srcRes.latencyMs, error: srcRes.error || null } : null,
        target: tgtRes ? { status: tgtRes.status, latencyMs: tgtRes.latencyMs, error: tgtRes.error || null } : null,
        latencyDeltaMs: (srcRes && tgtRes && srcRes.status > 0 && tgtRes.status > 0) ? (tgtRes.latencyMs - srcRes.latencyMs) : null,
        issues,
        warnings: checkWarnings,
        preDnsCurlCommand: spec.preDnsCurlCommand
      });
    }

    const total = results.length;
    const parityPercent = total === 0 ? 100 : Math.round(((passed + warnCount * 0.5) / total) * 100);
    const cutoverReady = failed === 0;

    return {
      ok: cutoverReady,
      dryRun: false,
      cutoverReady,
      parityPercent,
      checkedAt: new Date().toISOString(),
      summary: { total, passed, warnings: warnCount, failed },
      checks: results,
      recommendation: cutoverReady
        ? (warnCount > 0
            ? 'Todos los endpoints críticos responden OK con avisos menores. Seguro proceder con el cutover DNS.'
            : 'Paridad 100% verificada entre Coolify y Culkibo. Listo para conmutación DNS sin caída.')
        : `${failed} endpoint(s) fallaron la verificación. Corrige los problemas antes de cambiar DNS; Coolify sigue intacto.`
    };
  }

  /**
   * Empaqueta una migración de Coolify en un Culkibo Portable Stack Bundle (`.zip` o `.ckb.gz`).
   * @param {{ apps?: any[], databases?: any[], services?: any[], projects?: any[] }} snapshot
   * @param {{ stackName?: string, format?: 'zip' | 'ckb.gz', passphrase?: string | null }} [opts]
   */
  exportMigrationBundle(snapshot, opts = {}) {
    const plan = this.buildMigrationPlan(snapshot);
    /** @type {any[]} */
    const projects = [];
    /** @type {any[]} */
    const domains = [];
    /** @type {any[]} */
    const crons = [];
    /** @type {Record<string, string>} */
    const vaultSecrets = {};

    /** @type {any[]} */
    const apps = Array.isArray(snapshot && snapshot.apps) ? (snapshot.apps || []) : [];
    /** @type {any[]} */
    const databases = Array.isArray(snapshot && snapshot.databases) ? (snapshot.databases || []) : [];
    /** @type {any[]} */
    const services = Array.isArray(snapshot && snapshot.services) ? (snapshot.services || []) : [];

    for (const app of apps) {
      const hosts = this.parseFqdnHosts(app.fqdn);
      /** @type {Record<string, string>} */
      const envMap = {};
      for (const ev of (app.environment_variables || [])) {
        if (ev && ev.key && !ev.is_preview) envMap[ev.key] = ev.value ?? '';
      }
      const magic = this.translateMagicVariables(envMap, { resourceName: app.name, fqdn: app.fqdn, hosts, gitBranch: app.git_branch });
      const traefik = this.parseTraefikLabels(app.custom_labels, { defaultHosts: hosts, composeYaml: app.docker_compose || '' });
      const firstPort = traefik.targetPort || parseInt(String(app.ports_exposes || app.port || '3000').split(',')[0], 10) || 3000;
      const projId = String(app.project_id || app.uuid || 'coolify_app').replace(/[^a-zA-Z0-9_-]/g, '_');

      projects.push({
        id: projId,
        name: app.name || 'Coolify App',
        description: app.description || '',
        source: 'coolify-import',
        gitRepo: app.git_repository || app.git_full_url || '',
        gitBranch: app.git_branch || 'main',
        buildCommand: app.build_command || '',
        startCommand: app.start_command || '',
        baseDirectory: app.base_directory || '/',
        containerPort: firstPort,
        healthPath: app.health_check_path || '/',
        memoryMb: this.parseMemoryMb(app.limits_memory),
        cpus: app.limits_cpus ? Number(app.limits_cpus) : null,
        domains: hosts,
        envVars: magic.translatedEnv,
        volumes: app.local_persistent_volumes || app.volumes || []
      });

      for (const host of hosts) {
        domains.push({
          hostname: host,
          projectId: projId,
          targetPort: firstPort,
          migrationSource: 'coolify',
          ...traefik.previewEdgeConfig
        });
      }
      const tasks = this.translateScheduledTasks(app.scheduled_tasks || [], app.name || 'App');
      for (const c of tasks.crons) {
        if (c.valid) crons.push({ ...c, projectId: projId });
      }
    }

    for (const svc of services) {
      const hosts = this.parseFqdnHosts(svc.fqdn);
      const projId = String(svc.project_id || svc.uuid || 'coolify_svc').replace(/[^a-zA-Z0-9_-]/g, '_');
      projects.push({
        id: projId,
        name: svc.name || 'Coolify Service',
        description: svc.description || '',
        source: 'coolify-import',
        containerPort: 3000,
        domains: hosts,
        envVars: {}
      });
    }

    const dbList = databases.map((db) => {
      const resolved = this.resolveDatabaseEngine(db);
      const pwd = db.database_password || db.postgres_password || db.mysql_password || db.mariadb_password || db.redis_password || db.dragonfly_password || db.clickhouse_admin_password || '';
      if (pwd) vaultSecrets[toVaultKey(`${slugify(db.name || 'db')}_PASSWORD`)] = String(pwd);
      return {
        id: db.uuid,
        name: db.name,
        engine: resolved.engine,
        image: db.image || undefined,
        projectId: db.project_id ? String(db.project_id) : null,
        dbName: db.database_name || db.postgres_db || db.mysql_database || db.mariadb_database || undefined,
        username: db.database_user || db.postgres_user || db.mysql_user || db.mariadb_user || db.clickhouse_admin_user || undefined,
        port: Number(db.public_port || db.port) || undefined,
        volumes: db.local_persistent_volumes || db.volumes || []
      };
    });

    const archiver = getBundleArchiver();
    return archiver.exportStackBundle({
      stackName: opts.stackName || 'coolify-migration',
      format: opts.format || 'zip',
      source: 'coolify-migration',
      passphrase: opts.passphrase || null,
      projects,
      domains,
      databases: dbList,
      crons,
      vaultSecrets,
      migrationReport: plan
    });
  }

  // ===========================================================================
  // 7. LIVE VOLUME & SQL DATA STREAMER PLAN (`buildVolumeAndDbStreamPlan`)
  // ===========================================================================

  /**
   * Genera un plan determinista de streaming en vivo de bases de datos SQL/NoSQL
   * (PostgreSQL, MySQL, MariaDB, MongoDB, Redis/KeyDB/Dragonfly→Valkey, ClickHouse)
   * y volúmenes Docker con nombre usando estrictamente arrays `program` + `args[]`
   * (0 cadenas de shell, 0 contraseñas en `argv`, verificación SHA-256 paso a paso).
   *
   * @param {{ apps?: any[], databases?: any[], services?: any[], projects?: any[] }} snapshot
   * @param {{
   *   sourceHost?: string | null,
   *   sourceUser?: string,
   *   sourcePort?: number | string,
   *   targetDbContainers?: Record<string, string>,
   *   targetVolumePrefix?: string,
   *   helperImage?: string
   * }} [opts]
   */
  buildVolumeAndDbStreamPlan(snapshot, opts = {}) {
    const SAFE_DOCKER_TOKEN_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
    const SAFE_IDENT_RE = /^[a-zA-Z0-9_.-]{1,80}$/;
    const SAFE_SSH_HOST_RE = /^[a-zA-Z0-9._:-]{1,253}$/;
    const SAFE_SSH_USER_RE = /^[a-zA-Z0-9._-]{1,64}$/;

    /** @param {string} raw @param {string} label @param {RegExp} re */
    const assertSafeToken = (raw, label, re) => {
      const s = String(raw || '').trim();
      if (!s || s.startsWith('-') || /[\s\r\n\0;|&$`'"<>\\]/.test(s) || s.includes('..') || !re.test(s)) {
        throw new Error(`Parámetro inseguro rechazado en buildVolumeAndDbStreamPlan (${label}): "${s.slice(0, 60)}"`);
      }
      return s;
    };

    const sourceHost = opts.sourceHost ? assertSafeToken(opts.sourceHost, 'sourceHost', SAFE_SSH_HOST_RE) : null;
    const sourceUser = assertSafeToken(opts.sourceUser || 'root', 'sourceUser', SAFE_SSH_USER_RE);
    const sourcePortNum = Number(opts.sourcePort || 22);
    if (!Number.isInteger(sourcePortNum) || sourcePortNum < 1 || sourcePortNum > 65535) {
      throw new Error(`sourcePort inválido: "${opts.sourcePort}"`);
    }
    const targetVolumePrefix = assertSafeToken(opts.targetVolumePrefix || 'culkibo_mig_', 'targetVolumePrefix', /^[a-zA-Z0-9_-]{1,32}$/);
    const helperImage = String(opts.helperImage || 'alpine:3.20').trim();
    if (!/^[a-zA-Z0-9._\/:-]{1,128}$/.test(helperImage) || helperImage.startsWith('-')) {
      throw new Error(`helperImage inválido: "${helperImage.slice(0, 60)}"`);
    }
    const targetDbContainers = (opts.targetDbContainers && typeof opts.targetDbContainers === 'object') ? opts.targetDbContainers : {};

    /**
     * Envuelve un comando `{ program, args }` en `ssh` con array de argumentos puro cuando hay `sourceHost`.
     * @param {{ program: string, args: string[] }} cmd
     */
    const wrapRemoteSource = (cmd) => {
      if (!sourceHost) return null;
      return {
        program: 'ssh',
        args: [
          '-p', String(sourcePortNum),
          '-o', 'BatchMode=yes',
          '-o', 'StrictHostKeyChecking=accept-new',
          '--',
          `${sourceUser}@${sourceHost}`,
          cmd.program,
          ...cmd.args
        ]
      };
    };

    /** @type {any[]} */
    const databases = Array.isArray(snapshot && snapshot.databases) ? (snapshot.databases || []) : [];
    /** @type {any[]} */
    const apps = Array.isArray(snapshot && snapshot.apps) ? (snapshot.apps || []) : [];
    /** @type {any[]} */
    const services = Array.isArray(snapshot && snapshot.services) ? (snapshot.services || []) : [];

    /** @type {any[]} */
    const databaseStreams = [];
    /** @type {any[]} */
    const volumeStreams = [];
    /** @type {Set<string>} */
    const seenVolumes = new Set();

    // 1. Streaming SQL / NoSQL por cada base de datos
    for (const db of databases) {
      const resolved = this.resolveDatabaseEngine(db);
      const dbSlug = slugify(db.name || db.uuid || 'db').replace(/-/g, '_');
      const rawSrcContainer = db.container_name || db.uuid || `coolify_${dbSlug}`;
      const srcContainer = assertSafeToken(rawSrcContainer, `sourceContainer(${db.name || db.uuid})`, SAFE_DOCKER_TOKEN_RE);
      const rawTgtContainer = targetDbContainers[db.uuid] || targetDbContainers[db.name] || `culkibo_db_${dbSlug}`;
      const tgtContainer = assertSafeToken(rawTgtContainer, `targetContainer(${db.name || db.uuid})`, SAFE_DOCKER_TOKEN_RE);

      const rawUser = db.database_user || db.postgres_user || db.mysql_user || db.mariadb_user || db.mongo_initdb_root_username || db.clickhouse_admin_user || (resolved.engine === 'mysql' || resolved.engine === 'mariadb' ? 'root' : 'postgres');
      const dbUser = assertSafeToken(rawUser, `dbUser(${db.name || db.uuid})`, SAFE_IDENT_RE);
      const rawDbName = db.database_name || db.postgres_db || db.mysql_database || db.mariadb_database || (resolved.engine === 'clickhouse' ? 'default' : 'postgres');
      const dbName = assertSafeToken(rawDbName, `dbName(${db.name || db.uuid})`, SAFE_IDENT_RE);

      /** @type {{ program: string, args: string[] }} */
      let sourceDump;
      /** @type {{ program: string, args: string[] }} */
      let targetRestore;
      /** @type {{ program: string, args: string[] }} */
      let postVerifyCmd;
      let authEnvNote = '';

      if (resolved.engine === 'postgres' || resolved.engine === 'pgvector' || resolved.engine === 'timescaledb') {
        sourceDump = {
          program: 'docker',
          args: ['exec', '-i', srcContainer, 'pg_dump', '-U', dbUser, '-d', dbName, '-F', 'c', '-b']
        };
        targetRestore = {
          program: 'docker',
          args: ['exec', '-i', tgtContainer, 'pg_restore', '-U', dbUser, '-d', dbName, '--clean', '--if-exists', '--no-owner', '--no-privileges', '-e']
        };
        postVerifyCmd = {
          program: 'docker',
          args: ['exec', tgtContainer, 'psql', '-U', dbUser, '-d', dbName, '-Atc', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"]
        };
        authEnvNote = 'Usa PGPASSWORD del entorno interno del contenedor (jamás pasa contraseñas en argv).';
      } else if (resolved.engine === 'mysql' || resolved.engine === 'mariadb') {
        const dumpBin = resolved.engine === 'mariadb' ? 'mariadb-dump' : 'mysqldump';
        const restoreBin = resolved.engine === 'mariadb' ? 'mariadb' : 'mysql';
        const dumpArgs = ['exec', '-i', srcContainer, dumpBin, '-u', dbUser, '--single-transaction', '--quick'];
        if (resolved.engine === 'mysql') dumpArgs.push('--set-gtid-purged=OFF');
        dumpArgs.push(dbName);
        sourceDump = { program: 'docker', args: dumpArgs };
        targetRestore = {
          program: 'docker',
          args: ['exec', '-i', tgtContainer, restoreBin, '-u', dbUser, dbName]
        };
        postVerifyCmd = {
          program: 'docker',
          args: ['exec', tgtContainer, 'mysqladmin', 'ping', '-h', '127.0.0.1', '--silent']
        };
        authEnvNote = 'Usa MYSQL_PWD/CULKIBO_MYSQL_PWD interno del contenedor (jamás -p<clave> en argv).';
      } else if (resolved.engine === 'mongodb') {
        sourceDump = {
          program: 'docker',
          args: ['exec', '-i', srcContainer, 'mongodump', '--archive', '--gzip']
        };
        targetRestore = {
          program: 'docker',
          args: ['exec', '-i', tgtContainer, 'mongorestore', '--archive', '--gzip', '--drop']
        };
        postVerifyCmd = {
          program: 'docker',
          args: ['exec', tgtContainer, 'mongosh', '--quiet', '--eval', 'db.adminCommand({ ping: 1 }).ok']
        };
        authEnvNote = 'Autenticación mediante MONGO_INITDB_ROOT_* dentro del contenedor.';
      } else if (resolved.engine === 'valkey') {
        sourceDump = {
          program: 'docker',
          args: ['exec', srcContainer, 'redis-cli', 'SAVE']
        };
        targetRestore = {
          program: 'docker',
          args: ['cp', `${srcContainer}:/data/dump.rdb`, '-']
        };
        postVerifyCmd = {
          program: 'docker',
          args: ['exec', tgtContainer, 'valkey-cli', 'DBSIZE']
        };
        authEnvNote = 'Usa REDISCLI_AUTH dentro del contenedor; copia atómica de dump.rdb y validación DBSIZE.';
      } else if (resolved.engine === 'clickhouse') {
        sourceDump = {
          program: 'docker',
          args: ['exec', srcContainer, 'clickhouse-client', '--query', `SHOW TABLES FROM ${dbName}`]
        };
        targetRestore = {
          program: 'docker',
          args: ['exec', '-i', tgtContainer, 'clickhouse-client', '--database', dbName]
        };
        postVerifyCmd = {
          program: 'docker',
          args: ['exec', tgtContainer, 'clickhouse-client', '--query', `SELECT count() FROM system.tables WHERE database = '${dbName}'`]
        };
        authEnvNote = 'Autenticación mediante CLICKHOUSE_PASSWORD interno del contenedor.';
      } else {
        sourceDump = { program: 'docker', args: ['inspect', srcContainer] };
        targetRestore = { program: 'docker', args: ['inspect', tgtContainer] };
        postVerifyCmd = { program: 'docker', args: ['inspect', '--format', '{{.State.Running}}', tgtContainer] };
        authEnvNote = 'Motor genérico: sincroniza el volumen persistente asociado.';
      }

      databaseStreams.push({
        id: db.uuid || dbSlug,
        name: db.name || dbSlug,
        engine: resolved.engine,
        originalEngine: resolved.originalType,
        sourceContainer: srcContainer,
        targetContainer: tgtContainer,
        zeroShell: true,
        authEnvNote,
        sourceDump,
        sshSourceDump: wrapRemoteSource(sourceDump),
        targetRestore,
        verification: {
          streamChecksumAlgorithm: 'sha256',
          streamChecksumStep: 'Pipe stdout de sourceDump → crypto.createHash("sha256") PassThrough → stdin de targetRestore; registrar digest SHA-256 en bitácora de corte.',
          postRestoreCheck: postVerifyCmd
        }
      });
    }

    // 2. Streaming de volúmenes Docker con nombre de apps, BDs y servicios
    /** @param {any} resource @param {string} kind */
    const collectVolumesFrom = (resource, kind) => {
      const vols = resource.local_persistent_volumes || resource.persistent_volumes || resource.volumes || [];
      if (!Array.isArray(vols)) return;
      for (const v of vols) {
        const rawName = typeof v === 'string' ? v.split(':')[0] : (v && (v.name || v.source));
        if (!rawName || String(rawName).startsWith('/')) continue;
        const volName = assertSafeToken(String(rawName), `volume(${resource.name || resource.uuid})`, SAFE_DOCKER_TOKEN_RE);
        if (seenVolumes.has(volName)) continue;
        seenVolumes.add(volName);

        const targetVolName = assertSafeToken(`${targetVolumePrefix}${volName}`.slice(0, 127), 'targetVolume', SAFE_DOCKER_TOKEN_RE);
        const sourceArchive = {
          program: 'docker',
          args: ['run', '--rm', '-v', `${volName}:/src:ro`, helperImage, 'tar', '-cf', '-', '-C', '/src', '.']
        };
        const targetExtract = {
          program: 'docker',
          args: ['run', '--rm', '-i', '-v', `${targetVolName}:/dst`, helperImage, 'tar', '-xf', '-', '-C', '/dst']
        };
        const sourceHashCheck = {
          program: 'docker',
          args: ['run', '--rm', '-v', `${volName}:/src:ro`, helperImage, 'find', '/src', '-type', 'f', '-exec', 'sha256sum', '{}', '+']
        };
        const targetHashCheck = {
          program: 'docker',
          args: ['run', '--rm', '-v', `${targetVolName}:/dst:ro`, helperImage, 'find', '/dst', '-type', 'f', '-exec', 'sha256sum', '{}', '+']
        };

        volumeStreams.push({
          volumeName: volName,
          targetVolumeName: targetVolName,
          mountPath: (v && typeof v === 'object' && v.mount_path) ? String(v.mount_path) : null,
          ownerResource: resource.name || resource.uuid || kind,
          ownerType: kind,
          zeroShell: true,
          sourceArchive,
          sshSourceArchive: wrapRemoteSource(sourceArchive),
          targetExtract,
          verification: {
            algorithm: 'sha256',
            streamChecksumStep: 'Calcular SHA-256 sobre el stream tar en vuelo (Node PassThrough) y comparar conteo/hashes de archivos entre origen y destino.',
            sourceHashCheck,
            sshSourceHashCheck: wrapRemoteSource(sourceHashCheck),
            targetHashCheck
          }
        });
      }
    };

    for (const a of apps) collectVolumesFrom(a, 'app');
    for (const d of databases) collectVolumesFrom(d, 'database');
    for (const s of services) collectVolumesFrom(s, 'service');

    return {
      ok: true,
      zeroShell: true,
      sourceHost,
      sourcePort: sourceHost ? sourcePortNum : null,
      generatedAt: new Date().toISOString(),
      summary: {
        databases: databaseStreams.length,
        volumes: volumeStreams.length,
        totalSteps: databaseStreams.length + volumeStreams.length
      },
      databaseStreams,
      volumeStreams,
      verificationChecklist: [
        'Ejecutar cada comando exclusivamente mediante spawn(cmd.program, cmd.args, { shell: false }).',
        'Conectar stdout de origen a stdin de destino mediante Node stream.pipeline + PassThrough SHA-256.',
        'Confirmar que ningún secreto/contraseña aparece en argv ni en `ps` del host.',
        'Ejecutar postRestoreCheck y targetHashCheck antes de iniciar el cutover DNS.'
      ]
    };
  }
}

const instance = /** @type {any} */ (new CoolifyMigrator());
instance.CoolifyMigrator = CoolifyMigrator;
instance.sanitizeCoolifyMeta = sanitizeCoolifyMeta;
instance.maybeDecodeBase64Text = maybeDecodeBase64Text;
instance.extractLabelsFromComposeYaml = extractLabelsFromComposeYaml;
instance.DB_ENGINE_CATALOG = DB_ENGINE_CATALOG;

module.exports = instance;
