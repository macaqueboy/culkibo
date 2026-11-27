/**
 * Exportador IaC Cero Lock-In: OpenTofu / Terraform 1.6+ HCL + Docker Compose Portátil + `.env.example`.
 *
 * Garantías absolutas de seguridad:
 *  - 0 dependencias npm externas, 0 invocaciones de shell, 0 mutaciones en disco.
 *  - JAMÁS emite ningún valor de secreto en claro, contraseña de BD, API key ni clave privada
 *    WireGuard en NINGÚN archivo exportado (`main.tf`, `variables.tf`, `outputs.tf`,
 *    `docker-compose.yml`, `.env.example`). Todas las variables de entorno y credenciales de BD
 *    se exportan estrictamente como referencias `var.<slug>_<key>` (`sensitive = true` sin default)
 *    y `${SLUG_KEY}` placeholders.
 */

const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Sanitiza un identificador seguro para nombres de recursos/variables HCL y servicios Compose.
 * @param {string} raw
 * @param {string} [fallback]
 * @returns {string}
 */
function sanitizeIdent(raw, fallback = 'app') {
  let clean = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_{2,}/g, '_')
    .slice(0, 48);
  if (!clean) clean = fallback;
  if (/^[0-9]/.test(clean)) clean = `n_${clean}`;
  return clean;
}

/**
 * Sanitiza una clave de variable de entorno a formato POSIX seguro (`^[A-Z_][A-Z0-9_]*$`).
 * @param {string} raw
 * @returns {string | null}
 */
function sanitizeEnvKey(raw) {
  const k = String(raw || '').trim().replace(/[^A-Za-z0-9_]+/g, '_');
  if (!k || FORBIDDEN_PROTO_KEYS.has(k) || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(k)) return null;
  return k;
}

/**
 * Escapa de forma estricta un string para literales HCL entre comillas dobles
 * (neutralizando interpolación `${` / `%{`, comillas y saltos de línea).
 * @param {string} raw
 * @returns {string}
 */
function escapeHclString(raw) {
  return String(raw ?? '')
    .replace(/[\r\n\0]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\$\{/g, '$$\\{')
    .replace(/%\{/g, '%%\\{');
}

/**
 * Escapa una cadena segura para YAML entre comillas dobles.
 * @param {string} raw
 * @returns {string}
 */
function escapeYamlString(raw) {
  return String(raw ?? '')
    .replace(/[\r\n\0]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

/**
 * Resuelve la imagen Docker estándar de una base de datos gestionada.
 * @param {any} db
 * @returns {{ image: string, port: number, envPasswordKey: string, envUserKey: string, envDbKey: string, dataPath: string }}
 */
function resolveDbContainerSpec(db) {
  const engine = String((db && (db.engine || db.type)) || 'postgres').toLowerCase();
  if (engine === 'valkey' || engine === 'redis' || engine === 'dragonfly' || engine === 'keydb') {
    return {
      image: String(db.image || 'valkey/valkey:8-alpine'),
      port: Number(db.port) || 6379,
      envPasswordKey: 'VALKEY_PASSWORD',
      envUserKey: '',
      envDbKey: '',
      dataPath: '/data'
    };
  }
  if (engine === 'mysql') {
    return {
      image: String(db.image || 'mysql:9'),
      port: Number(db.port) || 3306,
      envPasswordKey: 'MYSQL_ROOT_PASSWORD',
      envUserKey: 'MYSQL_USER',
      envDbKey: 'MYSQL_DATABASE',
      dataPath: '/var/lib/mysql'
    };
  }
  if (engine === 'mariadb') {
    return {
      image: String(db.image || 'mariadb:11.8'),
      port: Number(db.port) || 3306,
      envPasswordKey: 'MARIADB_ROOT_PASSWORD',
      envUserKey: 'MARIADB_USER',
      envDbKey: 'MARIADB_DATABASE',
      dataPath: '/var/lib/mysql'
    };
  }
  if (engine === 'mongodb' || engine === 'mongo') {
    return {
      image: String(db.image || 'mongo:8'),
      port: Number(db.port) || 27017,
      envPasswordKey: 'MONGO_INITDB_ROOT_PASSWORD',
      envUserKey: 'MONGO_INITDB_ROOT_USERNAME',
      envDbKey: '',
      dataPath: '/data/db'
    };
  }
  if (engine === 'clickhouse') {
    return {
      image: String(db.image || 'clickhouse/clickhouse-server:24.8-alpine'),
      port: Number(db.port) || 8123,
      envPasswordKey: 'CLICKHOUSE_PASSWORD',
      envUserKey: 'CLICKHOUSE_USER',
      envDbKey: 'CLICKHOUSE_DB',
      dataPath: '/var/lib/clickhouse'
    };
  }
  return {
    image: String(db.image || 'postgres:17-alpine'),
    port: Number(db.port) || 5432,
    envPasswordKey: 'POSTGRES_PASSWORD',
    envUserKey: 'POSTGRES_USER',
    envDbKey: 'POSTGRES_DB',
    dataPath: '/var/lib/postgresql/data'
  };
}

/**
 * Extrae el catálogo normalizado de variables sensibles (sin NINGÚN valor en claro)
 * para todos los proyectos, bases de datos y dominios del estate.
 *
 * @param {{ projects: any[], databases: any[], domains: any[], crons: any[], meshPeers: any[] }} estate
 */
function buildRedactedVariableCatalog(estate) {
  /** @type {Array<{ tfName: string, envName: string, description: string, sensitive: boolean, group: string }>} */
  const vars = [];
  /** @type {Set<string>} */
  const seenTf = new Set();
  let secretsRedactedCount = 0;

  const addVar = (tfName, envName, description, sensitive, group) => {
    if (seenTf.has(tfName)) return;
    seenTf.add(tfName);
    vars.push({ tfName, envName, description, sensitive, group });
    if (sensitive) secretsRedactedCount++;
  };

  for (const proj of estate.projects) {
    const slug = sanitizeIdent(proj.id || proj.name, 'app');
    const rawEnv = (proj.envVars && typeof proj.envVars === 'object' && !Array.isArray(proj.envVars))
      ? proj.envVars
      : {};
    for (const rawKey of Object.keys(rawEnv).sort()) {
      const cleanKey = sanitizeEnvKey(rawKey);
      if (!cleanKey) continue;
      const tfName = `${slug}_${cleanKey.toLowerCase()}`;
      const envName = `${slug.toUpperCase()}_${cleanKey.toUpperCase()}`;
      addVar(tfName, envName, `Runtime env var ${cleanKey} for project ${proj.name || slug} (value redacted at export)`, true, `project:${slug}`);
    }
    const rawBuildSecrets = (proj.buildSecrets && typeof proj.buildSecrets === 'object') ? proj.buildSecrets : {};
    for (const rawKey of Object.keys(rawBuildSecrets).sort()) {
      const cleanKey = sanitizeEnvKey(rawKey);
      if (!cleanKey) continue;
      const tfName = `${slug}_build_${cleanKey.toLowerCase()}`;
      const envName = `${slug.toUpperCase()}_BUILD_${cleanKey.toUpperCase()}`;
      addVar(tfName, envName, `Build secret ${cleanKey} for project ${proj.name || slug}`, true, `project:${slug}`);
    }
  }

  for (const db of estate.databases) {
    const slug = sanitizeIdent(db.id || db.name, 'db');
    const spec = resolveDbContainerSpec(db);
    const tfName = `db_${slug}_password`;
    const envName = `DB_${slug.toUpperCase()}_PASSWORD`;
    addVar(tfName, envName, `${spec.envPasswordKey} for managed database ${db.name || slug} (value redacted at export)`, true, `database:${slug}`);
  }

  if (estate.domains.length > 0) {
    addVar('culkibo_edge_ip', 'CULKIBO_EDGE_IP', 'Public IPv4 address of the Culkibo Caddy edge host', false, 'dns');
    addVar('cloudflare_zone_id', 'CLOUDFLARE_ZONE_ID', 'Cloudflare DNS Zone ID for optional DNS record management', true, 'dns');
  }

  // Contabilizar claves privadas WireGuard omitidas explícitamente del export
  for (const peer of estate.meshPeers) {
    if (peer && (peer.privateKeyEncrypted || peer.encryptedPrivateKey || peer.privateKey)) {
      secretsRedactedCount++;
    }
  }

  return { vars, secretsRedactedCount };
}

/**
 * Renderiza `main.tf` compatible con OpenTofu / Terraform >= 1.6 (`kreuzwerker/docker` + opcional `cloudflare`).
 * @param {{ projects: any[], databases: any[], domains: any[], crons: any[], meshPeers: any[] }} estate
 */
function renderTerraformMain(estate) {
  const hasDomains = estate.domains.length > 0;
  const lines = [
    '# Generated by Culkibo Zero Lock-In IaC Exporter (OpenTofu / Terraform >= 1.6)',
    '# ZERO plaintext secrets: every env var and DB credential references sensitive var.*',
    '',
    'terraform {',
    '  required_version = ">= 1.6.0"',
    '  required_providers {',
    '    docker = {',
    '      source  = "kreuzwerker/docker"',
    '      version = "~> 3.0"',
    '    }'
  ];

  if (hasDomains) {
    lines.push(
      '    cloudflare = {',
      '      source  = "cloudflare/cloudflare"',
      '      version = "~> 4.0"',
      '    }'
    );
  }
  lines.push('  }', '}', '', 'provider "docker" {}', '');

  // Isolated per-project Docker bridge networks (cures dokploy#6028 DNS collisions)
  for (const proj of estate.projects) {
    const slug = sanitizeIdent(proj.id || proj.name, 'app');
    const port = Number(proj.containerPort || proj.citadelPort) || 3000;
    const memoryMb = Number(proj.memoryMb || proj.memoryLimitMb) || 512;
    const stopTimeout = Math.min(300, Math.max(5, Number(proj.stopGracePeriodSec) || 30));
    const image = escapeHclString(proj.imageTag || proj.activeImageTag || `culkibo/${slug}:latest`);
    const rawEnv = (proj.envVars && typeof proj.envVars === 'object' && !Array.isArray(proj.envVars)) ? proj.envVars : {};
    const envKeys = Object.keys(rawEnv).map(sanitizeEnvKey).filter(Boolean).sort();

    lines.push(
      `resource "docker_network" "net_${slug}" {`,
      `  name   = "culkibo-net-${slug}"`,
      '  driver = "bridge"',
      '}',
      '',
      `resource "docker_container" "app_${slug}" {`,
      `  name         = "culkibo_${slug}"`,
      `  image        = "${image}"`,
      '  restart      = "unless-stopped"',
      `  memory       = ${memoryMb}`,
      `  stop_timeout = ${stopTimeout}`,
      '  log_driver   = "json-file"',
      '  log_opts = {',
      '    "max-size" = "10m"',
      '    "max-file" = "3"',
      '  }',
      '  networks_advanced {',
      `    name = docker_network.net_${slug}.name`,
      '  }',
      '  ports {',
      `    internal = ${port}`,
      `    external = ${port}`,
      '    ip       = "127.0.0.1"',
      '  }'
    );

    if (envKeys.length > 0) {
      lines.push('  env = [');
      for (const k of envKeys) {
        const tfVar = `${slug}_${String(k).toLowerCase()}`;
        lines.push(`    "${k}=\${var.${tfVar}}",`);
      }
      lines.push('  ]');
    }
    lines.push('}', '');
  }

  // Managed Databases (strictly bound to 127.0.0.1 — cures kamal#1856)
  if (estate.databases.length > 0) {
    lines.push(
      'resource "docker_network" "net_databases" {',
      '  name   = "culkibo-net-databases"',
      '  driver = "bridge"',
      '}',
      ''
    );
  }
  for (const db of estate.databases) {
    const slug = sanitizeIdent(db.id || db.name, 'db');
    const spec = resolveDbContainerSpec(db);
    const dbNameSafe = escapeHclString(db.dbName || db.database || 'app');
    const dbUserSafe = escapeHclString(db.username || 'postgres');
    const tfPwdVar = `db_${slug}_password`;

    lines.push(
      `resource "docker_volume" "vol_db_${slug}" {`,
      `  name = "culkibo_db_${slug}_data"`,
      '}',
      '',
      `resource "docker_container" "db_${slug}" {`,
      `  name         = "culkibo_db_${slug}"`,
      `  image        = "${escapeHclString(spec.image)}"`,
      '  restart      = "unless-stopped"',
      '  stop_timeout = 30',
      '  log_driver   = "json-file"',
      '  log_opts = {',
      '    "max-size" = "10m"',
      '    "max-file" = "3"',
      '  }',
      '  networks_advanced {',
      '    name = docker_network.net_databases.name',
      '  }',
      '  ports {',
      `    internal = ${spec.port}`,
      `    external = ${spec.port}`,
      '    ip       = "127.0.0.1"',
      '  }',
      '  volumes {',
      `    volume_name    = docker_volume.vol_db_${slug}.name`,
      `    container_path = "${escapeHclString(spec.dataPath)}"`,
      '  }',
      '  env = [',
      `    "${spec.envPasswordKey}=\${var.${tfPwdVar}}",`
    );
    if (spec.envUserKey) lines.push(`    "${spec.envUserKey}=${dbUserSafe}",`);
    if (spec.envDbKey) lines.push(`    "${spec.envDbKey}=${dbNameSafe}",`);
    lines.push('  ]', '}', '');
  }

  // Optional Cloudflare DNS records for exported domains
  for (const dom of estate.domains) {
    const host = String(dom && dom.hostname ? dom.hostname : '').trim().toLowerCase();
    if (!host) continue;
    const domSlug = sanitizeIdent(host, 'domain');
    lines.push(
      `resource "cloudflare_record" "dns_${domSlug}" {`,
      '  zone_id = var.cloudflare_zone_id',
      `  name    = "${escapeHclString(host)}"`,
      '  type    = "A"',
      '  content = var.culkibo_edge_ip',
      `  proxied = ${Boolean(dom.cloudflareProxied)}`,
      '  ttl     = 60',
      '}',
      ''
    );
  }

  return lines.join('\n').trimEnd() + '\n';
}

/**
 * Renderiza `variables.tf` con `sensitive = true` y SIN valores por defecto para secretos.
 * @param {Array<{ tfName: string, envName: string, description: string, sensitive: boolean, group: string }>} vars
 */
function renderTerraformVariables(vars) {
  const lines = [
    '# Culkibo IaC Variable Declarations — ZERO secret defaults stored in HCL',
    '# Supply values via TF_VAR_* or an untracked terraform.tfvars file.',
    ''
  ];
  for (const v of vars) {
    lines.push(
      `variable "${v.tfName}" {`,
      '  type        = string',
      `  description = "${escapeHclString(v.description)}"`
    );
    if (v.sensitive) {
      lines.push('  sensitive   = true');
    }
    lines.push('}', '');
  }
  return lines.join('\n').trimEnd() + '\n';
}

/**
 * Renderiza `outputs.tf` exponiendo únicamente metadatos públicos (nombres, dominios, IPs mesh).
 * @param {{ projects: any[], databases: any[], domains: any[], crons: any[], meshPeers: any[] }} estate
 */
function renderTerraformOutputs(estate) {
  const projNames = estate.projects.map((p) => `"${escapeHclString(p.name || p.id)}"`).join(', ');
  const domHosts = estate.domains.map((d) => `"${escapeHclString(d.hostname || '')}"`).filter((s) => s !== '""').join(', ');
  const dbNames = estate.databases.map((d) => `"${escapeHclString(d.name || d.id)}"`).join(', ');

  const lines = [
    '# Culkibo IaC Public Estate Outputs (0 private keys or credentials)',
    '',
    'output "project_names" {',
    `  value = [${projNames}]`,
    '}',
    '',
    'output "domain_hostnames" {',
    `  value = [${domHosts}]`,
    '}',
    '',
    'output "database_names" {',
    `  value = [${dbNames}]`,
    '}',
    '',
    'output "mesh_peer_ips" {',
    '  value = {'
  ];
  for (const peer of estate.meshPeers) {
    if (!peer || !peer.nodeId || !peer.meshIp) continue;
    lines.push(`    "${escapeHclString(peer.nodeId)}" = "${escapeHclString(peer.meshIp)}"`);
  }
  lines.push('  }', '}', '');
  return lines.join('\n');
}

/**
 * Renderiza un `docker-compose.yml` portátil v2+ (redes aisladas, `stop_grace_period: 30s`,
 * rotación de logs `json-file` acotada, bindings `127.0.0.1`, y placeholders `${VAR_NAME}`).
 * @param {{ projects: any[], databases: any[], domains: any[], crons: any[], meshPeers: any[] }} estate
 */
function renderPortableCompose(estate) {
  const lines = [
    '# Generated by Culkibo Zero Lock-In IaC Exporter (Portable Docker Compose v2+)',
    '# ZERO plaintext secrets — populate .env from .env.example before running `docker compose up -d`.',
    'services:'
  ];

  /** @type {Set<string>} */
  const networks = new Set();
  /** @type {Set<string>} */
  const volumes = new Set();

  if (estate.projects.length === 0 && estate.databases.length === 0) {
    lines.push('  # No projects or databases selected in this export');
  }

  for (const proj of estate.projects) {
    const slug = sanitizeIdent(proj.id || proj.name, 'app');
    const netName = `culkibo_net_${slug}`;
    networks.add(netName);
    const port = Number(proj.containerPort || proj.citadelPort) || 3000;
    const stopSec = Math.min(300, Math.max(5, Number(proj.stopGracePeriodSec) || 30));
    const memMb = Number(proj.memoryMb || proj.memoryLimitMb) || 512;
    const image = escapeYamlString(proj.imageTag || proj.activeImageTag || `culkibo/${slug}:latest`);
    const rawEnv = (proj.envVars && typeof proj.envVars === 'object' && !Array.isArray(proj.envVars)) ? proj.envVars : {};
    const envKeys = Object.keys(rawEnv).map(sanitizeEnvKey).filter(Boolean).sort();

    lines.push(
      `  app_${slug}:`,
      `    image: "${image}"`,
      '    restart: unless-stopped',
      `    stop_grace_period: ${stopSec}s`,
      `    mem_limit: ${memMb}m`,
      '    logging:',
      '      driver: json-file',
      '      options:',
      '        max-size: "10m"',
      '        max-file: "3"',
      '    ports:',
      `      - "127.0.0.1:${port}:${port}"`,
      '    networks:',
      `      - ${netName}`
    );
    if (envKeys.length > 0) {
      lines.push('    environment:');
      for (const k of envKeys) {
        const placeholder = `${slug.toUpperCase()}_${String(k).toUpperCase()}`;
        lines.push(`      ${k}: "\${${placeholder}}"`);
      }
    }
  }

  for (const db of estate.databases) {
    const slug = sanitizeIdent(db.id || db.name, 'db');
    const spec = resolveDbContainerSpec(db);
    const netName = 'culkibo_net_databases';
    const volName = `culkibo_db_${slug}_data`;
    networks.add(netName);
    volumes.add(volName);
    const pwdVar = `DB_${slug.toUpperCase()}_PASSWORD`;

    lines.push(
      `  db_${slug}:`,
      `    image: "${escapeYamlString(spec.image)}"`,
      '    restart: unless-stopped',
      '    stop_grace_period: 30s',
      '    logging:',
      '      driver: json-file',
      '      options:',
      '        max-size: "10m"',
      '        max-file: "3"',
      '    ports:',
      `      - "127.0.0.1:${spec.port}:${spec.port}"`,
      '    volumes:',
      `      - ${volName}:${escapeYamlString(spec.dataPath)}`,
      '    networks:',
      `      - ${netName}`,
      '    environment:',
      `      ${spec.envPasswordKey}: "\${${pwdVar}}"`
    );
    if (spec.envUserKey) lines.push(`      ${spec.envUserKey}: "${escapeYamlString(db.username || 'postgres')}"`);
    if (spec.envDbKey) lines.push(`      ${spec.envDbKey}: "${escapeYamlString(db.dbName || db.database || 'app')}"`);
  }

  if (networks.size > 0) {
    lines.push('', 'networks:');
    for (const n of networks) {
      lines.push(`  ${n}:`, '    driver: bridge');
    }
  }
  if (volumes.size > 0) {
    lines.push('', 'volumes:');
    for (const v of volumes) {
      lines.push(`  ${v}:`);
    }
  }

  return lines.join('\n') + '\n';
}

/**
 * Renderiza `.env.example` con claves y comentarios seguros (ZERO valores en claro).
 * @param {Array<{ tfName: string, envName: string, description: string, sensitive: boolean, group: string }>} vars
 */
function renderEnvExample(vars) {
  const lines = [
    '# Culkibo IaC Environment Template (.env.example)',
    '# Copy to .env and fill secret values locally. ZERO plaintext values were exported.',
    ''
  ];
  let lastGroup = '';
  for (const v of vars) {
    if (v.group !== lastGroup) {
      if (lastGroup) lines.push('');
      lines.push(`# --- ${v.group} ---`);
      lastGroup = v.group;
    }
    lines.push(`# ${v.description}`);
    lines.push(`${v.envName}=`);
  }
  return lines.join('\n').trimEnd() + '\n';
}

class IaCExporter {
  /**
   * @param {{
   *   projectManager?: any,
   *   databaseManager?: any,
   *   domainManager?: any,
   *   cronManager?: any,
   *   fleetMeshService?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    this._deps = {
      projectManager: opts.projectManager || null,
      databaseManager: opts.databaseManager || null,
      domainManager: opts.domainManager || null,
      cronManager: opts.cronManager || null,
      fleetMeshService: opts.fleetMeshService || null
    };
  }

  _collectEstate(snapshot, projectIds) {
    const idSet = Array.isArray(projectIds) ? new Set(projectIds.map(String)) : null;

    /** @type {any[]} */
    let projects = [];
    if (snapshot && Array.isArray(snapshot.projects)) {
      projects = snapshot.projects;
    } else {
      try {
        const pm = this._deps.projectManager || require('./projectManager');
        projects = Array.isArray(pm.getAll()) ? pm.getAll() : [];
      } catch (e) {}
    }
    if (idSet) {
      projects = projects.filter((p) => p && idSet.has(String(p.id)));
    }
    const keptProjIds = new Set(projects.map((p) => String(p.id)));

    /** @type {any[]} */
    let databases = [];
    if (snapshot && Array.isArray(snapshot.databases)) {
      databases = snapshot.databases;
    } else {
      try {
        const dbm = this._deps.databaseManager || require('./databaseManager');
        const list = typeof dbm.list === 'function' ? dbm.list() : [];
        databases = Array.isArray(list) ? list : [];
      } catch (e) {}
    }
    if (idSet) {
      databases = databases.filter((d) => d && (!d.projectId || keptProjIds.has(String(d.projectId))));
    }

    /** @type {any[]} */
    let domains = [];
    if (snapshot && Array.isArray(snapshot.domains)) {
      domains = snapshot.domains;
    } else {
      try {
        const dm = this._deps.domainManager || require('./domainManager');
        const list = typeof dm.listDomains === 'function' ? dm.listDomains() : [];
        domains = Array.isArray(list) ? list : [];
      } catch (e) {}
    }
    if (idSet) {
      domains = domains.filter((d) => d && d.projectId && keptProjIds.has(String(d.projectId)));
    }

    /** @type {any[]} */
    let crons = [];
    if (snapshot && Array.isArray(snapshot.crons)) {
      crons = snapshot.crons;
    } else {
      try {
        const cm = this._deps.cronManager || require('./cronManager');
        const list = typeof cm.list === 'function' ? cm.list() : [];
        crons = Array.isArray(list) ? list : [];
      } catch (e) {}
    }
    if (idSet) {
      crons = crons.filter((c) => c && c.projectId && keptProjIds.has(String(c.projectId)));
    }

    /** @type {any[]} */
    let meshPeers = [];
    if (snapshot && Array.isArray(snapshot.meshPeers)) {
      meshPeers = snapshot.meshPeers;
    } else {
      try {
        const fm = this._deps.fleetMeshService || require('./fleetMeshService');
        if (fm && fm.state && fm.state.peers) {
          meshPeers = Object.values(fm.state.peers);
        }
      } catch (e) {}
    }

    return { projects, databases, domains, crons, meshPeers };
  }

  /**
   * Exporta el estate completo (o filtrado por `projectIds`) a OpenTofu/Terraform HCL
   * y/o Docker Compose portátil con ZERO secretos en claro.
   *
   * @param {{
   *   format?: 'all' | 'terraform' | 'compose',
   *   projectIds?: string[] | null,
   *   snapshot?: { projects?: any[], databases?: any[], domains?: any[], crons?: any[], meshPeers?: any[] } | null
   * }} [opts]
   */
  exportEstate(opts = {}) {
    const rawFmt = String((opts && opts.format) || 'all').trim().toLowerCase();
    const format = rawFmt === 'terraform' || rawFmt === 'compose' ? rawFmt : 'all';
    const estate = this._collectEstate(opts.snapshot || null, opts.projectIds || null);
    const { vars, secretsRedactedCount } = buildRedactedVariableCatalog(estate);

    /** @type {Record<string, string>} */
    const files = {};
    if (format === 'all' || format === 'terraform') {
      files['main.tf'] = renderTerraformMain(estate);
      files['variables.tf'] = renderTerraformVariables(vars);
      files['outputs.tf'] = renderTerraformOutputs(estate);
    }
    if (format === 'all' || format === 'compose') {
      files['docker-compose.yml'] = renderPortableCompose(estate);
    }
    files['.env.example'] = renderEnvExample(vars);

    return {
      ok: true,
      format,
      generatedAt: new Date().toISOString(),
      files,
      stats: {
        projects: estate.projects.length,
        databases: estate.databases.length,
        domains: estate.domains.length,
        crons: estate.crons.length,
        meshPeers: estate.meshPeers.length
      },
      secretsRedactedCount
    };
  }
}

const instance = /** @type {any} */ (new IaCExporter());
instance.IaCExporter = IaCExporter;
instance.renderTerraformMain = renderTerraformMain;
instance.renderTerraformVariables = renderTerraformVariables;
instance.renderTerraformOutputs = renderTerraformOutputs;
instance.renderPortableCompose = renderPortableCompose;
instance.renderEnvExample = renderEnvExample;
module.exports = instance;
