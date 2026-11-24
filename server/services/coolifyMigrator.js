const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const localRunner = require('./localRunner');
const { assertSafeUrl, safeFetch } = require('./ssrfGuard');

const COOLIFY_SENSITIVE_META_RE = /(password|passwd|secret|token|private_key|api_key|apikey|credential|environment_variables|docker_compose_raw)/i;

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
          const [details, envs, storages] = await Promise.all([
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}`),
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/envs`).catch((e) => {
              if (e && (e.status === 401 || e.status === 403)) return { _authWarning: e.message };
              return [];
            }),
            this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/storages`).catch(() => null)
          ]);

          const detailsObj = Array.isArray(details) ? {} : (details || {});
          const fullItem = { ...item, ...detailsObj };
          if (envs && typeof envs === 'object' && !Array.isArray(envs) && envs._authWarning) {
            fullItem._warnings = [...(fullItem._warnings || []), `Sin permiso para leer variables: ${envs._authWarning}`];
          }
          fullItem.environment_variables = (Array.isArray(envs) && envs.length > 0) ? envs : (fullItem.environment_variables || []);

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
    return {
      apps,
      databases,
      services,
      projects
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

  async executeMigration(apiUrl, apiToken, options = {}) {
    return this.migrate(
      apiUrl,
      apiToken,
      options.apps !== undefined ? options.apps : null,
      options.dbs !== undefined ? options.dbs : null,
      options.services !== undefined ? options.services : null
    );
  }

  /**
   * @param {string} apiUrl
   * @param {string} apiToken
   * @param {string[] | null} [selectedApps]
   * @param {string[] | null} [selectedDbs]
   * @param {string[] | null} [selectedServices]
   */
  async migrate(apiUrl, apiToken, selectedApps = null, selectedDbs = null, selectedServices = null) {
    const apps = await this.fetchApplications(apiUrl, apiToken);
    const databases = await this.fetchDatabases(apiUrl, apiToken);
    const services = await this.fetchServices(apiUrl, apiToken);
    const projects = await this.fetchProjects(apiUrl, apiToken);

    const results = {
      importedApps: 0,
      importedDbs: 0,
      importedServices: 0,
      domainsLinked: 0,
      errors: /** @type {string[]} */ ([])
    };

    // Semántica estricta: null/undefined = importar todos; array explícito (incluido []) = sólo los seleccionados.
    const appsToImport = Array.isArray(selectedApps) ? apps.filter(app => selectedApps.includes(app.uuid)) : apps;
    const dbsToImport = Array.isArray(selectedDbs) ? databases.filter(db => selectedDbs.includes(db.uuid)) : databases;
    const servicesToImport = Array.isArray(selectedServices) ? services.filter(svc => selectedServices.includes(svc.uuid)) : services;

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

        const key = projectId;
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
                envVars: {},
                volumes: []
            });
        }
        return culkiboProjects.get(key);
    };

    const extractCommonFields = (res) => {
        /** @type {Record<string, string>} */
        const envVars = {};
        /** @type {Record<string, string>} */
        const previewEnvVars = {};
        if (res.environment_variables && Array.isArray(res.environment_variables)) {
             res.environment_variables.forEach(ev => {
                 if (!ev || !ev.key) return;
                 if (ev.is_preview) {
                   previewEnvVars[ev.key] = ev.value ?? '';
                 } else {
                   envVars[ev.key] = ev.value ?? '';
                 }
             });
        }

        const volumes = res.local_persistent_volumes || res.persistent_volumes || res.volumes || [];
        const fileMounts = res.local_file_volumes || [];

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

        const firstPort = parseInt(String(app.ports_exposes || app.port || '').split(',')[0], 10);
        if (!proj.gitRepo && effectiveGitRepo) proj.gitRepo = effectiveGitRepo;
        if (!proj.gitBranch && app.git_branch) proj.gitBranch = app.git_branch;
        if (!proj.buildCommand && app.build_command) proj.buildCommand = app.build_command;
        if (!proj.startCommand && app.start_command) proj.startCommand = app.start_command;
        if (!proj.baseDirectory && app.base_directory) proj.baseDirectory = app.base_directory;
        if (!proj.preDeployCommand && app.pre_deployment_command) proj.preDeployCommand = app.pre_deployment_command;
        if (!proj.postDeployCommand && app.post_deployment_command) proj.postDeployCommand = app.post_deployment_command;
        if (!proj.healthPath && app.health_check_path) proj.healthPath = app.health_check_path;
        if (!proj.containerPort && Number.isInteger(firstPort) && firstPort > 0 && firstPort < 65536) {
          proj.containerPort = firstPort;
          proj.citadelPort = firstPort;
        }
        const memMb = this.parseMemoryMb(app.limits_memory);
        if (!proj.memoryLimitMb && memMb) proj.memoryLimitMb = memMb;
        if (!proj.cpuLimit && app.limits_cpus && Number(app.limits_cpus) > 0) proj.cpuLimit = Number(app.limits_cpus);

        // Propagar variables de entorno y volúmenes de la app principal al proyecto raíz
        if (Object.keys(proj.envVars).length === 0 && Object.keys(common.envVars).length > 0) {
          Object.assign(proj.envVars, common.envVars);
        }
        if (Array.isArray(common.volumes) && common.volumes.length > 0 && proj.volumes.length === 0) {
          proj.volumes.push(...common.volumes);
        }

        proj.resources.push({
            id: app.uuid,
            type: 'app',
            name: app.name || 'Coolify App',
            description: app.description || `App migrada de Coolify (${app.uuid})`,
            gitRepo: effectiveGitRepo,
            image: imageName || undefined,
            domains: hosts,
            envVars: common.envVars,
            previewEnvVars: common.previewEnvVars,
            volumes: common.volumes,
            fileMounts: common.fileMounts,
            resourceLimits: common.resourceLimits,
            healthCheck: common.healthCheck,
            networkConfig: common.networkConfig,
            buildConfig: buildConfig,
            deployCommands: deployCommands,
            gitDetails: gitDetails,
            ports: app.ports_exposes || app.ports_mappings || app.port || '',
            status: this.normalizeCoolifyStatus(app.status),
            rawMeta: sanitizeCoolifyMeta(app)
        });

        for (const host of hosts) {
          proj.pendingHosts.push(host);
          proj.domains.push(host);
        }
        results.importedApps++;
      } catch (e) {
        results.errors.push(`App ${app.name}: ${e.message}`);
      }
    }

    // 2. Migrate DBs (soporta standalone-postgresql, mysql, mariadb, redis, keydb, dragonfly, clickhouse, mongodb)
    for (const db of dbsToImport) {
      try {
        const proj = getProjectForResource(db);
        const common = extractCommonFields(db);
        const rawType = String(db.database_type || db.type || 'database').toLowerCase();
        const dbEngine = rawType.includes('postgres') ? 'postgres'
          : rawType.includes('mariadb') ? 'mariadb'
          : rawType.includes('mysql') ? 'mysql'
          : (rawType.includes('redis') || rawType.includes('keydb') || rawType.includes('dragonfly')) ? 'valkey'
          : rawType.includes('mongo') ? 'mongodb'
          : rawType.includes('clickhouse') ? 'clickhouse'
          : rawType;

        proj.resources.push({
            id: db.uuid,
            type: 'database',
            engine: dbEngine,
            image: db.image || undefined,
            name: db.name || 'Coolify DB',
            description: db.description || `Base de datos (${db.database_type || db.type || 'DB'}). Importada de Coolify.`,
            status: this.normalizeCoolifyStatus(db.status),
            envVars: common.envVars,
            port: db.public_port || db.port || null,
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

    // 3. Migrate Services (incluyendo dominios en svc.applications[].fqdn)
    for (const svc of servicesToImport) {
      try {
        const proj = getProjectForResource(svc);
        const common = extractCommonFields(svc);
        const svcHosts = [...this.parseFqdnHosts(svc.fqdn)];
        if (Array.isArray(svc.applications)) {
          for (const subApp of svc.applications) {
            svcHosts.push(...this.parseFqdnHosts(subApp?.fqdn));
          }
        }
        const uniqueSvcHosts = Array.from(new Set(svcHosts));

        proj.resources.push({
            id: svc.uuid,
            type: 'service',
            name: svc.name || 'Coolify Service',
            description: svc.description || `Servicio Docker Compose migrado (${svc.uuid})`,
            status: this.normalizeCoolifyStatus(svc.status),
            domains: uniqueSvcHosts,
            envVars: common.envVars,
            dockerCompose: svc.docker_compose || svc.docker_compose_raw || '',
            volumes: common.volumes,
            fileMounts: common.fileMounts,
            resourceLimits: common.resourceLimits,
            healthCheck: common.healthCheck,
            networkConfig: common.networkConfig,
            rawMeta: sanitizeCoolifyMeta(svc)
        });
        for (const host of uniqueSvcHosts) {
          proj.pendingHosts.push(host);
          proj.domains.push(host);
        }
        results.importedServices++;
      } catch (e) {
        results.errors.push(`Service ${svc.name}: ${e.message}`);
      }
    }

    // Save projects & link domains with the real created projectId
    for (const [key, projData] of culkiboProjects.entries()) {
        try {
            const pendingHosts = Array.from(new Set(projData.pendingHosts || []));
            delete projData.pendingHosts;
            projData.domains = pendingHosts;
            const created = projectManager.create(projData);
            const realProjectId = (created && created.id) || projData.id;
            for (const host of pendingHosts) {
              try {
                await domainManager.addDomain({
                  hostname: host,
                  projectId: realProjectId,
                  targetPod: 'citadel',
                  targetPort: (created && created.citadelPort) || projData.citadelPort || 3000,
                  cloudflareProxied: false,
                  sslStatus: 'pending_migration',
                  sslProvider: 'lets_encrypt',
                  migrationSource: 'coolify'
                });
                results.domainsLinked++;
              } catch (e) {
                // Si el dominio ya existía, enlazarlo al proyecto migrado si no tenía propietario
                try {
                  const existing = domainManager.getByHostname ? domainManager.getByHostname(host) : null;
                  if (existing && !existing.projectId) {
                    await domainManager.updateDomain(existing.id, { projectId: realProjectId });
                    results.domainsLinked++;
                  }
                } catch (_) {}
              }
            }
            if (created && created.gitRepo) {
                localRunner.prepareProject(created).catch(() => {});
            }
        } catch(e) {
            results.errors.push(`Error guardando proyecto ${key}: ${e.message}`);
        }
    }

    try {
      await projectManager.flushToDisk();
    } catch (e) {}

    if (results.domainsLinked > 0) {
      try {
        await require('./ingressManager').reconcile();
      } catch (e) {}
    }

    return results;
  }
}

module.exports = new CoolifyMigrator();
