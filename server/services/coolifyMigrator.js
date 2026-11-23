const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const localRunner = require('./localRunner');
const { assertSafeUrl, safeFetch } = require('./ssrfGuard');

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
        const httpErr = new Error(`Coolify respondió HTTP ${response.status}`);
        /** @type {any} */ (httpErr).status = response.status;
        throw httpErr;
      }
      const rawText = response.text().trim();
      return rawText ? JSON.parse(rawText) : [];
    } catch (err) {
      if (err && /SSRF|inválida|protocolo|metadatos|privada/i.test(String(err.message || ''))) {
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
    
    const results = [];
    for (const item of list) {
      try {
        const safeUuid = encodeURIComponent(String(item.uuid || ''));
        const details = await this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}`);
        const envs = await this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/envs`);
        const storages = await this.fetchFromApi(apiUrl, apiToken, `${detailEndpointPrefix}/${safeUuid}/storages`);
        
        // fetchFromApi returns [] on error. If it's an array, it means it failed (or is unexpectedly an array).
        const detailsObj = Array.isArray(details) ? {} : (details || {});
        
        const fullItem = { ...item, ...detailsObj };
        
        // If envs is valid array, use it, otherwise fallback to item's envs
        fullItem.environment_variables = (Array.isArray(envs) && envs.length > 0) ? envs : (fullItem.environment_variables || []);
        
        // Extract persistent storages and file storages from Coolify v4 /storages endpoint
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
        
        results.push(fullItem);
      } catch (err) {
        results.push(item);
      }
    }
    return results;
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

  async executeMigration(apiUrl, apiToken, options = {}) {
    return this.migrate(
      apiUrl,
      apiToken,
      options.apps || [],
      options.dbs || [],
      options.services || []
    );
  }

  async migrate(apiUrl, apiToken, selectedApps = [], selectedDbs = [], selectedServices = []) {
    const apps = await this.fetchApplications(apiUrl, apiToken);
    const databases = await this.fetchDatabases(apiUrl, apiToken);
    const services = await this.fetchServices(apiUrl, apiToken);
    const projects = await this.fetchProjects(apiUrl, apiToken);
    
    const results = {
      importedApps: 0,
      importedDbs: 0,
      importedServices: 0,
      errors: /** @type {string[]} */ ([])
    };

    const appsToImport = selectedApps.length > 0 ? apps.filter(app => selectedApps.includes(app.uuid)) : apps;
    const dbsToImport = selectedDbs.length > 0 ? databases.filter(db => selectedDbs.includes(db.uuid)) : databases;
    const servicesToImport = selectedServices.length > 0 ? services.filter(svc => selectedServices.includes(svc.uuid)) : services;

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
                envVars: {}
            });
        }
        return culkiboProjects.get(key);
    };

    const extractCommonFields = (res) => {
        const envVars = {};
        if (res.environment_variables && Array.isArray(res.environment_variables)) {
             res.environment_variables.forEach(ev => {
                 envVars[ev.key] = ev.value;
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

        return { envVars, volumes, fileMounts, resourceLimits, healthCheck, networkConfig };
    };

    // 1. Migrate Apps
    for (const app of appsToImport) {
      try {
        const domains = app.fqdn ? app.fqdn.split(',').map(d => d.trim()) : [];
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

        const gitDetails = {
            git_full_url: app.git_full_url,
            git_commit_sha: app.git_commit_sha,
            private_key_id: app.private_key_id,
            docker_registry_image_name: app.docker_registry_image_name,
            docker_registry_image_tag: app.docker_registry_image_tag
        };

        const proj = getProjectForResource(app);
        if (!proj.gitRepo && (app.git_repository || app.git_full_url)) {
            proj.gitRepo = app.git_repository || app.git_full_url;
        }
        if (!proj.gitBranch && app.git_branch) {
            proj.gitBranch = app.git_branch;
        }
        if (!proj.buildCommand && app.build_command) {
            proj.buildCommand = app.build_command;
        }
        if (!proj.startCommand && app.start_command) {
            proj.startCommand = app.start_command;
        }
        if (!proj.baseDirectory && app.base_directory) {
            proj.baseDirectory = app.base_directory;
        }

        proj.resources.push({
            id: app.uuid,
            type: 'app',
            name: app.name || 'Coolify App',
            description: app.description || `App migrada de Coolify (${app.uuid})`,
            gitRepo: app.git_repository || app.git_full_url || '',
            domains: domains,
            envVars: common.envVars,
            volumes: common.volumes,
            fileMounts: common.fileMounts,
            resourceLimits: common.resourceLimits,
            healthCheck: common.healthCheck,
            networkConfig: common.networkConfig,
            buildConfig: buildConfig,
            deployCommands: deployCommands,
            gitDetails: gitDetails,
            ports: app.ports_exposes || app.ports_mappings || app.port || '',
            status: app.status === 'running' ? 'active' : 'stopped',
            rawMeta: app
        });

        for (const domain of domains) {
          const host = domain.replace(/^https?:\/\//, '');
          try {
            await domainManager.addDomain({
              hostname: host,
              targetPod: 'citadel',
              cloudflareProxied: false,
              sslStatus: 'pending_migration',
              sslProvider: 'lets_encrypt',
              migrationSource: 'coolify'
            });
            proj.domains.push(host);
          } catch (e) {
            // ignore domain already exists
          }
        }
        results.importedApps++;
      } catch (e) {
        results.errors.push(`App ${app.name}: ${e.message}`);
      }
    }

    // 2. Migrate DBs
    for (const db of dbsToImport) {
      try {
        const proj = getProjectForResource(db);
        const common = extractCommonFields(db);

        proj.resources.push({
            id: db.uuid,
            type: 'database',
            name: db.name || 'Coolify DB',
            description: db.description || `Base de datos (${db.database_type || 'DB'}). Importada de Coolify.`,
            status: db.status === 'running' ? 'active' : 'stopped',
            envVars: common.envVars,
            port: db.public_port || db.port || null,
            credentials: {
                user: db.database_user || db.postgres_user || db.mysql_user || db.mariadb_user || db.mongo_initdb_root_username || '',
                password: db.database_password || db.postgres_password || db.mysql_password || db.mariadb_password || db.mongo_initdb_root_password || '',
                rootPassword: db.database_root_password || db.mysql_root_password || db.mariadb_root_password || '',
                dbName: db.database_name || db.postgres_db || db.mysql_database || db.mariadb_database || ''
            },
            volumes: common.volumes,
            fileMounts: common.fileMounts,
            resourceLimits: common.resourceLimits,
            healthCheck: common.healthCheck,
            networkConfig: common.networkConfig,
            rawMeta: db
        });
        results.importedDbs++;
      } catch (e) {
        results.errors.push(`DB ${db.name}: ${e.message}`);
      }
    }

    // 3. Migrate Services
    for (const svc of servicesToImport) {
      try {
        const proj = getProjectForResource(svc);
        const common = extractCommonFields(svc);

        proj.resources.push({
            id: svc.uuid,
            type: 'service',
            name: svc.name || 'Coolify Service',
            description: svc.description || `Servicio Docker Compose migrado (${svc.uuid})`,
            status: svc.status === 'running' ? 'active' : 'stopped',
            envVars: common.envVars,
            dockerCompose: svc.docker_compose || svc.docker_compose_raw || '',
            volumes: common.volumes,
            fileMounts: common.fileMounts,
            resourceLimits: common.resourceLimits,
            healthCheck: common.healthCheck,
            networkConfig: common.networkConfig,
            rawMeta: svc
        });
        results.importedServices++;
      } catch (e) {
        results.errors.push(`Service ${svc.name}: ${e.message}`);
      }
    }

    // Save projects
    for (const [key, projData] of culkiboProjects.entries()) {
        try {
            // Remove duplicates from domains
            projData.domains = [...new Set(projData.domains)];
            const created = projectManager.create(projData);
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

    return results;
  }
}

module.exports = new CoolifyMigrator();
