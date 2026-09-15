const { EventEmitter } = require('events');
const containerOrchestrator = require('./containerOrchestrator');
const domainManager = require('./domainManager');
const sslManager = require('./sslManager');
const cloudflareService = require('./cloudflareService');
const projectManager = require('./projectManager');
const dockerManager = require('./dockerManager');
const dbBackupManager = require('./dbBackupManager');
const githubService = require('./githubService');
const ingressManager = require('./ingressManager');
const caddyManager = require('./caddyManager');

class McpServer extends EventEmitter {
  constructor() {
    super();
    this.auditLog = [];
    this.maxAuditLogs = 500;
  }

  getToolsDefinition() {
    return [
      {
        name: 'culkibo_create_project',
        description: 'Permite a la IA crear un nuevo proyecto (nombre, descripción, icono, gitRepo, puertos, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            description: { type: 'string' },
            icon: { type: 'string' },
            gitRepo: { type: 'string' },
            forgePort: { type: 'number' },
            citadelPort: { type: 'number' }
          },
          required: ['name']
        }
      },
      {
        name: 'culkibo_add_resource',
        description: 'Permite a la IA añadir un recurso a un proyecto (tipo: app, database, service).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            type: { type: 'string', enum: ['app', 'database', 'service'] },
            name: { type: 'string' },
            image: { type: 'string' },
            envVars: { type: 'object' },
            ports: { type: 'array', items: { type: 'string' } },
            credentials: { type: 'object' }
          },
          required: ['projectId', 'type', 'name']
        }
      },
      {
        name: 'culkibo_list_projects',
        description: 'Lista todos los proyectos con sus recursos y estados.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_get_project',
        description: 'Obtiene los detalles completos de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_set_project_env',
        description: 'Permite a la IA inyectar o actualizar variables de entorno de un proyecto o recurso específico.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            resourceId: { type: 'string', description: 'Opcional. ID o nombre del recurso específico (app, database, service) para inyectar variables de entorno.' },
            envVars: { type: 'object' }
          },
          required: ['projectId', 'envVars']
        }
      },
      {
        name: 'culkibo_deploy_project',
        description: 'Despliega o publica un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_list_pods',
        description: 'Inspect live status, metrics (CPU, RAM, latency), and traffic split between The Forge (hot-pod) and The Citadel (production).',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'culkibo_hot_sync',
        description: 'Register a code change against The Forge. NOTE: detection and classification only — the change is not yet transported to or applied on the pod. Returns applied:false.',
        inputSchema: {
          type: 'object',
          properties: {
            changedFile: { type: 'string', description: 'Relative path of the modified file (e.g. src/app.ts)' },
            diffSize: { type: 'string', description: 'Brief description of changes (e.g. 12 lines added)' }
          }
        }
      },
      {
        name: 'culkibo_switch_traffic',
        description: 'Instantly re-route incoming traffic between The Forge (dev) and The Citadel (prod).',
        inputSchema: {
          type: 'object',
          properties: {
            forgePercent: { type: 'number', description: 'Percentage of traffic to The Forge (0-100)' },
            citadelPercent: { type: 'number', description: 'Percentage of traffic to The Citadel (0-100)' }
          },
          required: ['citadelPercent']
        }
      },
      {
        name: 'culkibo_manage_domain',
        description: 'Add or configure custom domain, wildcard domain, or Cloudflare edge routing.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['add', 'delete', 'list', 'toggle_proxy', 'update'], description: 'Action to perform' },
            hostname: { type: 'string', description: 'Domain name (e.g. api.domain.com or *.domain.com)' },
            id: { type: 'string', description: 'Domain ID' },
            targetPod: { type: 'string', enum: ['forge', 'citadel'], description: 'Target pod to route traffic to' },
            cloudflareProxied: { type: 'boolean', description: 'Enable Cloudflare Orange Cloud (CDN/WAF/Edge)' },
            cloudflareZoneId: { type: 'string', description: 'Cloudflare Zone ID if applicable' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_inspect_ingress',
        description: 'Inspect edge ingress route resolution and TLS status for an incoming Host header.',
        inputSchema: {
          type: 'object',
          properties: {
            hostname: { type: 'string', description: 'Incoming hostname (e.g. preview.culkibo.dev)' }
          },
          required: ['hostname']
        }
      },
      {
        name: 'culkibo_manage_watcher',
        description: 'Start, stop, or inspect the directory watcher that detects code changes for The Forge.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'start', 'stop'], description: 'Watcher action' },
            directory: { type: 'string', description: 'Absolute or relative directory to watch (for start action)' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_issue_wildcard_ssl',
        description: 'Trigger Let\'s Encrypt ACME DNS-01 wildcard SSL certificate issuance via Cloudflare DNS-01 challenge.',
        inputSchema: {
          type: 'object',
          properties: {
            domain: { type: 'string', description: 'Domain name (e.g. *.culkibo.dev or culkibo.dev)' },
            zoneId: { type: 'string', description: 'Cloudflare Zone ID' },
            provider: { type: 'string', enum: ['lets_encrypt', 'zerossl'], description: 'ACME Certificate Authority' }
          },
          required: ['domain']
        }
      },
      {
        name: 'culkibo_create_sslip_domain',
        description: 'Generate instant Zero-Config wildcard domain with On-Demand TLS (e.g. *.127-0-0-1.sslip.io).',
        inputSchema: {
          type: 'object',
          properties: {
            ip: { type: 'string', description: 'Server IP address (default 127.0.0.1)' },
            service: { type: 'string', enum: ['sslip.io', 'nip.io'], description: 'Wildcard DNS service' }
          }
        }
      },
      {
        name: 'culkibo_get_logs',
        description: 'Retrieve real-time streaming or historical container logs from pods.',
        inputSchema: {
          type: 'object',
          properties: {
            pod: { type: 'string', enum: ['forge', 'citadel', 'all'], description: 'Target pod' },
            limit: { type: 'number', description: 'Number of recent log lines to retrieve' },
            search: { type: 'string', description: 'Filter keyword' }
          }
        }
      },
      {
        name: 'culkibo_docker_status',
        description: 'Comprueba el estado del motor Docker (modo nativo vs simulación sandbox), límites de memoria y contenedores.',
        inputSchema: {
          type: 'object',
          properties: {
            refresh: { type: 'boolean', description: 'Forzar recarga en vivo del estado de Docker' }
          }
        }
      },
      {
        name: 'culkibo_docker_containers',
        description: 'Lista los contenedores Docker activos o en modo sandbox con sus puertos, estados y métricas.',
        inputSchema: {
          type: 'object',
          properties: {
            all: { type: 'boolean', description: 'Incluir contenedores detenidos' },
            projectId: { type: 'string', description: 'Filtrar por ID de proyecto' }
          }
        }
      },
      {
        name: 'culkibo_export_backup',
        description: 'Genera un backup exportable completo de un proyecto (metadata, volúmenes, envs, dominios).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto a respaldar' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_restore_backup',
        description: 'Restaura un proyecto completo a partir de un archivo de backup JSON.',
        inputSchema: {
          type: 'object',
          properties: {
            backupFilePath: { type: 'string', description: 'Ruta absoluta o nombre del archivo de backup' }
          },
          required: ['backupFilePath']
        }
      },
      {
        name: 'culkibo_github_status',
        description: 'Obtiene el estado de conexión con GitHub y el usuario vinculado en Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_connect',
        description: 'Conecta un Personal Access Token (PAT) de GitHub con permisos de repo a Culkibo.',
        inputSchema: {
          type: 'object',
          properties: {
            token: { type: 'string', description: 'GitHub Personal Access Token (ghp_...)' }
          },
          required: ['token']
        }
      },
      {
        name: 'culkibo_github_disconnect',
        description: 'Desvincula la cuenta de GitHub de Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_list_repos',
        description: 'Lista los repositorios accesibles en la cuenta de GitHub conectada con soporte de búsqueda y paginación.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Término de búsqueda o filtro de repositorio' },
            page: { type: 'number', description: 'Número de página' },
            perPage: { type: 'number', description: 'Repositorios por página' }
          }
        }
      },
      {
        name: 'culkibo_github_get_branches',
        description: 'Lista las ramas disponibles en un repositorio de GitHub.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario u organización del repositorio' },
            repo: { type: 'string', description: 'Nombre del repositorio' }
          },
          required: ['owner', 'repo']
        }
      },
      {
        name: 'culkibo_github_auto_detect',
        description: 'Analiza automáticamente el código fuente de un repositorio de GitHub para inferir su stack tecnológico, comandos de build/start y puertos.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario del repositorio' },
            repo: { type: 'string', description: 'Nombre del repositorio' },
            branch: { type: 'string', description: 'Rama a inspeccionar (por defecto main)' }
          },
          required: ['owner', 'repo']
        }
      },
      {
        name: 'culkibo_create_project_from_github',
        description: 'Importa, autodetecta y despliega automáticamente un proyecto directamente desde GitHub.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario del repo en GitHub' },
            repo: { type: 'string', description: 'Nombre del repositorio' },
            branch: { type: 'string', description: 'Rama a desplegar (default main)' },
            name: { type: 'string', description: 'Nombre personalizado para el proyecto (opcional)' },
            description: { type: 'string', description: 'Descripción opcional' },
            autoDeploy: { type: 'boolean', description: 'Activar auto-despliegue en cada push (default true)' }
          },
          required: ['owner', 'repo']
        }
      }
    ];
  }

  logCall(toolName, args, result, success = true, durationMs = 0) {
    const entry = {
      id: `mcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      toolName,
      args,
      resultSummary: typeof result === 'object' ? JSON.stringify(result).slice(0, 160) : String(result),
      success,
      durationMs: Math.round(durationMs),
      agent: 'AI Assistant (MCP stdio/sse)'
    };
    this.auditLog.unshift(entry);
    if (this.auditLog.length > this.maxAuditLogs) this.auditLog.pop();
    this.emit('mcp_call', entry);
    return entry;
  }

  getAuditLog(limit = 50) {
    return this.auditLog.slice(0, limit);
  }

  async executeTool(toolName, args = {}) {
    const start = performance.now();
    try {
      let res;
      switch (toolName) {
        case 'culkibo_create_project':
          res = projectManager.create({
            name: args.name,
            description: args.description,
            icon: args.icon,
            gitRepo: args.gitRepo,
            forgePort: args.forgePort,
            citadelPort: args.citadelPort
          });
          break;

        case 'culkibo_add_resource': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new Error('Project not found');
          const resource = {
            id: `res_${Date.now()}`,
            type: args.type,
            name: args.name,
            image: args.image,
            envVars: args.envVars || {},
            ports: args.ports || [],
            credentials: args.credentials || {},
            status: 'active'
          };
          project.resources = project.resources || [];
          project.resources.push(resource);
          res = projectManager.update(args.projectId, { resources: project.resources });
          break;
        }

        case 'culkibo_list_projects':
          res = { projects: projectManager.getAll() };
          break;

        case 'culkibo_get_project':
          res = projectManager.getById(args.projectId);
          if (!res) throw new Error('Project not found');
          break;

        case 'culkibo_set_project_env': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new Error('Project not found');
          if (args.resourceId) {
            const resource = project.resources?.find(r => r.id === args.resourceId || r.name === args.resourceId);
            if (!resource) throw new Error('Resource not found');
            resource.envVars = { ...(resource.envVars || {}), ...args.envVars };
          } else {
            project.envVars = { ...(project.envVars || {}), ...args.envVars };
          }
          res = projectManager.update(args.projectId, { envVars: project.envVars, resources: project.resources });
          break;
        }

        case 'culkibo_deploy_project':
          res = projectManager.activate(args.projectId); // Simplified deploy
          break;

        case 'culkibo_list_pods':
          res = containerOrchestrator.getPods();
          break;

        case 'culkibo_hot_sync':
          res = await containerOrchestrator.triggerHotSync({
            changedFile: args.changedFile || 'src/main.ts',
            diffSize: args.diffSize || 'hot sync'
          });
          break;

        case 'culkibo_switch_traffic':
          res = await containerOrchestrator.switchTraffic({
            forgePercent: args.forgePercent !== undefined ? args.forgePercent : 100 - (args.citadelPercent || 0),
            citadelPercent: args.citadelPercent !== undefined ? args.citadelPercent : 100
          });
          break;

        case 'culkibo_manage_domain':
          if (args.action === 'list') {
            res = { domains: domainManager.listDomains() };
          } else if (args.action === 'add') {
            res = await domainManager.addDomain({
              hostname: args.hostname,
              targetPod: args.targetPod || 'forge',
              cloudflareProxied: args.cloudflareProxied ?? true,
              cloudflareZoneId: args.cloudflareZoneId
            });
          } else if (args.action === 'delete') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw new Error('Domain not found');
            res = await domainManager.deleteDomain(found.id);
          } else if (args.action === 'toggle_proxy') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw new Error('Domain not found');
            res = await domainManager.toggleProxy(found.id);
          } else if (args.action === 'update') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw new Error('Domain not found');
            const updates = {};
            if (args.targetPod) updates.targetPod = args.targetPod;
            if (args.targetPort) updates.targetPort = args.targetPort;
            if (args.cloudflareProxied !== undefined) updates.cloudflareProxied = args.cloudflareProxied;
            res = await domainManager.updateDomain(found.id, updates);
          }
          // Cualquier cambio en el registro de dominios tiene que llegar al
          // plano de datos en el mismo paso, o el agente creerá haber publicado
          // algo que no está publicado.
          if (args.action && args.action !== 'list') {
            res = { ...res, ingress: await ingressManager.reconcile() };
          }
          break;

        case 'culkibo_inspect_ingress': {
          const hostname = args.hostname;
          const route = domainManager.resolveRoute(hostname);
          // `tlsIssuer`/`tlsActive` salían del registro propio de certificados,
          // que se inventaba el emisor y la caducidad. Un agente que pregunte
          // por el TLS de un dominio tiene que recibir el handshake real, no
          // nuestra propia afirmación.
          const tls = await ingressManager.probeTls(hostname, { timeoutMs: 3000 });
          const detection = await caddyManager.detect();
          res = {
            hostname,
            found: Boolean(route),
            matchedRoute: route?.hostname || null,
            isWildcard: route?.isWildcard || false,
            targetPod: route?.targetPod || null,
            targetPort: route?.targetPort || null,
            projectId: route?.projectId || null,
            cloudflareProxied: route?.cloudflareProxied || false,
            dataPlane: 'caddy',
            ingressAvailable: detection.available,
            ingressReason: detection.reason,
            tls,
            trafficSplit: containerOrchestrator.trafficAllocation
          };
          break;
        }

        case 'culkibo_manage_watcher':
          if (args.action === 'start') {
            res = containerOrchestrator.watchDirectory(args.directory || process.cwd());
          } else if (args.action === 'stop') {
            res = containerOrchestrator.stopWatching();
          } else {
            res = containerOrchestrator.getWatcherStatus();
          }
          break;

        case 'culkibo_issue_wildcard_ssl':
          res = await sslManager.issueWildcardCertificate({
            domain: args.domain,
            zoneId: args.zoneId,
            provider: args.provider || 'lets_encrypt'
          });
          break;

        case 'culkibo_create_sslip_domain':
          const sslRes = await sslManager.issueOnDemandSslip({
            ip: args.ip || '127.0.0.1',
            service: args.service || 'sslip.io'
          });
          const newDom = await domainManager.addDomain({
            hostname: `app.${sslRes.cert.rootDomain}`,
            targetPod: 'forge',
            targetPort: 3001,
            routingMode: 'direct_dns'
          });
          res = { success: true, certificate: sslRes.cert, domain: newDom };
          break;

        case 'culkibo_get_logs':
          res = {
            logs: containerOrchestrator.getLogs({
              pod: args.pod === 'all' ? null : args.pod,
              limit: args.limit || 50,
              search: args.search || ''
            })
          };
          break;

        case 'culkibo_docker_status':
          res = await dockerManager.checkDockerStatus(args.refresh);
          break;

        case 'culkibo_docker_containers':
          res = {
            containers: await dockerManager.listContainers({
              all: args.all !== false,
              projectId: args.projectId
            })
          };
          break;

        case 'culkibo_export_backup':
          res = await dbBackupManager.exportProject(args.projectId);
          break;

        case 'culkibo_restore_backup':
          res = await dbBackupManager.restoreProject(args.backupFilePath);
          break;

        case 'culkibo_github_status':
          res = githubService.getStatus();
          break;

        case 'culkibo_github_connect':
          res = await githubService.connect(args.token);
          break;

        case 'culkibo_github_disconnect':
          res = await githubService.disconnect();
          break;

        case 'culkibo_github_list_repos':
          res = await githubService.getRepositories({
            page: args.page || 1,
            perPage: args.perPage || 30,
            search: args.search || ''
          });
          break;

        case 'culkibo_github_get_branches':
          res = await githubService.getBranches(args.owner, args.repo);
          break;

        case 'culkibo_github_auto_detect':
          res = await githubService.autoDetectRepo(args.owner, args.repo, args.branch || 'main');
          break;

        case 'culkibo_create_project_from_github': {
          const analysis = await githubService.autoDetectRepo(args.owner, args.repo, args.branch || 'main');
          const project = projectManager.create({
            name: args.name || args.repo,
            description: args.description || `Proyecto importado desde ${args.owner}/${args.repo}`,
            icon: analysis.icon || '🚀',
            forgePort: analysis.port || 3000,
            citadelPort: Math.floor(Math.random() * (9000 - 8000) + 8000),
            trafficSplit: { forge: 100, citadel: 0 },
            gitRepo: `https://github.com/${args.owner}/${args.repo}.git`,
            gitBranch: args.branch || 'main',
            githubOwner: args.owner,
            githubRepo: args.repo,
            source: 'github',
            buildCommand: analysis.buildCommand || '',
            startCommand: analysis.startCommand || '',
            watchPaths: analysis.watchPaths || ['src/**', 'public/**'],
            envVars: analysis.envVars || {},
            autoDeploy: args.autoDeploy !== false
          });
          projectManager.activate(project.id);
          res = { success: true, project, analysis };
          break;
        }

        default:
          throw new Error(`Unknown tool: ${toolName}`);
      }

      const durationMs = performance.now() - start;
      this.logCall(toolName, args, res, true, durationMs);
      return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
    } catch (err) {
      const durationMs = performance.now() - start;
      this.logCall(toolName, args, { error: err.message }, false, durationMs);
      return {
        isError: true,
        content: [{ type: 'text', text: `Error executing ${toolName}: ${err.message}` }]
      };
    }
  }

  // Handle standard JSON-RPC 2.0 MCP requests
  async handleJsonRpc(request) {
    const { id, method, params } = request;

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: {
            name: 'culkibo-mcp-orchestrator',
            version: '1.0.0'
          }
        }
      };
    }

    if (method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: this.getToolsDefinition()
        }
      };
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments || {};
      const toolResult = await this.executeTool(toolName, args);
      return {
        jsonrpc: '2.0',
        id,
        result: toolResult
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Method '${method}' not found`
      }
    };
  }

  getClientConfigs(serverUrl = 'http://localhost:3030') {
    return {
      claudeDesktop: {
        mcpServers: {
          culkibo: {
            command: 'node',
            args: ['c:\\Users\\pablo\\Desktop\\Culkibo\\bin\\culkibo.js', 'mcp'],
            env: {
              CULKIBO_API_URL: serverUrl
            }
          }
        }
      },
      cursorOrWindsurf: {
        mcpServers: {
          culkibo: {
            url: `${serverUrl}/api/mcp/sse`
          }
        }
      }
    };
  }
}

module.exports = new McpServer();
