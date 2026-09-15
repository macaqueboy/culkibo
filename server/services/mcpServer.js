const { EventEmitter } = require('events');
const containerOrchestrator = require('./containerOrchestrator');
const domainManager = require('./domainManager');
const sslManager = require('./sslManager');
const cloudflareService = require('./cloudflareService');
const projectManager = require('./projectManager');
const dockerManager = require('./dockerManager');
const dbBackupManager = require('./dbBackupManager');
const githubService = require('./githubService');

// ---------------------------------------------------------------------------
// Revisiones del protocolo.
//
// 2026-07-28 eliminó el handshake `initialize`: ya no hay negociación por
// conexión, cada petición declara su propia versión en
// `_meta["io.modelcontextprotocol/protocolVersion"]` y, sobre HTTP, también en
// la cabecera `MCP-Protocol-Version`. Por eso el servidor valida por petición
// y no guarda estado de sesión.
//
// `LEGACY_PROTOCOL_VERSION` es la era anterior (handshake `initialize`), que
// seguimos sirviendo en /api/mcp/message y /api/mcp/sse para no romper las
// configuraciones de Cursor y Claude Desktop ya instaladas. Está deprecada.
// ---------------------------------------------------------------------------
const PROTOCOL_VERSION = '2026-07-28';
const SUPPORTED_PROTOCOL_VERSIONS = [PROTOCOL_VERSION];
const LEGACY_PROTOCOL_VERSION = '2024-11-05';

const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CLIENT_INFO = 'io.modelcontextprotocol/clientInfo';
const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';

// Prefijo propio para metadatos que no define la especificación. La segunda
// etiqueta no puede ser `mcp` ni `modelcontextprotocol`: esas están reservadas.
const META_CULKIBO_ERROR = 'dev.culkibo/error';

const SERVER_INFO = { name: 'culkibo-mcp-orchestrator', version: '1.0.0' };

// -32020..-32099 es el rango que la especificación se reserva. Solo se emiten
// los códigos que ella define, y solo con su significado.
const ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  HEADER_MISMATCH: -32020,
  MISSING_REQUIRED_CLIENT_CAPABILITY: -32021,
  UNSUPPORTED_PROTOCOL_VERSION: -32022
};

// Métodos que sirve el transporte moderno. Cualquier otro es 404 + -32601.
const MODERN_METHODS = ['server/discover', 'tools/list', 'tools/call'];

// Métodos que obligan a enviar la cabecera `Mcp-Name`.
const NAME_BEARING_METHODS = ['tools/call', 'resources/read', 'prompts/get'];

/**
 * Error de ejecución de herramienta con forma accionable.
 *
 * El cliente primario de Culkibo es un agente, no una persona leyendo un log.
 * Un `Error` pelado le obliga a adivinar del texto si puede reintentar o si
 * debe cambiar de argumentos; este lleva el código estable, si es reintentable
 * y qué hacer a continuación.
 */
class McpToolError extends Error {
  constructor(code, message, { retryable = false, remediation = null, details = {} } = {}) {
    super(message);
    this.name = 'McpToolError';
    this.code = code;
    this.retryable = retryable;
    this.remediation = remediation;
    this.details = details;
  }
}

function jsonType(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

function matchesSchemaType(value, expected) {
  switch (expected) {
    case 'string': return typeof value === 'string';
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'integer': return Number.isInteger(value);
    case 'boolean': return typeof value === 'boolean';
    case 'array': return Array.isArray(value);
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
    default: return true;
  }
}

/**
 * Validación de argumentos contra el `inputSchema` declarado.
 *
 * Se hace aquí y no en cada `case` porque el fallo de un agente casi siempre es
 * el mismo —falta un campo obligatorio o mete un valor fuera del enum— y ese
 * fallo se corrige solo si la respuesta dice exactamente qué falta. Antes se
 * colaba hasta el servicio y volvía como un `TypeError` ilegible.
 */
function validateToolArguments(tool, args) {
  const schema = tool.inputSchema || {};
  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];

  const missing = required.filter((key) => args[key] === undefined || args[key] === null);
  if (missing.length > 0) {
    throw new McpToolError(
      'MISSING_ARGUMENT',
      `Faltan argumentos obligatorios en ${tool.name}: ${missing.join(', ')}.`,
      {
        retryable: true,
        remediation: `Repite la llamada incluyendo ${missing.join(', ')}.`,
        details: { missing, required, received: Object.keys(args) }
      }
    );
  }

  for (const [key, value] of Object.entries(args)) {
    const spec = properties[key];
    if (!spec || value === undefined || value === null) continue;

    if (Array.isArray(spec.enum) && !spec.enum.includes(value)) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${key}' de ${tool.name} no admite el valor ${JSON.stringify(value)}.`,
        {
          retryable: true,
          remediation: `Usa uno de estos valores para '${key}': ${spec.enum.join(', ')}.`,
          details: { argument: key, received: value, allowed: spec.enum }
        }
      );
    }

    if (spec.type && !matchesSchemaType(value, spec.type)) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${key}' de ${tool.name} debe ser de tipo ${spec.type}.`,
        {
          retryable: true,
          remediation: `Convierte '${key}' a ${spec.type} y vuelve a llamar.`,
          details: { argument: key, expectedType: spec.type, receivedType: jsonType(value) }
        }
      );
    }
  }
}

// Fallos de «no existe». Un agente los resuelve solo si la respuesta le dice
// con qué herramienta obtener el identificador bueno, así que siempre lo dice.
function projectNotFoundError(projectId) {
  return new McpToolError('PROJECT_NOT_FOUND', `No existe ningún proyecto con el identificador '${projectId}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_list_projects y usa el campo id de uno de los proyectos devueltos.',
    details: { projectId: projectId ?? null }
  });
}

function resourceNotFoundError(projectId, resourceId) {
  return new McpToolError('RESOURCE_NOT_FOUND', `El proyecto '${projectId}' no tiene ningún recurso llamado '${resourceId}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_get_project y usa el id o el name de uno de los recursos listados.',
    details: { projectId: projectId ?? null, resourceId: resourceId ?? null }
  });
}

function domainNotFoundError({ hostname, id }) {
  return new McpToolError('DOMAIN_NOT_FOUND', `No hay ningún dominio configurado que coincida con '${hostname || id}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_manage_domain con action "list" para ver los dominios registrados y sus id.',
    details: { hostname: hostname ?? null, id: id ?? null }
  });
}

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
        title: 'Crear proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
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
        title: 'Añadir recurso a un proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
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
        title: 'Listar proyectos',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projects: { type: 'array', description: 'Proyectos con sus recursos y estado.' }
          }
        },
        description: 'Lista todos los proyectos con sus recursos y estados.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_get_project',
        title: 'Ver un proyecto',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Obtiene los detalles completos de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_set_project_env',
        title: 'Inyectar variables de entorno',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
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
        title: 'Desplegar proyecto',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Despliega o publica un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_list_pods',
        title: 'Estado de los pods',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            pods: { type: 'object', description: 'Estado de The Forge y The Citadel.' },
            trafficAllocation: { type: 'object', description: 'Reparto de tráfico en porcentaje.' },
            totalRequestsServed: { type: 'number' },
            activeConnections: { type: 'number' },
            daemon: { type: 'object' },
            localProcesses: { type: 'object' }
          }
        },
        description: 'Inspect live status, metrics (CPU, RAM, latency), and traffic split between The Forge (hot-pod) and The Citadel (production).',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'culkibo_hot_sync',
        title: 'Registrar cambio en The Forge',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
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
        title: 'Repartir tráfico entre Forge y Citadel',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
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
        title: 'Gestionar dominios',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
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
        title: 'Inspeccionar el enrutado de ingress',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            hostname: { type: 'string' },
            found: { type: 'boolean' },
            matchedRoute: {
              type: ['string', 'null']
            },
            isWildcard: { type: 'boolean' },
            targetPod: {
              type: ['string', 'null']
            },
            targetPort: {
              type: ['number', 'null']
            },
            cloudflareProxied: { type: 'boolean' },
            tlsIssuer: {
              type: ['string', 'null']
            },
            tlsActive: { type: 'boolean' },
            trafficSplit: { type: 'object' }
          }
        },
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
        title: 'Gestionar el vigilante de ficheros',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
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
        title: 'Emitir certificado wildcard (ACME DNS-01)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
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
        title: 'Crear dominio comodín instantáneo',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
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
        title: 'Leer logs de los pods',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            logs: { type: 'array', description: 'Líneas de log más recientes, de la más nueva a la más antigua.' }
          }
        },
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
        title: 'Estado del motor Docker',
        annotations: { readOnlyHint: true, openWorldHint: false },
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
        title: 'Listar contenedores Docker',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            containers: { type: 'array' }
          }
        },
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
        title: 'Exportar backup de un proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
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
        title: 'Restaurar un proyecto desde backup',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
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
        title: 'Estado de la conexión con GitHub',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Obtiene el estado de conexión con GitHub y el usuario vinculado en Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_connect',
        title: 'Conectar una cuenta de GitHub',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
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
        title: 'Desconectar la cuenta de GitHub',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Desvincula la cuenta de GitHub de Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_list_repos',
        title: 'Listar repositorios de GitHub',
        annotations: { readOnlyHint: true, openWorldHint: true },
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
        title: 'Listar ramas de un repositorio',
        annotations: { readOnlyHint: true, openWorldHint: true },
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
        title: 'Autodetectar el stack de un repositorio',
        annotations: { readOnlyHint: true, openWorldHint: true },
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
        title: 'Importar y desplegar desde GitHub',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
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

  logCall(toolName, args, result, success = true, durationMs = 0, transport = 'MCP stdio/sse') {
    const entry = {
      id: `mcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      toolName,
      args,
      resultSummary: typeof result === 'object' ? JSON.stringify(result).slice(0, 160) : String(result),
      success,
      durationMs: Math.round(durationMs),
      // El transporte deja de ser una cadena fija: ahora hay dos eras vivas y
      // la auditoría tiene que decir por cuál entró cada llamada.
      transport,
      agent: `AI Assistant (${transport})`
    };
    this.auditLog.unshift(entry);
    if (this.auditLog.length > this.maxAuditLogs) this.auditLog.pop();
    this.emit('mcp_call', entry);
    return entry;
  }

  getAuditLog(limit = 50) {
    return this.auditLog.slice(0, limit);
  }

  /**
   * Ejecuta una herramienta y devuelve el `CallToolResult` neutro respecto a la
   * era: `resultType` lo añade solo el manejador moderno, porque 2024-11-05 no
   * lo define y no queremos meterlo en respuestas de la era antigua.
   *
   * @param {string} toolName
   * @param {object} args
   * @param {{ transport?: string }} context
   */
  async executeTool(toolName, args = {}, context = {}) {
    const start = performance.now();
    const transport = context.transport || 'MCP stdio/sse';
    const tool = this.getToolsDefinition().find((t) => t.name === toolName);
    try {
      if (!tool) {
        throw new McpToolError('UNKNOWN_TOOL', `Esta instalación de Culkibo no expone ninguna herramienta llamada '${toolName}'.`, {
          retryable: false,
          remediation: 'Llama a tools/list para ver el catálogo vigente y usa uno de esos nombres.',
          details: { requested: toolName }
        });
      }
      validateToolArguments(tool, args);

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
          if (!project) throw projectNotFoundError(args.projectId);
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
          if (!res) throw projectNotFoundError(args.projectId);
          break;

        case 'culkibo_set_project_env': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.resourceId) {
            const resource = project.resources?.find(r => r.id === args.resourceId || r.name === args.resourceId);
            if (!resource) throw resourceNotFoundError(args.projectId, args.resourceId);
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
            if (!found) throw domainNotFoundError(args);
            res = await domainManager.deleteDomain(found.id);
          } else if (args.action === 'toggle_proxy') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw domainNotFoundError(args);
            res = await domainManager.toggleProxy(found.id);
          } else if (args.action === 'update') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw domainNotFoundError(args);
            const updates = {};
            if (args.targetPod) updates.targetPod = args.targetPod;
            if (args.targetPort) updates.targetPort = args.targetPort;
            if (args.cloudflareProxied !== undefined) updates.cloudflareProxied = args.cloudflareProxied;
            res = await domainManager.updateDomain(found.id, updates);
          }
          break;

        case 'culkibo_inspect_ingress': {
          const hostname = args.hostname;
          const route = domainManager.resolveRoute(hostname);
          const cert = sslManager.getCertificateByDomain(hostname);
          res = {
            hostname,
            found: Boolean(route),
            matchedRoute: route?.hostname || null,
            isWildcard: route?.isWildcard || false,
            targetPod: route?.targetPod || null,
            targetPort: route?.targetPort || null,
            cloudflareProxied: route?.cloudflareProxied || false,
            tlsIssuer: cert?.issuer || null,
            tlsActive: Boolean(cert),
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
          // Inalcanzable: `tool` ya se resolvió contra el catálogo más arriba.
          throw new McpToolError('UNKNOWN_TOOL', `La herramienta '${toolName}' está declarada pero no implementada.`, {
            retryable: false,
            remediation: 'Repórtalo como fallo de Culkibo: el catálogo y el despachador no coinciden.',
            details: { requested: toolName }
          });
      }

      const durationMs = performance.now() - start;
      this.logCall(toolName, args, res, true, durationMs, transport);

      const result = {
        content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        isError: false
      };
      // `structuredContent` evita que el agente tenga que reparsear el texto.
      // Solo se adjunta si el resultado es JSON estructurado, porque un
      // escalar suelto no aporta nada frente al bloque de texto.
      if (res !== null && typeof res === 'object') result.structuredContent = res;
      return result;
    } catch (err) {
      const durationMs = performance.now() - start;
      const envelope = this.describeToolFailure(toolName, tool, err, durationMs);
      this.logCall(toolName, args, { error: envelope.code, message: envelope.message }, false, durationMs, transport);
      return {
        isError: true,
        // El error va como JSON en el bloque de texto —no como prosa— para que
        // el agente lea `code`, `retryable` y `remediation` sin adivinar. No se
        // adjunta `structuredContent`: ese campo está contratado por el
        // `outputSchema` de la herramienta, que describe el éxito, no el fallo.
        content: [{ type: 'text', text: JSON.stringify(envelope, null, 2) }],
        _meta: { [META_CULKIBO_ERROR]: envelope }
      };
    }
  }

  /**
   * Convierte cualquier excepción en un sobre que un agente pueda accionar.
   *
   * Los errores que no vienen ya tipados se clasifican por la anotación
   * `openWorldHint` de la herramienta: si habla con un tercero (Cloudflare,
   * GitHub, una CA ACME) el fallo es casi siempre transitorio y reintentarlo
   * tiene sentido; si es local, reintentar sin cambiar nada solo repite el
   * fallo.
   */
  describeToolFailure(toolName, tool, err, durationMs) {
    const typed = err instanceof McpToolError;
    const openWorld = Boolean(tool && tool.annotations && tool.annotations.openWorldHint);
    return {
      ok: false,
      tool: toolName,
      code: typed ? err.code : (openWorld ? 'UPSTREAM_ERROR' : 'INTERNAL_ERROR'),
      message: err && err.message ? err.message : String(err),
      retryable: typed ? err.retryable : openWorld,
      remediation: typed
        ? err.remediation
        : (openWorld
          ? 'El servicio externo falló o no respondió. Reintenta en unos segundos; si persiste, comprueba credenciales y conectividad.'
          : 'Revisa los argumentos y el estado del daemon con culkibo_docker_status o culkibo_list_pods antes de reintentar.'),
      details: typed ? err.details : {},
      durationMs: Math.round(durationMs),
      timestamp: new Date().toISOString()
    };
  }

  // -------------------------------------------------------------------------
  // Era antigua (2024-11-05): handshake `initialize` y sesión implícita.
  //
  // DEPRECADO. Se mantiene porque romper las configuraciones ya instaladas de
  // Cursor y Claude Desktop sería peor que arrastrarlo, pero no recibe
  // funciones nuevas: lo nuevo vive en `handleModernRpc`.
  // -------------------------------------------------------------------------
  async handleJsonRpc(request) {
    const { id, method, params } = request;

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: LEGACY_PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
          instructions: `Este endpoint habla la revisión ${LEGACY_PROTOCOL_VERSION}, deprecada. Culkibo ya sirve la revisión ${PROTOCOL_VERSION} en POST /api/mcp (Streamable HTTP, sin handshake).`
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
      const toolResult = await this.executeTool(toolName, args, { transport: `MCP ${LEGACY_PROTOCOL_VERSION} (deprecado)` });
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
        code: ERROR_CODES.METHOD_NOT_FOUND,
        message: `Method '${method}' not found`,
        data: {
          supported: ['initialize', 'tools/list', 'tools/call'],
          hint: `Este endpoint sirve la revisión ${LEGACY_PROTOCOL_VERSION}. Para ${PROTOCOL_VERSION} usa POST /api/mcp.`
        }
      }
    };
  }

  // -------------------------------------------------------------------------
  // Era moderna (2026-07-28): sin handshake, sin sesión, versión por petición.
  // -------------------------------------------------------------------------

  /**
   * Respuesta de `server/discover`: versiones, capacidades e identidad en una
   * sola llamada. La especificación la hace obligatoria.
   */
  getDiscoverResult() {
    return {
      supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
      capabilities: {
        // `listChanged: false` es la verdad: el catálogo es estático en el
        // proceso, así que no prometemos notificaciones que nunca emitiríamos.
        tools: { listChanged: false }
      },
      instructions: [
        'Culkibo es un orquestador cloud autohospedado. Sus herramientas gestionan proyectos, pods (The Forge para desarrollo y The Citadel para producción), dominios, certificados TLS, contenedores Docker, copias de seguridad y la integración con GitHub.',
        'Empieza por culkibo_list_projects y culkibo_list_pods para situarte antes de modificar nada.',
        'Las herramientas anotadas con destructiveHint cambian tráfico en producción, sobrescriben credenciales o borran estado: confírmalas con la persona usuaria antes de llamarlas.',
        'Cuando una llamada falla, el bloque de texto del resultado es un JSON con code, retryable y remediation: úsalo para decidir si reintentar o corregir los argumentos.'
      ].join(' '),
      // El catálogo no depende de quién pregunte, así que la respuesta es
      // cacheable por cualquiera.
      ttlMs: 300000,
      cacheScope: 'public'
    };
  }

  /**
   * Despacha una petición JSON-RPC de la revisión 2026-07-28.
   *
   * Solo recibe peticiones ya validadas por el transporte (cabeceras, `_meta`,
   * versión). Lo único que puede fallar aquí es el método o la herramienta.
   *
   * @param {object} request mensaje JSON-RPC completo
   * @param {{ transport?: string, isCancelled?: () => boolean }} context
   */
  async handleModernRpc(request, context = {}) {
    const { id, method, params } = request;
    const transport = context.transport || `MCP ${PROTOCOL_VERSION}`;

    const ok = (result) => ({
      jsonrpc: '2.0',
      id,
      result: {
        resultType: 'complete',
        ...result,
        _meta: { ...(result._meta || {}), [META_SERVER_INFO]: SERVER_INFO }
      }
    });

    if (method === 'server/discover') {
      return ok(this.getDiscoverResult());
    }

    if (method === 'tools/list') {
      return ok({ tools: this.getToolsDefinition(), ttlMs: 60000, cacheScope: 'public' });
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments || {};
      const toolResult = await this.executeTool(toolName, args, { transport });
      return ok(toolResult);
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: ERROR_CODES.METHOD_NOT_FOUND,
        message: `Este servidor no implementa el método '${method}'.`,
        data: { method, supported: MODERN_METHODS }
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
      // Clientes con transporte HTTP: el endpoint moderno, un solo POST.
      cursorOrWindsurf: {
        mcpServers: {
          culkibo: {
            url: `${serverUrl}/api/mcp`
          }
        }
      },
      // Solo para clientes que aún no hablan 2026-07-28. Ver README.
      legacySse: {
        deprecated: true,
        protocolVersion: LEGACY_PROTOCOL_VERSION,
        note: `Transporte HTTP+SSE deprecado desde la revisión 2025-03-26. Migra a ${serverUrl}/api/mcp.`,
        mcpServers: {
          culkibo: {
            url: `${serverUrl}/api/mcp/sse`
          }
        }
      },
      protocol: {
        current: PROTOCOL_VERSION,
        supported: SUPPORTED_PROTOCOL_VERSIONS,
        endpoint: `${serverUrl}/api/mcp`,
        legacyEndpoint: `${serverUrl}/api/mcp/sse`
      }
    };
  }
}

const mcpServer = new McpServer();

// Constantes del protocolo, para que el transporte no las duplique.
mcpServer.protocol = {
  PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  LEGACY_PROTOCOL_VERSION,
  META_PROTOCOL_VERSION,
  META_CLIENT_INFO,
  META_CLIENT_CAPABILITIES,
  META_SERVER_INFO,
  ERROR_CODES,
  MODERN_METHODS,
  NAME_BEARING_METHODS,
  SERVER_INFO
};
mcpServer.McpToolError = McpToolError;

module.exports = mcpServer;
