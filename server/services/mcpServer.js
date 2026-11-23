const path = require('path');
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
const deployManager = require('./deployManager');
const databaseManager = require('./databaseManager');
const catalogManager = require('./catalogManager');
const liveSyncEngine = require('./liveSyncEngine');
const coolifyMigrator = require('./coolifyMigrator');
const wordpressMigrator = require('./wordpressMigrator');
const universalImporter = require('./universalImporter');
const metricsCollector = require('./metricsCollector');
const systemDoctor = require('./systemDoctor');

const SENSITIVE_KEY_RE = /(token|password|passwd|secret|apikey|api_key|authorization|credential|connectionstring|envvars)/i;
const REDACTED_RESULT_TOOLS = new Set([
  'culkibo_database_credentials',
  'culkibo_github_connect',
  'culkibo_create_database',
  'culkibo_set_project_env',
  'culkibo_migrate_coolify'
]);

/** Redacta recursivamente tokens, contraseñas y secretos antes de guardar o emitir auditoría MCP. */
function redactForAudit(value, depth = 0) {
  if (depth > 5) return '[…]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (/(ghp_|gho_|github_pat_|sk_|bearer\s+)/i.test(value)) return '***';
    return value.length > 240 ? `${value.slice(0, 240)}…` : value;
  }
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 25).map(v => redactForAudit(v, depth + 1));
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEY_RE.test(k)) {
      out[k] = typeof v === 'object' && v !== null ? '[oculto]' : '***';
    } else {
      out[k] = redactForAudit(v, depth + 1);
    }
  }
  return out;
}

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
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ retryable?: boolean, remediation?: string | null, details?: Record<string, any> }} [opts]
   */
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
    /** @type {any[] | null} */
    this._toolsCache = null;
    /** @type {Map<string, any> | null} */
    this._toolsByName = null;
    /** @type {Buffer | null} */
    this._toolsSerializedCache = null;
    /** @type {any | null} */
    this._discoverCache = null;
  }

  getToolsDefinition() {
    if (this._toolsCache) return this._toolsCache;
    this._toolsCache = [
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
        title: 'Emitir certificado wildcard (NO IMPLEMENTADO)',
        // `readOnlyHint: true`: la herramienta ya no cambia nada. Un agente no
        // debe creer que invocarla tiene efecto — antes escribía un PEM falso.
        // Sin `destructiveHint`/`idempotentHint`: sólo significan algo cuando la
        // herramienta muta, y ésta no muta.
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'NOT IMPLEMENTED. Culkibo does not issue wildcard certificates: TLS is issued on demand by Caddy at the first handshake of each host, and certificates live in Caddy\'s volume, not in data/certs/. This tool always returns an explanatory error; it never issues anything. Use culkibo_create_sslip_domain or query /api/ingress/status for the real TLS state.',
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
        description: 'Register an instant Zero-Config wildcard hostname (e.g. *.127-0-0-1.sslip.io) whose certificate Caddy issues on demand at the first HTTPS handshake. Culkibo stores no key material and cannot report the certificate\'s issuer or expiry; query /api/ingress/status for the verified handshake.',
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
      },

      // --- Producción (deployManager: Docker BuildKit + Caddy zero-downtime) ---
      {
        name: 'culkibo_deploy_strategy',
        title: 'Analizar estrategia de despliegue',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Inspecciona en seco el repositorio del proyecto (Dockerfile, railpack, nixpacks o Dockerfile generado con BuildKit) sin construir nada.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_deploy_production',
        title: 'Desplegar a producción (zero-downtime)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Construye la imagen Docker con caché BuildKit, verifica salud en el nuevo contenedor, conmuta la ruta atómica en Caddy y drena el contenedor anterior sin caídas.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            commit: { type: 'string', description: 'Hash de commit específico opcional' },
            gitSync: { type: 'boolean', description: 'Si false, despliega el árbol ya presente en disco (default true)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_list_deployments',
        title: 'Listar despliegues de producción',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve el estado actual de producción (Citadel) y el historial reciente de despliegues de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            limit: { type: 'number', description: 'Máximo de entradas (default 10)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_rollback_deployment',
        title: 'Revertir despliegue en producción',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Revierte a la release anterior conmutando la ruta en Caddy (sin reconstruir la imagen cuando el contenedor anterior sigue en reserva).',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_prune_build_cache',
        title: 'Podar caché de construcción Docker',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Libera espacio de caché de Docker BuildKit bajo demanda (nunca se ejecuta automáticamente).',
        inputSchema: {
          type: 'object',
          properties: {
            keepStorageGb: { type: 'number', description: 'GB de caché a conservar (default 10)' },
            untilHours: { type: 'number', description: 'Opcional: podar entradas con más de N horas de antigüedad' }
          }
        }
      },

      // --- Bases de datos gestionadas + copias S3/R2 ---
      {
        name: 'culkibo_list_databases',
        title: 'Listar bases de datos gestionadas',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista las bases de datos gestionadas (PostgreSQL 18, MySQL 9, MariaDB 12.3, Valkey, Redis, MongoDB 8) con su salud y copias programadas. Nunca expone contraseñas.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'Filtrar opcionalmente por proyecto' } }
        }
      },
      {
        name: 'culkibo_create_database',
        title: 'Aprovisionar base de datos gestionada',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Aprovisiona en un clic una base de datos aislada en la red del proyecto con contraseña de 192 bits cifrada en AES-256-GCM y cero puertos expuestos por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto propietario' },
            engine: { type: 'string', enum: ['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb'], description: 'Motor de base de datos' },
            name: { type: 'string', description: 'Nombre legible de la base de datos' },
            dbName: { type: 'string', description: 'Nombre lógico del esquema (opcional)' },
            memoryMb: { type: 'number', description: 'Límite de RAM en MB (opcional)' }
          },
          required: ['projectId', 'engine']
        }
      },
      {
        name: 'culkibo_database_backup',
        title: 'Ejecutar copia de seguridad de base de datos',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Genera un volcado comprimido en disco y lo sube automáticamente a S3/R2 si hay almacenamiento remoto configurado.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_database_credentials',
        title: 'Consultar credenciales de base de datos',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve explícitamente las credenciales descifradas y la cadena de conexión interna de una base de datos gestionada.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_delete_database',
        title: 'Eliminar base de datos gestionada',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Elimina una base de datos gestionada y opcionalmente su volumen persistente de datos.',
        inputSchema: {
          type: 'object',
          properties: {
            databaseId: { type: 'string', description: 'ID de la base de datos' },
            deleteVolume: { type: 'boolean', description: 'Borrar también el volumen persistente (irreversible, default false)' }
          },
          required: ['databaseId']
        }
      },

      // --- Catálogo de servicios de un clic ---
      {
        name: 'culkibo_list_catalog_templates',
        title: 'Explorar catálogo de servicios de un clic',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista las 14 plantillas curadas del catálogo de un clic (WordPress, n8n, Ghost, Plausible, Uptime Kuma, Metabase, MinIO, Gitea, Vaultwarden, Umami, Listmonk, NocoDB, Stirling-PDF, Redis Commander).',
        inputSchema: {
          type: 'object',
          properties: { category: { type: 'string', description: 'Filtrar opcionalmente por categoría' } }
        }
      },
      {
        name: 'culkibo_install_catalog_service',
        title: 'Instalar servicio del catálogo en un clic',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Instala un servicio del catálogo con red aislada, base de datos gestionada, secretos criptográficos y ruta HTTPS automática en Caddy.',
        inputSchema: {
          type: 'object',
          properties: {
            templateId: { type: 'string', description: 'ID de plantilla (p. ej. n8n, ghost, uptime-kuma, plausible)' },
            name: { type: 'string', description: 'Nombre de la instalación (opcional)' },
            domain: { type: 'string', description: 'Dominio público opcional para HTTPS automático' }
          },
          required: ['templateId']
        }
      },
      {
        name: 'culkibo_list_catalog_installations',
        title: 'Listar servicios instalados del catálogo',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista todos los servicios instalados desde el catálogo junto con su estado, salud y URL.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_uninstall_catalog_service',
        title: 'Desinstalar servicio del catálogo',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Desinstala un servicio del catálogo, retirando contenedores, red y ruta de ingress.',
        inputSchema: {
          type: 'object',
          properties: {
            installationId: { type: 'string', description: 'ID de la instalación' },
            deleteVolumes: { type: 'boolean', description: 'Borrar también los volúmenes persistentes y BD (default false)' }
          },
          required: ['installationId']
        }
      },

      // --- Sincronización en vivo (The Forge: Commit Frames + Merkle + Rollback + Promoción) ---
      {
        name: 'culkibo_verify_sync',
        title: 'Verificar integridad de sincronización (Merkle)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Calcula el árbol Merkle real en disco de un proyecto y reporta estado de sincronización, divergencia y percentiles reales de latencia (p50/p95/p99).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            clientDigest: { type: 'string', description: 'Digest SHA-256 raíz opcional del árbol local del agente para comprobar cero divergencia' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_rollback_sync',
        title: 'Revertir parche en vivo (<10 ms)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Revierte los últimos commit frames de sincronización en vivo directamente desde el historial de parches en memoria sin reconstruir.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            steps: { type: 'number', description: 'Número de commit frames a revertir (default 1)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_promote_forge',
        title: 'Promocionar Forge verificado a Citadel',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Congela el árbol exacto verificado en The Forge y lo despliega a producción (The Citadel) con zero-downtime sin requerir un git push previo.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },

      // --- Migrador de Coolify v4 vía MCP ---
      {
        name: 'culkibo_migrate_coolify',
        title: 'Migrar proyectos desde Coolify v4',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Conecta con la API v4 de una instancia de Coolify para previsualizar (`mode: "preview"`) o importar (`mode: "import"`) todos sus proyectos, apps, bases de datos, variables y volúmenes.',
        inputSchema: {
          type: 'object',
          properties: {
            coolifyUrl: { type: 'string', description: 'URL base de Coolify (p. ej. https://coolify.midominio.com)' },
            apiToken: { type: 'string', description: 'API Token de Coolify v4' },
            mode: { type: 'string', enum: ['preview', 'import'], description: 'preview solo inspecciona; import crea los proyectos en Culkibo (default preview)' }
          },
          required: ['coolifyUrl', 'apiToken']
        }
      },

      // --- Migrador de WordPress, Importador Compose y Acceso Remoto ---
      {
        name: 'culkibo_analyze_wordpress',
        title: 'Analizar web WordPress para migración',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Inspecciona una web WordPress en vivo (HTML + /wp-json) para detectar versión, tema, plugins, WooCommerce, Cloudflare y generar un plan de migración sin cortes a Culkibo.',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'URL pública del sitio WordPress (p. ej. https://mitienda.com)' }
          },
          required: ['url']
        }
      },
      {
        name: 'culkibo_import_compose',
        title: 'Importar stack desde Docker Compose',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Analiza un archivo docker-compose.yml (mode: "parse") o lo importa como proyecto Culkibo (mode: "import"), detectando bases de datos y avisos de producción.',
        inputSchema: {
          type: 'object',
          properties: {
            yamlText: { type: 'string', description: 'Contenido completo del archivo docker-compose.yml' },
            projectName: { type: 'string', description: 'Nombre del proyecto en Culkibo (opcional)' },
            mode: { type: 'string', enum: ['parse', 'import'], description: 'parse solo analiza; import crea el proyecto (default parse)' }
          },
          required: ['yamlText']
        }
      },
      {
        name: 'culkibo_get_remote_access',
        title: 'Consultar configuración de acceso remoto y agentes',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve el estado de acceso remoto del daemon (dominio del panel, túneles Cloudflare, endpoints MCP/WebSocket y plantillas listas para clientes de IA).',
        inputSchema: {
          type: 'object',
          properties: {
            serverUrl: { type: 'string', description: 'URL base del servidor Culkibo (opcional)' }
          }
        }
      },
      {
        name: 'culkibo_get_observability',
        title: 'Consultar telemetría y latencia real en vivo',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve métricas reales medidas en tiempo de ejecución: latencia HTTP (p50/p95/p99), RPS, event-loop lag, RAM/heap, WebSockets, Live Sync y estado de Caddy.',
        inputSchema: {
          type: 'object',
          properties: {
            fresh: { type: 'boolean', description: 'Forzar muestreo sin caché de 250 ms (opcional)' }
          }
        }
      },
      {
        name: 'culkibo_system_doctor',
        title: 'Ejecutar diagnóstico completo del sistema',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Ejecuta el diagnóstico integral del servidor (Node, Docker, Caddy, disco/RAM, postura de seguridad, dominios, copias de seguridad y residuos temporales) con recomendaciones concretas.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
    this._toolsByName = new Map(this._toolsCache.map((t) => [t.name, t]));
    return this._toolsCache;
  }

  /** Buffer JSON pre-serializado para GET /api/mcp/tools. */
  getToolsSerialized() {
    if (!this._toolsSerializedCache) {
      const tools = this.getToolsDefinition();
      this._toolsSerializedCache = Buffer.from(JSON.stringify({
        protocolVersion: PROTOCOL_VERSION,
        tools,
        count: tools.length
      }), 'utf8');
    }
    return this._toolsSerializedCache;
  }

  getToolByName(toolName) {
    if (!this._toolsByName) this.getToolsDefinition();
    return (this._toolsByName && this._toolsByName.get(toolName)) || null;
  }

  logCall(toolName, args, result, success = true, durationMs = 0, transport = 'MCP stdio/sse') {
    const safeArgs = redactForAudit(args);
    let resultSummary;
    if (REDACTED_RESULT_TOOLS.has(toolName) && success) {
      resultSummary = '[resultado sensible ocultado en auditoría]';
    } else if (typeof result === 'object' && result !== null) {
      resultSummary = JSON.stringify(redactForAudit(result)).slice(0, 160);
    } else {
      resultSummary = String(redactForAudit(result));
    }
    const entry = {
      id: `mcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      toolName,
      args: safeArgs,
      resultSummary,
      success,
      durationMs: Math.round(durationMs),
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
   * @param {string} toolName
   * @param {any} args
   * @param {{ transport?: string }} [context]
   */
  async executeTool(toolName, args = {}, context = {}) {
    const start = performance.now();
    const transport = context.transport || 'MCP stdio/sse';
    const tool = this.getToolByName(toolName);
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
          await projectManager.flushToDisk();
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
          await projectManager.flushToDisk();
          break;
        }

        case 'culkibo_list_projects':
          res = {
            projects: projectManager.getAll().map((p) => ({
              ...p,
              webhookSecret: p.webhookSecret ? '[oculto]' : undefined,
              envVarsKeys: Object.keys(p.envVars || {})
            }))
          };
          break;

        case 'culkibo_get_project': {
          const p = projectManager.getById(args.projectId);
          if (!p) throw projectNotFoundError(args.projectId);
          res = {
            ...p,
            webhookSecret: p.webhookSecret ? '[oculto]' : undefined,
            envVarsKeys: Object.keys(p.envVars || {})
          };
          break;
        }

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
          await projectManager.flushToDisk();
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
          res = { ...res, ingress: await ingressManager.reconcile() };
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
            let watchDir = process.cwd();
            if (args.directory) {
              const resolved = path.resolve(String(args.directory));
              if (process.env.CULKIBO_ALLOW_ARBITRARY_WATCH !== '1') {
                const projectsRoot = path.resolve(__dirname, '..', '..', 'projects');
                const cwdRoot = path.resolve(process.cwd());
                const inProjects = !path.relative(projectsRoot, resolved).startsWith('..') && !path.isAbsolute(path.relative(projectsRoot, resolved));
                const inCwd = !path.relative(cwdRoot, resolved).startsWith('..') && !path.isAbsolute(path.relative(cwdRoot, resolved));
                if (!inProjects && !inCwd) {
                  throw new Error('Solo se permite observar directorios dentro del espacio de trabajo de Culkibo');
                }
              }
              watchDir = resolved;
            }
            res = containerOrchestrator.watchDirectory(watchDir);
          } else if (args.action === 'stop') {
            res = await containerOrchestrator.stopWatching();
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
          res = { success: true, certificate: sslRes.cert, domain: newDom, ingress: await ingressManager.reconcile() };
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

        case 'culkibo_deploy_strategy': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          const contextDir = liveSyncEngine.resolveTargetDir(project.id);
          const strategy = await deployManager.detectStrategy(contextDir, project);
          res = { projectId: project.id, contextDir, strategy };
          break;
        }

        case 'culkibo_deploy_production': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          res = await deployManager.deploy(project, {
            commit: args.commit || null,
            gitSync: args.gitSync !== false,
            trigger: 'mcp'
          });
          break;
        }

        case 'culkibo_list_deployments': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          res = {
            projectId: project.id,
            status: await deployManager.status(project.id),
            deployments: deployManager.listDeployments(project.id, Number(args.limit) || 10)
          };
          break;
        }

        case 'culkibo_rollback_deployment': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          res = await deployManager.rollback(project.id);
          break;
        }

        case 'culkibo_prune_build_cache': {
          res = await deployManager.pruneBuildCache({
            keepStorageGb: args.keepStorageGb !== undefined ? Number(args.keepStorageGb) : 10,
            untilHours: args.untilHours !== undefined ? Number(args.untilHours) : null
          });
          break;
        }

        case 'culkibo_list_databases': {
          res = {
            engines: databaseManager.listEngines(),
            databases: databaseManager.list({ projectId: args.projectId || undefined })
          };
          break;
        }

        case 'culkibo_create_database': {
          res = await databaseManager.provision({
            projectId: args.projectId,
            engine: args.engine,
            name: args.name,
            dbName: args.dbName,
            memoryMb: args.memoryMb
          });
          break;
        }

        case 'culkibo_database_backup': {
          res = await databaseManager.runBackup(args.databaseId, { trigger: 'mcp' });
          break;
        }

        case 'culkibo_database_credentials': {
          res = databaseManager.getCredentials(args.databaseId);
          break;
        }

        case 'culkibo_delete_database': {
          res = await databaseManager.remove(args.databaseId, { deleteVolume: Boolean(args.deleteVolume) });
          break;
        }

        case 'culkibo_list_catalog_templates': {
          const all = catalogManager.listTemplates();
          const templates = args.category ? all.filter((t) => t.category === args.category) : all;
          res = { categories: catalogManager.listCategories(), templates };
          break;
        }

        case 'culkibo_install_catalog_service': {
          res = await catalogManager.install({
            templateId: args.templateId,
            name: args.name,
            domain: args.domain || null
          });
          break;
        }

        case 'culkibo_list_catalog_installations': {
          res = { installations: catalogManager.list() };
          break;
        }

        case 'culkibo_uninstall_catalog_service': {
          res = await catalogManager.remove(args.installationId, { deleteVolumes: Boolean(args.deleteVolumes) });
          break;
        }

        case 'culkibo_verify_sync': {
          const verification = liveSyncEngine.verifySync(args.projectId, {
            clientDigest: args.clientDigest || null
          });
          res = { ...verification, telemetry: liveSyncEngine.getStatus(args.projectId) };
          break;
        }

        case 'culkibo_rollback_sync': {
          res = liveSyncEngine.rollback(args.projectId, Number(args.steps) || 1);
          break;
        }

        case 'culkibo_promote_forge': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          const targetDir = liveSyncEngine.resolveTargetDir(project.id);
          const verification = liveSyncEngine.verifySync(project.id);
          const deployment = await deployManager.deploy(project, {
            contextDir: targetDir,
            gitSync: false,
            trigger: 'mcp_forge_promote'
          });
          res = { promoted: deployment.status === 'activo', workspaceDigest: verification.serverDigest, deployment };
          break;
        }

        case 'culkibo_migrate_coolify': {
          const mode = args.mode === 'import' ? 'import' : 'preview';
          if (mode === 'preview') {
            const preview = await coolifyMigrator.previewMigration(args.coolifyUrl, args.apiToken);
            res = { mode: 'preview', ...preview };
          } else {
            const migration = await coolifyMigrator.executeMigration(args.coolifyUrl, args.apiToken, {
              apps: Array.isArray(args.apps) ? args.apps : [],
              dbs: Array.isArray(args.dbs) ? args.dbs : [],
              services: Array.isArray(args.services) ? args.services : []
            });
            await projectManager.flushToDisk();
            res = { mode: 'import', ...migration };
          }
          break;
        }

        case 'culkibo_analyze_wordpress': {
          res = await wordpressMigrator.analyzeSite(args.url);
          break;
        }

        case 'culkibo_import_compose': {
          if (args.mode === 'import') {
            res = await universalImporter.importDockerCompose({
              yamlText: args.yamlText,
              projectName: args.projectName || ''
            });
            await projectManager.flushToDisk();
          } else {
            res = universalImporter.parseDockerCompose(args.yamlText);
          }
          break;
        }

        case 'culkibo_get_remote_access': {
          const base = args.serverUrl || (ingressManager.panelDomain ? `https://${ingressManager.panelDomain}` : `http://localhost:${process.env.PORT || 3030}`);
          res = {
            panelDomain: ingressManager.panelDomain || null,
            caddy: await caddyManager.detect(),
            cloudflare: cloudflareService.getConfigStatus(),
            clientConfigs: this.getClientConfigs(base)
          };
          break;
        }

        case 'culkibo_get_observability': {
          res = metricsCollector.getSnapshot(Boolean(args.fresh));
          break;
        }

        case 'culkibo_system_doctor': {
          res = await systemDoctor.runDoctor();
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
    if (!this._discoverCache) {
      this._discoverCache = {
        supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
        capabilities: {
          // `listChanged: false` es la verdad: el catálogo es estático en el
          // proceso, así que no prometemos notificaciones que nunca emitiríamos.
          tools: { listChanged: false }
        },
        instructions: [
          'Culkibo es un orquestador cloud autohospedado. Sus herramientas gestionan proyectos, pods (The Forge para desarrollo y The Citadel para producción), dominios, certificados TLS, contenedores Docker, copias de seguridad, migración WordPress/Compose/Coolify y la integración con GitHub.',
          'Empieza por culkibo_list_projects y culkibo_list_pods para situarte antes de modificar nada.',
          'Las herramientas anotadas con destructiveHint cambian tráfico en producción, sobrescriben credenciales o borran estado: confírmalas con la persona usuaria antes de llamarlas.',
          'Cuando una llamada falla, el bloque de texto del resultado es un JSON con code, retryable y remediation: úsalo para decidir si reintentar o corregir los argumentos.'
        ].join(' '),
        ttlMs: 300000,
        cacheScope: 'public'
      };
    }
    return this._discoverCache;
  }

  /**
   * Despacha una petición JSON-RPC de la revisión 2026-07-28.
   *
   * Solo recibe peticiones ya validadas por el transporte (cabeceras, `_meta`,
   * versión). Lo único que puede fallar aquí es el método o la herramienta.
   *
   * @param {any} request mensaje JSON-RPC completo
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

  getClientConfigs(serverUrl = 'http://localhost:3030', { includeAuthPlaceholder = false } = {}) {
    const cleanUrl = String(serverUrl || 'http://localhost:3030').replace(/\/+$/, '');
    const cliEntry = path.resolve(__dirname, '..', '..', 'bin', 'culkibo.js');
    const isRemote = !/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(cleanUrl);
    const needAuth = includeAuthPlaceholder || isRemote;
    const remoteHeaders = needAuth ? { Authorization: 'Bearer TU_CULKIBO_TOKEN' } : undefined;

    return {
      claudeDesktop: {
        mcpServers: {
          culkibo: {
            command: 'node',
            args: [cliEntry, 'mcp'],
            env: {
              CULKIBO_API_URL: cleanUrl,
              ...(needAuth ? { CULKIBO_TOKEN: 'TU_CULKIBO_TOKEN' } : {})
            }
          }
        }
      },
      // Clientes con transporte HTTP: el endpoint moderno, un solo POST.
      cursorOrWindsurf: {
        mcpServers: {
          culkibo: {
            url: `${cleanUrl}/api/mcp`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      vscodeCopilot: {
        servers: {
          culkibo: {
            type: 'http',
            url: `${cleanUrl}/api/mcp`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      claudeCodeCli: needAuth
        ? `claude mcp add --transport http culkibo ${cleanUrl}/api/mcp --header "Authorization: Bearer TU_CULKIBO_TOKEN"`
        : `claude mcp add --transport http culkibo ${cleanUrl}/api/mcp`,
      // Solo para clientes que aún no hablan 2026-07-28. Ver README.
      legacySse: {
        deprecated: true,
        protocolVersion: LEGACY_PROTOCOL_VERSION,
        note: `Transporte HTTP+SSE deprecado desde la revisión 2025-03-26. Migra a ${cleanUrl}/api/mcp.`,
        mcpServers: {
          culkibo: {
            url: `${cleanUrl}/api/mcp/sse`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      protocol: {
        current: PROTOCOL_VERSION,
        supported: SUPPORTED_PROTOCOL_VERSIONS,
        endpoint: `${cleanUrl}/api/mcp`,
        legacyEndpoint: `${cleanUrl}/api/mcp/sse`,
        wsUrl: `${cleanUrl.replace(/^http/, 'ws')}/ws/sync`
      }
    };
  }
}

const mcpServer = Object.assign(new McpServer(), {
  // Constantes del protocolo, para que el transporte no las duplique.
  protocol: {
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
  },
  McpToolError
});

module.exports = mcpServer;
