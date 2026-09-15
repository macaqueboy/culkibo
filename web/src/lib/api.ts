const API_BASE = '/api';

/**
 * El backend devuelve `{ error }` con el motivo en español en cada fallo. Sin
 * esto, un 400 se convertía en un objeto raro asignado al estado y la interfaz
 * mostraba "undefined" en lugar de "Publicar en 0.0.0.0 expone la base de
 * datos...". Los avisos de seguridad sólo sirven si llegan a verse.
 */
async function jsonOrThrow(res: Response, fallback: string) {
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && body.error) || fallback);
  return body;
}

// --- Bases de datos gestionadas ---

export interface DbEngine {
  engine: string;
  label: string;
  image: string;
  port: number;
  licence: string;
  requiresDatabaseName: boolean;
}

export interface DbExposure {
  enabled: boolean;
  bindAddress: string;
  hostPort: number | null;
}

export interface ManagedDatabase {
  id: string;
  projectId: string;
  engine: string;
  engineLabel: string;
  name: string;
  image: string;
  username: string;
  dbName: string | null;
  port: number;
  containerName: string;
  volumeName: string;
  networkName: string;
  memoryMb: number;
  cpus: number;
  exposure: DbExposure;
  status: string;
  health: 'healthy' | 'unhealthy' | 'starting' | 'unknown';
  createdAt: string;
  updatedAt: string;
  schedule: {
    enabled: boolean;
    cron: string;
    nextRunAt: string | null;
    lastRunAt: string | null;
    lastStatus: string | null;
  };
  retention: { daily: number; weekly: number };
  backupsCount: number;
  /** Cadena de conexión con la contraseña sustituida por asteriscos. */
  connectionTemplate: string;
  hasPassword: boolean;
}

export interface DbCredentials {
  id: string;
  username: string;
  password: string;
  dbName: string | null;
  host: string;
  port: number;
  internalConnectionString: string;
  hostConnectionString: string | null;
}

export interface DbBackup {
  id: string;
  fileName: string;
  sizeBytes: number;
  sha256: string;
  createdAt: string;
  trigger: string;
  durationMs: number;
  remote: { key: string; uploadedAt: string } | null;
  localAvailable: boolean;
  remoteAvailable: boolean;
}

export interface DbStorageConfig {
  configured: boolean;
  endpoint?: string;
  region?: string;
  bucket?: string;
  prefix?: string;
  pathStyle?: boolean;
  /** Siempre enmascarado por el backend. */
  accessKeyId?: string;
  secretAccessKey?: string;
}

export interface PodInfo {
  id: string;
  name: string;
  role: string;
  status: 'running' | 'idle' | 'hot_syncing' | 'deploying' | 'stopped' | 'not_provisioned';
  health: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  port: number;
  /** `provisioned: false` significa que no hay contenedor detrás del pod: las
   *  métricas de abajo llegan a null y hay que dibujar «—», no un número. */
  provisioned: boolean;
  note?: string;
  latencyMs: number | null;
  cpuPercent: number | null;
  memoryMb: number | null;
  memoryLimitMb: number | null;
  uptimeSeconds: number | null;
  hotReloadsCount: number;
  lastHotReloadMs: number | null;
  fileWatchersActive: number;
  localProcesses?: number;
  localPorts?: number[];
  version?: string;
  environment: string;
  gitCommit?: string;
}

/** Métricas del proceso del daemon. Estas sí se miden de verdad. */
export interface DaemonMetrics {
  cpuPercent: number | null;
  memoryMb: number;
  heapUsedMb: number;
  uptimeSeconds: number;
  measured: true;
}

export interface PodsData {
  pods: {
    forge: PodInfo;
    citadel: PodInfo;
  };
  trafficAllocation: {
    forge: number;
    citadel: number;
  };
  totalRequestsServed: number;
  activeConnections: number;
}

export interface DomainItem {
  id: string;
  hostname: string;
  isWildcard: boolean;
  targetPod: 'forge' | 'citadel';
  targetPort: number;
  status: string;
  cloudflareProxied: boolean;
  cloudflareZoneId: string | null;
  sslStatus: string;
  sslCertId: string | null;
  sslProvider: string | null;
  routingMode: string;
  createdAt: string;
  lastCheckedAt: string;
  migrationSource?: string;
  certInfo?: {
    issuer: string;
    expiresAt: string;
    daysRemaining: number;
    isWildcard: boolean;
  } | null;
}

export interface SslCertificate {
  id: string;
  domain: string;
  rootDomain: string;
  type: string;
  provider: string;
  issuer: string;
  sans: string[];
  status: string;
  issuedAt: string;
  expiresAt: string;
  autoRenew: boolean;
  fingerprint: string;
  keyType: string;
  daysRemaining: number;
  isExpiringSoon: boolean;
  isExpired: boolean;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'DEBUG' | 'WARN' | 'ERROR' | 'HOT_SYNC' | 'SUCCESS';
  pod: string;
  message: string;
}

export interface McpAuditEntry {
  id: string;
  timestamp: string;
  toolName: string;
  args: any;
  resultSummary: string;
  success: boolean;
  durationMs: number;
  agent: string;
}

export interface GitHubUser {
  login: string;
  id: number;
  name: string;
  avatar_url: string;
  html_url: string;
  bio: string;
  public_repos: number;
  total_private_repos: number;
  followers: number;
  following: number;
}

export interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  owner: {
    login: string;
    avatar_url: string;
  };
  description: string;
  private: boolean;
  html_url: string;
  clone_url: string;
  default_branch: string;
  language: string;
  stars: number;
  forks: number;
  updated_at: string;
}

export interface GitHubBranch {
  name: string;
  commitSha: string;
  protected?: boolean;
}

export interface GitHubStatus {
  connected: boolean;
  user: GitHubUser | null;
  tokenMasked: string | null;
  connectedAt: string | null;
}

export interface GitHubAutoDetectResult {
  detected: boolean;
  framework: string;
  language: string;
  buildCommand: string;
  startCommand: string;
  port: number;
  icon: string;
  baseDirectory: string;
  watchPaths: string[];
  envVars?: Record<string, string>;
  confidence: string;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  icon: string;
  status: 'active' | 'hibernated' | 'stopped';
  forgePort: number;
  citadelPort: number;
  trafficSplit: { forge: number; citadel: number };
  domains: string[];
  envVars: Record<string, string>;
  gitRepo: string;
  createdAt: string;
  updatedAt: string;
  source: string;
  resources?: any[];
  gitBranch?: string;
  buildCommand?: string;
  startCommand?: string;
  baseDirectory?: string;
  watchPaths?: string[];
  volumes?: any[];
  fileMounts?: any[];
  webhookSecret?: string;
  autoDeploy?: boolean;
  lastDeployedAt?: string | null;
  lastCommit?: {
    sha: string;
    message: string;
    author: string;
    timestamp: string;
  } | null;
  githubOwner?: string;
  githubRepo?: string;
  localRunning?: boolean;
  localPort?: number;
}

export const api = {
  async getProjects(): Promise<Project[]> {
    const res = await fetch(`${API_BASE}/projects`);
    return res.json();
  },
  async getProject(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}`);
    return res.json();
  },
  async createProject(data: any): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    return res.json();
  },
  async updateProject(id: string, data: any): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    return res.json();
  },
  async deleteProject(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/projects/${id}`, { method: 'DELETE' });
    return res.json();
  },
  async activateProject(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}/activate`, { method: 'POST' });
    return res.json();
  },
  async hibernateProject(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}/hibernate`, { method: 'POST' });
    return res.json();
  },
  async startLocal(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}/start-local`, { method: 'POST' });
    return res.json();
  },
  async stopLocal(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}/stop-local`, { method: 'POST' });
    return res.json();
  },
  async stopProject(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}/stop`, { method: 'POST' });
    return res.json();
  },
  async previewCoolify(apiUrl: string, apiToken: string): Promise<any> {
    const res = await fetch(`${API_BASE}/import/coolify/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiUrl, apiToken })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error de conexión');
    return res.json();
  },
  async importCoolify(apiUrl: string, apiToken: string, selectedApps: string[], selectedDbs: string[], selectedServices: string[]): Promise<any> {
    const res = await fetch(`${API_BASE}/import/coolify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiUrl, apiToken, selectedApps, selectedDbs, selectedServices })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al importar');
    return res.json();
  },
  async migrateDomain(hostname: string, serverIp: string, autoCloudflare: boolean): Promise<any> {
    const res = await fetch(`${API_BASE}/import/coolify/migrate-domain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname, serverIp, autoCloudflare })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al migrar dominio');
    return res.json();
  },
  async migrateDomainsBatch(domains: string[], serverIp: string, autoCloudflare: boolean): Promise<any> {
    const res = await fetch(`${API_BASE}/import/coolify/migrate-domains-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains, serverIp, autoCloudflare })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al migrar dominios');
    return res.json();
  },
  async getServerIp(): Promise<{ ip: string | null }> {
    const res = await fetch(`${API_BASE}/server/ip`);
    if (!res.ok) return { ip: null };
    return res.json();
  },
  async getPods(): Promise<PodsData> {
    const res = await fetch(`${API_BASE}/pods`);
    return res.json();
  },

  async triggerHotSync(changedFile = 'src/app.ts'): Promise<{ success: boolean; syncDurationMs: number; reloadsTotal: number }> {
    const res = await fetch(`${API_BASE}/pods/hot-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ changedFile })
    });
    return res.json();
  },

  async switchTraffic(forgePercent: number, citadelPercent: number): Promise<any> {
    const res = await fetch(`${API_BASE}/pods/switch-traffic`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ forgePercent, citadelPercent })
    });
    return res.json();
  },

  async deployRelease(imageTag: string, description: string): Promise<any> {
    const res = await fetch(`${API_BASE}/pods/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ imageTag, description })
    });
    return res.json();
  },

  async getDomains(): Promise<{ domains: DomainItem[] }> {
    const res = await fetch(`${API_BASE}/domains`);
    return res.json();
  },

  async addDomain(payload: {
    hostname: string;
    targetPod: string;
    targetPort: number;
    cloudflareZoneId?: string | null;
    cloudflareProxied?: boolean;
    autoCreateDns?: boolean;
  }): Promise<DomainItem> {
    const res = await fetch(`${API_BASE}/domains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to add domain');
    }
    return res.json();
  },

  async updateDomain(id: string, updates: Partial<DomainItem>): Promise<DomainItem> {
    const res = await fetch(`${API_BASE}/domains/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to update domain');
    }
    return res.json();
  },

  async toggleDomainProxy(id: string): Promise<DomainItem> {
    const res = await fetch(`${API_BASE}/domains/${id}/toggle-proxy`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to toggle proxy');
    }
    return res.json();
  },

  async deleteDomain(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/domains/${id}`, { method: 'DELETE' });
    return res.json();
  },

  async verifyDns(hostname: string): Promise<any> {
    const res = await fetch(`${API_BASE}/domains/verify-dns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname })
    });
    return res.json();
  },

  async getWatcherStatus(): Promise<{ isWatching: boolean; directory: string | null; fileWatchersActive: number }> {
    const res = await fetch(`${API_BASE}/watcher/status`);
    return res.json();
  },

  async startWatcher(directory?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/watcher/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ directory })
    });
    return res.json();
  },

  async stopWatcher(): Promise<any> {
    const res = await fetch(`${API_BASE}/watcher/stop`, {
      method: 'POST'
    });
    return res.json();
  },

  async getIngressResolution(hostname: string): Promise<any> {
    const res = await fetch(`${API_BASE}/ingress/resolve?hostname=${encodeURIComponent(hostname)}`);
    return res.json();
  },

  async getCertificates(): Promise<{ certificates: SslCertificate[] }> {
    const res = await fetch(`${API_BASE}/ssl/certificates`);
    return res.json();
  },

  async issueWildcardSsl(domain: string, zoneId?: string, provider = 'lets_encrypt'): Promise<any> {
    const res = await fetch(`${API_BASE}/ssl/issue-wildcard`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, zoneId, provider })
    });
    return res.json();
  },

  async issueOnDemandSslip(ip = '127.0.0.1', service = 'sslip.io'): Promise<any> {
    const res = await fetch(`${API_BASE}/ssl/issue-ondemand-sslip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, service })
    });
    return res.json();
  },

  async getCloudflareConfig(): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/config`);
    return res.json();
  },

  async saveCloudflareConfig(payload: { apiToken?: string; accountId?: string; useMock?: boolean }): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async verifyCloudflareToken(apiToken?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/verify-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiToken })
    });
    return res.json();
  },

  async getCloudflareZones(): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/zones`);
    return res.json();
  },

  async getCloudflareRecords(zoneId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/zones/${zoneId}/dns-records`);
    return res.json();
  },

  async getCloudflareTunnels(): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/tunnels`);
    return res.json();
  },

  async createCloudflareTunnel(name: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cloudflare/tunnels`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    return res.json();
  },

  async getLogs(params: { pod?: string; level?: string; limit?: number; search?: string; projectId?: string } = {}): Promise<{ logs: LogEntry[] }> {
    const qs = new URLSearchParams();
    if (params.pod) qs.set('pod', params.pod);
    if (params.level) qs.set('level', params.level);
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.search) qs.set('search', params.search);
    if (params.projectId) qs.set('projectId', params.projectId);
    const res = await fetch(`${API_BASE}/logs?${qs.toString()}`);
    return res.json();
  },

  async getMcpTools(): Promise<{ tools: any[] }> {
    const res = await fetch(`${API_BASE}/mcp/tools`);
    return res.json();
  },

  async executeMcpTool(name: string, args: any = {}): Promise<any> {
    const res = await fetch(`${API_BASE}/mcp/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'tools/call',
        params: { name, arguments: args }
      })
    });
    return res.json();
  },

  async getMcpAudit(): Promise<{ auditLog: McpAuditEntry[] }> {
    const res = await fetch(`${API_BASE}/mcp/audit`);
    return res.json();
  },

  async getMcpConfig(): Promise<any> {
    const res = await fetch(`${API_BASE}/mcp/config`);
    return res.json();
  },

  async getSystemStatus(): Promise<any> {
    const res = await fetch(`${API_BASE}/system/status`);
    return res.json();
  },

  async getGitHubStatus(): Promise<GitHubStatus> {
    const res = await fetch(`${API_BASE}/github/status`);
    return res.json();
  },

  async connectGitHub(token: string): Promise<{ success: boolean; user: GitHubUser }> {
    const res = await fetch(`${API_BASE}/github/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al conectar con GitHub');
    }
    return res.json();
  },

  async disconnectGitHub(): Promise<{ success: boolean }> {
    const res = await fetch(`${API_BASE}/github/disconnect`, { method: 'POST' });
    return res.json();
  },

  async getGitHubRepos(params: { page?: number; perPage?: number; search?: string; sort?: string } = {}): Promise<{ repos: GitHubRepo[]; total: number; page: number; perPage: number }> {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.perPage) qs.set('perPage', String(params.perPage));
    if (params.search) qs.set('search', params.search);
    if (params.sort) qs.set('sort', params.sort);
    const res = await fetch(`${API_BASE}/github/repos?${qs.toString()}`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al obtener repositorios');
    }
    return res.json();
  },

  async getGitHubBranches(owner: string, repo: string): Promise<GitHubBranch[]> {
    const res = await fetch(`${API_BASE}/github/repos/${owner}/${repo}/branches`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al obtener ramas');
    }
    return res.json();
  },

  async autoDetectGitHub(owner: string, repo: string, branch = 'main'): Promise<GitHubAutoDetectResult> {
    const res = await fetch(`${API_BASE}/github/auto-detect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner, repo, branch })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al analizar repositorio');
    }
    return res.json();
  },

  // --- BASES DE DATOS GESTIONADAS ---

  async getDbEngines(): Promise<{ engines: DbEngine[] }> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/engines`), 'Error al leer el catálogo de motores');
  },

  async getDbDockerStatus(): Promise<{ available: boolean; reason: string | null }> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/status`), 'Error al consultar Docker');
  },

  async getDatabases(projectId?: string): Promise<{ databases: ManagedDatabase[] }> {
    const q = projectId ? `?projectId=${encodeURIComponent(projectId)}` : '';
    return jsonOrThrow(await fetch(`${API_BASE}/databases${q}`), 'Error al listar bases de datos');
  },

  async createDatabase(data: Record<string, unknown>): Promise<ManagedDatabase & { connectionString: string }> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
      }),
      'Error al aprovisionar la base de datos'
    );
  },

  async deleteDatabase(id: string, opts: { deleteVolume?: boolean; deleteBackups?: boolean } = {}): Promise<any> {
    const q = new URLSearchParams();
    if (opts.deleteVolume) q.set('deleteVolume', 'true');
    if (opts.deleteBackups) q.set('deleteBackups', 'true');
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}?${q.toString()}`, { method: 'DELETE' }),
      'Error al eliminar la base de datos'
    );
  },

  /** Devuelve la contraseña en claro. Sólo a petición explícita del usuario. */
  async getDatabaseCredentials(id: string): Promise<DbCredentials> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/${id}/credentials`), 'Error al leer las credenciales');
  },

  async refreshDatabaseHealth(id: string): Promise<ManagedDatabase> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/${id}/health`), 'Error al comprobar el estado');
  },

  async controlDatabase(id: string, action: 'start' | 'stop' | 'restart'): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/${action}`, { method: 'POST' }),
      'Error al cambiar el estado de la base de datos'
    );
  },

  async setDatabaseExposure(
    id: string,
    body: { enabled: boolean; hostPort?: number; bindAddress?: string; acknowledgeRisk?: boolean }
  ): Promise<ManagedDatabase & { warning: string | null }> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/exposure`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al cambiar la exposición'
    );
  },

  async getDatabaseBackups(id: string): Promise<{ backups: DbBackup[] }> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/${id}/backups`), 'Error al listar las copias');
  },

  async runDatabaseBackup(id: string): Promise<{ success: boolean; backup: DbBackup }> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/backups`, { method: 'POST' }),
      'Error al ejecutar la copia'
    );
  },

  async restoreDatabase(id: string, body: { backupId?: string; remoteKey?: string }): Promise<any> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/restore`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al restaurar'
    );
  },

  async setDatabaseSchedule(id: string, body: { enabled: boolean; cron?: string }): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/schedule`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar la programación'
    );
  },

  async setDatabaseRetention(id: string, body: { daily: number; weekly: number }): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/${id}/retention`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar la retención'
    );
  },

  async getDbStorage(): Promise<DbStorageConfig> {
    return jsonOrThrow(await fetch(`${API_BASE}/databases/storage`), 'Error al leer el almacenamiento remoto');
  },

  async setDbStorage(body: Record<string, unknown> | null): Promise<DbStorageConfig> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/storage`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar el almacenamiento remoto'
    );
  },

  async testDbStorage(): Promise<{ success: boolean; endpoint: string; bucket: string }> {
    return jsonOrThrow(
      await fetch(`${API_BASE}/databases/storage/test`, { method: 'POST' }),
      'Error al probar el almacenamiento remoto'
    );
  }
};
