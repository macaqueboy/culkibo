const API_BASE = '/api';
const TOKEN_STORAGE_KEY = 'culkibo_control_token';

let _cachedToken: string | null | undefined;
let _unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  _unauthorizedHandler = handler;
}

export function getAuthToken(): string | null {
  if (_cachedToken !== undefined) return _cachedToken;
  try {
    _cachedToken = window.localStorage.getItem(TOKEN_STORAGE_KEY);
    return _cachedToken;
  } catch {
    _cachedToken = null;
    return null;
  }
}

export function setAuthToken(token: string): void {
  _cachedToken = token;
  try {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    // Entornos sin storage
  }
}

export function clearAuthToken(): void {
  _cachedToken = null;
  try {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Entornos sin storage
  }
}

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(init.headers || {});
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const res = await window.fetch(input, { ...init, headers });
  if (res.status === 401 && _unauthorizedHandler) {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!urlStr.includes('/auth/session') && !urlStr.includes('/auth/verify')) {
      clearAuthToken();
      _unauthorizedHandler();
    }
  }
  return res;
}

/**
 * El backend devuelve `{ error }` con el motivo en español en cada fallo. Sin
 * esto, un 400 se convertía en un objeto raro asignado al estado y la interfaz
 * mostraba "undefined" en lugar de "Publicar en 0.0.0.0 expone la base de
 * datos...". Los avisos de seguridad solo sirven si llegan a verse.
 */
async function jsonOrThrow(res: Response, fallback: string) {
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && (body.error || body.message)) || `${fallback} (HTTP ${res.status})`);
  return body;
}

export interface AuthSession {
  authenticated: boolean;
  method: string | null;
  requireTokenAlways: boolean;
  tokenConfigured: boolean;
  tokenSource: string;
}

export interface LiveSyncRecentFrame {
  seq: number;
  written: number;
  deleted: number;
  dedupSkipped: number;
  applyMs: number;
  mode: string;
  reason?: string;
  at: string;
  files?: Array<{ path: string; action: string; size?: number }>;
}

export interface LiveSyncClientInfo {
  id?: string;
  clientName?: string | null;
  sourceDir?: string | null;
  connectedAt?: string | null;
  lastFrameAt?: string | null;
}

export interface LiveSyncStatus {
  projectId: string;
  targetDir: string;
  connectedClients: number;
  clients?: LiveSyncClientInfo[];
  lastSeq: number;
  framesApplied: number;
  filesWritten: number;
  filesDeleted: number;
  dedupSkipped: number;
  bytesSynced: number;
  rollbacksCount: number;
  driftDetected: boolean;
  lastPath: string | null;
  lastReason: string | null;
  lastAppliedAt: string | null;
  lastApplyMs: number | null;
  historyDepth: number;
  recentFrames?: LiveSyncRecentFrame[];
  latencyMs: {
    samples: number;
    p50: number | null;
    p95: number | null;
    p99: number | null;
  };
}

export interface LiveSyncFrameDiff {
  projectId: string;
  seq: number;
  at?: string;
  mode?: string;
  reason?: string;
  files: Array<{
    path: string;
    action: string;
    previousSize?: number | null;
    currentSize?: number | null;
    diff?: string | null;
    binary?: boolean;
  }>;
}

export interface WordPressAnalysis {
  success: boolean;
  url: string;
  hostname: string;
  httpStatus: number;
  isWordPress: boolean;
  siteName: string;
  siteDescription: string;
  wpVersion: string | null;
  generator: string | null;
  restApiAvailable: boolean;
  theme: string | null;
  themes: string[];
  plugins: string[];
  hasWooCommerce: boolean;
  postTypes: string[];
  usesHttps: boolean;
  usesCloudflare: boolean;
  serverHeader: string | null;
  resolvedIps: string[];
  estimatedRamMb: number;
  suggestedSlug: string;
  migrationPlan: string[];
}

export interface ComposeParsedService {
  name: string;
  image: string;
  build: string;
  kind: 'app' | 'database';
  dbEngine: string | null;
  dbLabel: string | null;
  ports: string[];
  containerPort: number | null;
  volumes: string[];
  envVars: Record<string, string>;
  dependsOn: string[];
  warnings: string[];
}

export interface ComposeParseResult {
  success: boolean;
  servicesCount: number;
  appsCount: number;
  databasesCount: number;
  services: ComposeParsedService[];
}

export interface GitInspectResult {
  success: boolean;
  provider: string;
  host: string;
  owner: string;
  repo: string;
  suggestedName: string;
  cloneUrl: string;
  defaultBranch: string;
  description: string;
  language: string | null;
  isPrivate: boolean;
  framework: string | null;
  buildCommand: string;
  startCommand: string;
  port: number;
  icon: string;
  verifiedPublic: boolean;
}

export interface PlatformParseResult {
  success: boolean;
  platform: string;
  name: string;
  gitRepo: string;
  gitBranch: string;
  framework: string | null;
  buildCommand: string;
  startCommand: string;
  outputDirectory: string;
  baseDirectory: string;
  healthPath: string;
  port: number;
  domains: string[];
  envVars: Record<string, string>;
  recommendedDatabases: Array<{ engine: string; label: string; envKey: string }>;
  notes: string[];
}

export interface RemoteAccessInfo {
  panelDomain: string | null;
  currentOrigin: string;
  recommendedUrl: string;
  serverIp: string | null;
  auth: AuthSession & { allowedOrigins?: string[] };
  caddy: { available: boolean; adminUrl?: string; version?: string | null; reason?: string | null };
  cloudflare: { isConfigured: boolean; hasApiToken: boolean; accountId: string | null; tokenMasked?: string | null; useMock?: boolean };
  tunnels: Array<{ id: string; name: string; status?: string; created_at?: string }>;
  tunnelsMock: boolean;
  clientConfigs: any;
  cliUpdateCommand: string;
}

export interface NotificationsConfig {
  enabled: boolean;
  events: {
    service_down: boolean;
    service_failed?: boolean;
    deploy_started?: boolean;
    deploy_failed: boolean;
    deploy_succeeded: boolean;
    rollback?: boolean;
    production_unhealthy?: boolean;
    ssl_issued: boolean;
    tls_expiring?: boolean;
    backup_succeeded?: boolean;
    backup_failed?: boolean;
    disk_warning?: boolean;
    cron_failed?: boolean;
    project_stopped: boolean;
  };
  channels: {
    telegram: { enabled: boolean; botToken: string; chatId: string; configured?: boolean };
    discord: { enabled: boolean; webhookUrl: string; configured?: boolean };
    slack: { enabled: boolean; webhookUrl: string; configured?: boolean };
    webhook: { enabled: boolean; url: string; secretHeader?: string; hasSecretHeader?: boolean; configured?: boolean };
  };
}

export interface NotificationHistoryItem {
  id: string;
  at?: string;
  timestamp?: string;
  event: string;
  level: string;
  title: string;
  message: string;
  deliveredChannels?: string[];
  failedChannels?: Array<{ channel: string; error: string }>;
  skipped?: boolean;
}

export interface ServiceCategory {
  id: string;
  label: string;
  count: number;
}

export interface ServiceTemplate {
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
  summary: string;
  description: string;
  website: string;
  licence: string;
  tags: string[];
  image: string;
  port: number;
  memoryMb: number;
  cpus: string;
  totalMemoryMb: number;
  database: { engine: string; image: string | null } | null;
  sidecars: { name: string; image: string; memoryMb: number }[];
  secretNames: string[];
  nextSteps: string[];
  notes: string[];
  installedCount: number;
}

export interface ServiceInstallation {
  id: string;
  templateId: string;
  templateName: string;
  name: string;
  category: string;
  categoryLabel: string;
  image: string;
  domain: string | null;
  url: string;
  hostPort: number;
  appPort: number;
  containerName: string;
  networkName: string;
  sidecars: { name: string; image: string; containerName: string }[];
  databaseId: string | null;
  memoryMb: number;
  cpus: string;
  status: 'installing' | 'running' | 'degraded' | 'stopped' | 'error';
  health: string;
  progress: {
    step: string;
    label: string;
    stepIndex: number;
    totalSteps: number;
    message?: string | null;
    detail?: string | null;
    failed?: boolean;
  } | null;
  ingress: { applied: boolean; reason?: string | null } | null;
  lastProbe: Record<string, unknown> | null;
  lastError: string | null;
  secretNames: string[];
  nextSteps: string[];
  notes: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ServiceSecrets {
  id: string;
  name: string;
  secrets: Record<string, string>;
  database: DbCredentials | null;
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
  retention: { hourly?: number; daily: number; weekly: number };
  backupsCount: number;
  /** Cadena de conexión con la contraseña sustituida por asteriscos. */
  connectionTemplate: string;
  hasPassword: boolean;
}

export interface DbInspectResult {
  id: string;
  engine: string;
  reachable: boolean;
  latencyMs: number | null;
  version: string | null;
  databaseSizeBytes?: number | null;
  databaseSizeHuman?: string | null;
  volumeSizeBytes?: number | null;
  volumeSizeHuman?: string | null;
  volumeExists?: boolean;
  containerState?: { running?: boolean; status?: string; health?: string } | null;
  topTables?: Array<{ name: string; rows?: number | null; size?: string | null }>;
  keyCount?: number | null;
  error?: string | null;
}

export interface RemoteS3Object {
  key: string;
  size: number;
  lastModified: string;
  etag?: string;
}

export interface InstanceBackupItem {
  fileName: string;
  sizeBytes?: number;
  createdAt?: string;
  encrypted?: boolean;
  includesSecrets?: boolean;
  kind?: string;
}

export interface CronJobItem {
  id: string;
  projectId: string;
  name: string;
  schedule: string;
  command: string;
  enabled: boolean;
  timeoutSec: number;
  lastRunAt?: string | null;
  lastStatus?: string | null;
  nextRunAt?: string | null;
  createdAt: string;
  updatedAt?: string;
}

export interface CronRunItem {
  id: string;
  jobId?: string;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  status: string;
  exitCode: number | null;
  output?: string;
  trigger?: string;
}

export interface PreviewDeploymentItem {
  key: string;
  projectId: string;
  branch: string;
  prNumber: number | null;
  title?: string | null;
  commit?: string | null;
  hostname?: string | null;
  url: string | null;
  hostPort: number | null;
  containerName: string | null;
  status: string;
  error?: string | null;
  createdAt: string;
  updatedAt?: string;
}

export interface AuditLogEvent {
  id?: string;
  at?: string;
  timestamp?: string;
  source: string;
  action: string;
  target?: string | null;
  actor?: string | null;
  ip?: string | null;
  status?: string | null;
  meta?: Record<string, unknown>;
}

export interface TelemetryStatus {
  schemaVersion: number;
  enabled: boolean;
  persistedEnabled: boolean;
  lockedByEnv: boolean;
  reason: string;
  instanceId: string;
  endpoint: string;
  debug: boolean;
  queuedEvents: number;
  stats: {
    enqueued: number;
    sent: number;
    dropped: number;
    deduplicated: number;
    lastFlushAt: string | null;
    lastError: string | null;
  };
  circuitOpenUntil: string | null;
  collectedTypes: string[];
  neverCollected: string[];
}

export interface TelemetryPreview {
  schemaVersion: number;
  instanceId: string;
  appVersion: string;
  sentAt: string;
  endpoint: string;
  events: Array<Record<string, unknown>>;
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

export interface DomainWizardPreset {
  serviceId?: string;
  serviceName?: string;
  targetPort?: number;
  suggestedHostname?: string;
}

export interface IngressCapabilities {
  available: boolean;
  version: string | null;
  hasCloudflareDnsPlugin: boolean | null;
  hasCfTokenEnv: boolean;
  containerized: boolean;
  containerName: string;
  wildcardPolicies: Array<{
    rootDomain: string;
    subjects: string[];
    tokenEnv: string;
    includeApex: boolean;
    enabled?: boolean;
    addedAt?: string;
  }>;
  acmeEmail: string | null;
  cloudflareConfigured: boolean;
}

export interface DomainDiagnosisCheck {
  id: string;
  title: string;
  status: 'ok' | 'warn' | 'fail';
  detail: string;
}

export interface DomainDiagnosisReport {
  hostname: string;
  overall: 'ok' | 'warn' | 'fail';
  checks: DomainDiagnosisCheck[];
  dns?: any;
  tls?: TlsProbe;
  route?: IngressRoute | null;
  upstreamReachable?: boolean | null;
  capabilities?: Partial<IngressCapabilities>;
  checkedAt?: string;
}

export interface DomainItem {
  id: string;
  hostname: string;
  isWildcard: boolean;
  /** Proyecto dueño del dominio, o null si va directo a un pod. */
  projectId: string | null;
  serviceId?: string | null;
  serviceName?: string | null;
  targetPod: 'forge' | 'citadel' | 'service';
  targetPort: number;
  status: string;
  cloudflareProxied: boolean;
  cloudflareZoneId: string | null;
  sslStatus: string;
  sslCertId: string | null;
  sslProvider: string | null;
  routingMode: string;
  canonicalRedirect?: 'none' | 'www_to_apex' | 'apex_to_www';
  securityHeaders?: boolean;
  framePolicy?: 'SAMEORIGIN' | 'DENY' | 'ALLOW';
  customHeaders?: Record<string, string>;
  basicAuth?: {
    enabled: boolean;
    username?: string;
    password?: string;
    passwordHash?: string;
    realm?: string;
  } | null;
  ipAllowlist?: string[];
  maxBodySizeMb?: number | null;
  rateLimit?: {
    enabled: boolean;
    requestsPerMinute?: number;
  } | null;
  createdAt: string;
  lastCheckedAt: string;
  migrationSource?: string;
  /**
   * Lo que el registro interno AFIRMA sobre el certificado. `verified: false`
   * siempre: no es una comprobación, es nuestra propia nota. Lo verificado sale
   * de `IngressStatus.tls`, que es un handshake TLS real.
   */
  certClaim?: {
    verified: false;
    /** `caddy_on_demand` cuando el TLS lo emite el plano de datos. */
    managedBy?: string | null;
    /** `null` en las entradas delegadas: nadie aquí conoce el emisor. */
    issuer: string | null;
    expiresAt: string | null;
    daysRemaining: number | null;
    isWildcard: boolean;
  } | null;
}

/** Resultado de un handshake TLS real contra un dominio. */
export interface TlsProbe {
  hostname: string;
  probed: string;
  wildcard: boolean;
  reachable: boolean;
  handshakeMs: number;
  error?: string;
  issuer?: string | null;
  issuerCN?: string | null;
  subject?: string | null;
  sans?: string[];
  notBefore?: string | null;
  notAfter?: string | null;
  daysRemaining?: number | null;
  expired?: boolean | null;
  trusted?: boolean;
  trustError?: string | null;
  protocol?: string | null;
  alpn?: string | null;
}

export interface IngressRoute {
  id: string;
  hosts: string[];
  upstreams: string[];
  weights: number[] | null;
}

export interface IngressStatus {
  dataPlane: 'caddy';
  available: boolean;
  adminUrl: string;
  version: string | null;
  reason: string | null;
  message: string;
  routesManaged: number;
  routesError: string | null;
  routes: IngressRoute[];
  desired: Array<{ id: string; kind: string; label?: string; hosts: string[]; upstreams: string[]; weights: number[] | null }>;
  skipped: Array<{ hostnames: string[]; projectId?: string; reason: string }>;
  drift: { missing: string[]; unexpected: string[]; modified?: string[] };
  inSync: boolean;
  lastReconcile: { at: string; applied: number; removed: number; skipped: number } | null;
  tlsProbed: boolean;
  tls: TlsProbe[];
  checkedAt: string;
}

/** Lo que devuelve cualquier acción que toque el plano de datos. */
export interface IngressOutcome {
  applied?: boolean;
  available?: boolean;
  action?: string;
  routeId?: string;
  hostnames?: string[];
  upstreams?: string[];
  reason?: string;
  message?: string;
  error?: string;
}

/**
 * Entrada del registro de certificados.
 *
 * Dos formas posibles, y ninguna admite datos inventados:
 *
 *  - `status: 'on_disk'` — hay un PEM en `data/certs/`. Emisor, caducidad,
 *    huella y SANs se leen del X.509 en cada consulta, no se almacenan.
 *  - `status: 'delegated'` — el certificado lo emite Caddy bajo demanda. No
 *    hay emisor ni caducidad que el servidor pueda afirmar: llegan `null`.
 *
 * Hasta v1.0.0 esto incluía certificados fabricados con caducidad inventada.
 * El dato verificado sigue estando en `IngressStatus.tls` (handshake real).
 */
export interface SslCertificate {
  id: string;
  domain: string;
  rootDomain: string;
  type: string;
  provider: string;
  issuer: string | null;
  subject?: string | null;
  sans: string[];
  status: 'on_disk' | 'delegated' | string;
  verified: boolean;
  managedBy?: string | null;
  issuedAt: string | null;
  expiresAt: string | null;
  autoRenew: boolean;
  fingerprint: string | null;
  keyType: string | null;
  daysRemaining: number | null;
  isExpiringSoon: boolean;
  isExpired: boolean;
  message?: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'DEBUG' | 'WARN' | 'ERROR' | 'HOT_SYNC' | 'SUCCESS';
  pod: string;
  projectId?: string;
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
  containerPort?: number;
  healthPath?: string;
  memoryMb?: number;
  cpus?: string | number;
  linkedDatabaseIds?: string[];
  maintenanceMode?: boolean;
  autoRollback?: boolean;
  localPath?: string | null;
  deployHookToken?: string | null;
  preDeployCommand?: string | null;
  postDeployCommand?: string | null;
  previewDeployments?: {
    enabled: boolean;
    baseDomain?: string | null;
    maxActive?: number;
    ttlHours?: number;
    allowForks?: boolean;
  } | null;
}

// --- Despliegue a producción ---

/**
 * Los estados los nombra el servidor en español y en el orden real del
 * proceso. Se tipan como unión cerrada más `string` para que un estado nuevo
 * del backend no rompa la compilación del panel.
 */
export type DeployStatus_ =
  | 'pendiente' | 'en_cola' | 'sincronizando' | 'construyendo' | 'arrancando'
  | 'verificando' | 'promocionando' | 'drenando' | 'activo' | 'fallido' | 'cancelado';

export interface DeployGitInfo {
  branch: string | null;
  commit: string | null;
  shortCommit: string | null;
  subject: string | null;
  author: string | null;
  committedAt?: string | null;
  action?: 'clonado' | 'actualizado' | 'sin-cambios' | 'omitido' | string;
  previousCommit?: string | null;
  discardedChanges?: number;
}

export interface DeployLogLine {
  at: string;
  level: string;
  message: string;
}

export interface Deployment {
  id: string;
  projectId: string;
  projectName: string;
  status: DeployStatus_ | string;
  kind?: 'rollback';
  trigger?: 'manual' | 'webhook' | string;
  imageTag: string;
  containerName: string;
  hostPort: number | null;
  containerPort: number | null;
  upstream: string | null;
  hostnames: string[];
  routeSwitched: boolean;
  git: DeployGitInfo | null;
  strategy: { builder: string; stack: string; containerPort: number; healthPath: string; reason: string } | null;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  error: string | null;
  /** Solo en el detalle; el listado manda `logLineCount`. */
  logLines?: DeployLogLine[];
  logLineCount?: number;
}

export interface DeployRelease {
  deploymentId: string;
  projectName: string;
  imageTag: string;
  containerName: string;
  hostPort: number;
  containerPort: number;
  upstream: string;
  healthPath: string;
  hostnames: string[];
  version: string;
  git: DeployGitInfo | null;
  promotedAt: string;
}

export interface DeployStatus {
  docker: { available: boolean; version: string | null; reason: string | null };
  current: DeployRelease | null;
  previous: DeployRelease | null;
  canRollback: boolean;
  containerState: { status: string; health: string } | null;
  inProgress: boolean;
  queued: boolean;
  lastDeployment: Deployment | null;
}

export interface DeployStrategyPreview {
  available: boolean;
  reason?: string;
  contextDir: string;
  docker?: { available: boolean; version: string | null; reason: string | null };
  hostnames?: string[];
  strategy?: { builder: string; stack: string; containerPort: number; healthPath: string; reason: string };
  generatedDockerfile?: string | null;
}

/** Evento de fase que llega por WebSocket (`deploy_event`). */
export interface DeployEvent {
  deploymentId: string;
  projectId: string;
  status: string;
  kind?: string;
  imageTag: string | null;
  upstream: string | null;
  hostnames: string[];
  commit: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  error: string | null;
}

/** Línea de build que llega por WebSocket (`deploy_log`). */
export interface DeployLogEvent {
  deploymentId: string;
  projectId: string;
  at: string;
  level: string;
  message: string;
}

export interface ObservabilityHistoryPoint {
  ts: number;
  rps: number;
  p50Ms: number;
  p95Ms: number;
  rssMb: number;
  heapMb: number;
  elLagMs: number;
  cpuPercent: number;
}

export interface ObservabilitySnapshot {
  timestamp: string;
  uptimeSeconds: number;
  bootMs: number | null;
  process: {
    pid: number;
    nodeVersion: string;
    platform: string;
    arch: string;
    uptimeSeconds: number;
    cpuPercent: number | null;
    memoryMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
    hostMemoryTotalMb: number;
    hostMemoryUsedMb: number;
    hostMemoryFreeMb?: number;
    hostCpus: number;
    loadAvg: number[];
    measured: boolean;
  };
  eventLoop: {
    resolutionMs: number;
    samples: number;
    p50Ms: number | null;
    p95Ms: number | null;
    p99Ms: number | null;
    maxMs: number | null;
    utilizationRatio: number | null;
  };
  http: {
    requestsTotal: number;
    inFlight: number;
    rps: {
      rps1s: number;
      rps10s: number;
      rps60s: number;
    };
    status: {
      '2xx': number;
      '3xx': number;
      '4xx': number;
      '5xx': number;
    };
    methods: Record<string, number>;
    latencyMs: {
      samples: number;
      min: number | null;
      mean: number | null;
      p50: number | null;
      p95: number | null;
      p99: number | null;
      max: number | null;
    };
    topRoutes: Array<{ route: string; count: number; errors: number; avgMs: number; maxMs?: number }>;
  };
  websocket: {
    telemetryClients: number;
    syncClients: number;
    sseClients: number;
    connectionsTotal: number;
    broadcastsTotal: number;
  };
  liveSync: {
    loaded: boolean;
    activeSessions: number;
    connectedClients: number;
    framesApplied: number;
    filesWritten: number;
    dedupSkipped: number;
    bytesSynced: number;
    rollbacksCount: number;
    applyLatencyMs: { samples: number; p50: number | null; p95: number | null; p99: number | null };
  };
  caddy: {
    available: boolean | null;
    version: string | null;
    managedRoutes: number | null;
    swapsTotal: number;
    noopSkips: number;
    swapLatencyMs: { samples: number; p50: number | null; p95: number | null; p99: number | null; max?: number | null };
  };
  history: ObservabilityHistoryPoint[];
}

export interface DoctorCheck {
  id: string;
  name: string;
  status: 'ok' | 'warn' | 'fail';
  summary: string;
  detail: string;
  fixAction: string | null;
  fixLabel: string | null;
}

export interface SystemDoctorReport {
  overall: 'ok' | 'warn' | 'fail';
  durationMs: number;
  timestamp: string;
  summary: { ok: number; warn: number; fail: number };
  checks: DoctorCheck[];
}

export const api = {
  async getProjects(): Promise<Project[]> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/projects`), 'No se pudieron cargar los proyectos');
  },
  async getProject(id: string): Promise<Project> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/projects/${id}`), 'No se pudo cargar el proyecto');
  },
  async createProject(data: any): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
      'No se pudo crear el proyecto'
    );
  },
  async updateProject(id: string, data: any): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
      'No se pudo actualizar el proyecto'
    );
  },
  async deleteProject(id: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}`, { method: 'DELETE' }),
      'No se pudo eliminar el proyecto'
    );
  },
  async activateProject(id: string): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/activate`, { method: 'POST' }),
      'No se pudo activar el proyecto'
    );
  },
  async hibernateProject(id: string): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/hibernate`, { method: 'POST' }),
      'No se pudo hibernar el proyecto'
    );
  },
  async startLocal(id: string): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/start-local`, { method: 'POST' }),
      'No se pudo iniciar la vista previa local'
    );
  },
  async stopLocal(id: string): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/stop-local`, { method: 'POST' }),
      'No se pudo detener la vista previa local'
    );
  },
  async stopProject(id: string): Promise<Project> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/stop`, { method: 'POST' }),
      'No se pudo detener el proyecto'
    );
  },
  async testProjectWebhook(id: string): Promise<{ success: boolean; message?: string; delivery?: any }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${id}/webhook/test`, { method: 'POST' }),
      'No se pudo probar el webhook del proyecto'
    );
  },
  async previewCoolify(apiUrl: string, apiToken: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/import/coolify/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiUrl, apiToken })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error de conexión');
    return res.json();
  },
  async importCoolify(apiUrl: string, apiToken: string, selectedApps: string[], selectedDbs: string[], selectedServices: string[]): Promise<any> {
    const res = await apiFetch(`${API_BASE}/import/coolify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiUrl, apiToken, selectedApps, selectedDbs, selectedServices })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al importar');
    return res.json();
  },
  async migrateDomain(hostname: string, serverIp: string, autoCloudflare: boolean): Promise<any> {
    const res = await apiFetch(`${API_BASE}/import/coolify/migrate-domain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname, serverIp, autoCloudflare })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al migrar dominio');
    return res.json();
  },
  async migrateDomainsBatch(domains: string[], serverIp: string, autoCloudflare: boolean): Promise<any> {
    const res = await apiFetch(`${API_BASE}/import/coolify/migrate-domains-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains, serverIp, autoCloudflare })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error al migrar dominios');
    return res.json();
  },
  async getServerIp(): Promise<{ ip: string | null }> {
    const res = await apiFetch(`${API_BASE}/server/ip`);
    if (!res.ok) return { ip: null };
    return res.json();
  },
  async getPods(): Promise<PodsData> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/pods`), 'No se pudo consultar el estado de los pods');
  },

  async triggerHotSync(changedFile = 'src/app.ts'): Promise<{ success: boolean; syncDurationMs: number; reloadsTotal: number }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/pods/hot-sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ changedFile })
      }),
      'No se pudo ejecutar la sincronización'
    );
  },

  async switchTraffic(forgePercent: number, citadelPercent: number): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/pods/switch-traffic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ forgePercent, citadelPercent })
      }),
      'No se pudo cambiar el tráfico'
    );
  },

  async deployRelease(imageTag: string, description: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/pods/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageTag, description })
      }),
      'No se pudo desplegar la versión'
    );
  },

  async getDomains(): Promise<{ domains: DomainItem[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/domains`), 'No se pudieron cargar los dominios');
  },

  async addDomain(payload: {
    hostname: string;
    targetPod: string;
    targetPort: number;
    projectId?: string | null;
    serviceId?: string | null;
    serviceName?: string | null;
    cloudflareZoneId?: string | null;
    cloudflareProxied?: boolean;
    autoCreateDns?: boolean;
    serverIp?: string | null;
    canonicalRedirect?: 'none' | 'www_to_apex' | 'apex_to_www';
    securityHeaders?: boolean;
    framePolicy?: 'SAMEORIGIN' | 'DENY' | 'ALLOW';
    customHeaders?: Record<string, string>;
    basicAuth?: { enabled: boolean; username?: string; password?: string; realm?: string } | null;
    ipAllowlist?: string[];
    maxBodySizeMb?: number | null;
    rateLimit?: { enabled: boolean; requestsPerMinute?: number } | null;
  }): Promise<DomainItem & { ingress?: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo añadir el dominio'
    );
  },

  async updateDomain(id: string, updates: Partial<DomainItem>): Promise<DomainItem & { ingress?: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      }),
      'No se pudo actualizar el dominio'
    );
  },

  async toggleDomainProxy(id: string): Promise<DomainItem> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains/${id}/toggle-proxy`, { method: 'POST' }),
      'No se pudo cambiar el estado del proxy'
    );
  },

  async deleteDomain(id: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains/${id}`, { method: 'DELETE' }),
      'No se pudo eliminar el dominio'
    );
  },

  async verifyDns(hostname: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains/verify-dns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname })
      }),
      'No se pudo comprobar el DNS'
    );
  },

  async getWatcherStatus(): Promise<{ isWatching: boolean; directory: string | null; fileWatchersActive: number }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/watcher/status`), 'No se pudo consultar el observador');
  },

  async startWatcher(directory?: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/watcher/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ directory })
      }),
      'No se pudo iniciar el observador'
    );
  },

  async stopWatcher(): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/watcher/stop`, { method: 'POST' }),
      'No se pudo detener el observador'
    );
  },

  async getIngressResolution(hostname: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/resolve?hostname=${encodeURIComponent(hostname)}`),
      'No se pudo simular el enrutado'
    );
  },

  /** Estado real del plano de datos, con handshakes TLS de verdad. */
  async getIngressStatus(opts: { probe?: boolean; force?: boolean } = {}): Promise<IngressStatus> {
    const qs = new URLSearchParams();
    if (opts.probe === false) qs.set('probe', '0');
    if (opts.force) qs.set('force', '1');
    return jsonOrThrow(await apiFetch(`${API_BASE}/ingress/status?${qs.toString()}`), 'No se pudo consultar Caddy');
  },

  async reconcileIngress(): Promise<IngressOutcome> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/ingress/reconcile`, { method: 'POST' }), 'No se pudieron reconciliar las rutas');
  },

  async startIngress(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/ingress/start`, { method: 'POST' }), 'No se pudo iniciar Caddy');
  },

  /** Vincula un dominio a un proyecto: crea el registro Y publica la ruta. */
  async attachDomainToProject(projectId: string, payload: {
    hostname: string;
    targetPod?: string;
    targetPort?: number;
    cloudflareZoneId?: string | null;
    cloudflareProxied?: boolean;
    autoCreateDns?: boolean;
    serverIp?: string | null;
    canonicalRedirect?: 'none' | 'www_to_apex' | 'apex_to_www';
    securityHeaders?: boolean;
  }): Promise<{ domain: DomainItem; project: Project; ingress: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo vincular el dominio'
    );
  },

  /** Desvincula un dominio: borra el registro Y retira la ruta. */
  async detachDomainFromProject(projectId: string, domainId: string, keepDomain = false): Promise<any> {
    const qs = keepDomain ? '?keepDomain=1' : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/domains/${domainId}${qs}`, { method: 'DELETE' }),
      'No se pudo desvincular el dominio'
    );
  },

  async getCertificates(): Promise<{ certificates: SslCertificate[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/ssl/certificates`), 'No se pudieron cargar los certificados');
  },

  /**
   * @deprecated Responde 501: Culkibo no emite comodines. Se conserva porque el
   * endpoint sigue existiendo para clientes externos (CLI, agentes MCP) y tiene
   * que devolverles el error explicativo en vez de un 404.
   */
  async issueWildcardSsl(domain: string, zoneId?: string, provider = 'lets_encrypt'): Promise<any> {
    const res = await apiFetch(`${API_BASE}/ssl/issue-wildcard`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, zoneId, provider })
    });
    return res.json();
  },

  async issueOnDemandSslip(ip = '127.0.0.1', service = 'sslip.io'): Promise<any> {
    const res = await apiFetch(`${API_BASE}/ssl/issue-ondemand-sslip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, service })
    });
    return res.json();
  },

  async getCloudflareConfig(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/cloudflare/config`), 'No se pudo leer la configuración de Cloudflare');
  },

  async saveCloudflareConfig(payload: { apiToken?: string; accountId?: string; useMock?: boolean }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo guardar la configuración de Cloudflare'
    );
  },

  async verifyCloudflareToken(apiToken?: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/cloudflare/verify-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiToken })
    });
    return res.json();
  },

  async getCloudflareZones(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/cloudflare/zones`), 'No se pudieron obtener las zonas de Cloudflare');
  },

  async getCloudflareRecords(zoneId: string): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/cloudflare/zones/${zoneId}/dns-records`), 'No se pudieron cargar los registros DNS');
  },

  async getCloudflareTunnels(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/cloudflare/tunnels`), 'No se pudieron listar los túneles');
  },

  async createCloudflareTunnel(name: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/tunnels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      }),
      'No se pudo crear el túnel'
    );
  },

  async getLogs(params: { pod?: string; level?: string; limit?: number; search?: string; projectId?: string } = {}): Promise<{ logs: LogEntry[] }> {
    const qs = new URLSearchParams();
    if (params.pod) qs.set('pod', params.pod);
    if (params.level) qs.set('level', params.level);
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.search) qs.set('search', params.search);
    if (params.projectId) qs.set('projectId', params.projectId);
    return jsonOrThrow(await apiFetch(`${API_BASE}/logs?${qs.toString()}`), 'No se pudieron cargar los registros');
  },

  async getMcpTools(): Promise<{ tools: any[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/mcp/tools`), 'No se pudieron cargar las herramientas MCP');
  },

  async executeMcpTool(name: string, args: any = {}): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/mcp/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: { name, arguments: args }
        })
      }),
      'Error al ejecutar la herramienta MCP'
    );
  },

  async getMcpAudit(): Promise<{ auditLog: McpAuditEntry[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/mcp/audit`), 'No se pudo cargar la auditoría MCP');
  },

  async getMcpConfig(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/mcp/config`), 'No se pudo cargar la configuración MCP');
  },

  async getSystemStatus(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/system/status`), 'No se pudo consultar el estado del sistema');
  },

  async getGitHubStatus(): Promise<GitHubStatus> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/github/status`), 'No se pudo consultar el estado de GitHub');
  },

  async connectGitHub(token: string): Promise<{ success: boolean; user: GitHubUser }> {
    const res = await apiFetch(`${API_BASE}/github/connect`, {
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
    const res = await apiFetch(`${API_BASE}/github/disconnect`, { method: 'POST' });
    return res.json();
  },

  async getGitHubRepos(params: { page?: number; perPage?: number; search?: string; sort?: string } = {}): Promise<{ repos: GitHubRepo[]; total: number; page: number; perPage: number }> {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.perPage) qs.set('perPage', String(params.perPage));
    if (params.search) qs.set('search', params.search);
    if (params.sort) qs.set('sort', params.sort);
    const res = await apiFetch(`${API_BASE}/github/repos?${qs.toString()}`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al obtener repositorios');
    }
    return res.json();
  },

  async getGitHubBranches(owner: string, repo: string): Promise<GitHubBranch[]> {
    const res = await apiFetch(`${API_BASE}/github/repos/${owner}/${repo}/branches`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Error al obtener ramas');
    }
    return res.json();
  },

  async autoDetectGitHub(owner: string, repo: string, branch = 'main'): Promise<GitHubAutoDetectResult> {
    const res = await apiFetch(`${API_BASE}/github/auto-detect`, {
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
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/engines`), 'Error al leer el catálogo de motores');
  },

  async getDbDockerStatus(): Promise<{ available: boolean; reason: string | null }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/status`), 'Error al consultar Docker');
  },

  async getDatabases(projectId?: string): Promise<{ databases: ManagedDatabase[] }> {
    const q = projectId ? `?projectId=${encodeURIComponent(projectId)}` : '';
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases${q}`), 'Error al listar bases de datos');
  },

  async createDatabase(data: Record<string, unknown>): Promise<ManagedDatabase & { connectionString: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases`, {
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
      await apiFetch(`${API_BASE}/databases/${id}?${q.toString()}`, { method: 'DELETE' }),
      'Error al eliminar la base de datos'
    );
  },

  /** Devuelve la contraseña en claro. Sólo a petición explícita del usuario. */
  async getDatabaseCredentials(id: string): Promise<DbCredentials> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/${id}/credentials`), 'Error al leer las credenciales');
  },

  async refreshDatabaseHealth(id: string): Promise<ManagedDatabase> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/${id}/health`), 'Error al comprobar el estado');
  },

  async controlDatabase(id: string, action: 'start' | 'stop' | 'restart'): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/${action}`, { method: 'POST' }),
      'Error al cambiar el estado de la base de datos'
    );
  },

  async setDatabaseExposure(
    id: string,
    body: { enabled: boolean; hostPort?: number; bindAddress?: string; acknowledgeRisk?: boolean }
  ): Promise<ManagedDatabase & { warning: string | null }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/exposure`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al cambiar la exposición'
    );
  },

  async getDatabaseBackups(id: string): Promise<{ backups: DbBackup[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/${id}/backups`), 'Error al listar las copias');
  },

  async runDatabaseBackup(id: string): Promise<{ success: boolean; backup: DbBackup }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/backups`, { method: 'POST' }),
      'Error al ejecutar la copia'
    );
  },

  async restoreDatabase(id: string, body: { backupId?: string; remoteKey?: string; createSafetySnapshot?: boolean }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/restore`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al restaurar'
    );
  },

  async inspectDatabase(id: string): Promise<DbInspectResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/inspect`, { method: 'POST' }),
      'Error al inspeccionar la base de datos'
    );
  },

  async recoverDatabase(id: string): Promise<ManagedDatabase & { recovered?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/recover`, { method: 'POST' }),
      'Error al recrear el contenedor de la base de datos'
    );
  },

  async deleteDatabaseBackup(id: string, backupId: string, deleteRemote = false): Promise<any> {
    const qs = deleteRemote ? '?deleteRemote=1' : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/backups/${encodeURIComponent(backupId)}${qs}`, { method: 'DELETE' }),
      'Error al eliminar la copia de seguridad'
    );
  },

  async downloadDatabaseBackupBlob(id: string, backupId: string): Promise<{ blob: Blob; fileName: string }> {
    const res = await apiFetch(`${API_BASE}/databases/${id}/backups/${encodeURIComponent(backupId)}/download`);
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new Error((body && (body.error || body.message)) || `Error al descargar copia (HTTP ${res.status})`);
    }
    const cd = res.headers.get('Content-Disposition') || '';
    const match = cd.match(/filename="([^"]+)"/i);
    const fileName = match ? match[1] : `${backupId}.sql.gz`;
    return { blob: await res.blob(), fileName };
  },

  async uploadDatabaseBackup(
    id: string,
    file: File,
    opts: { restore?: boolean; safety?: boolean } = {}
  ): Promise<{ success: boolean; backup: DbBackup; restored?: any }> {
    const qs = new URLSearchParams();
    if (opts.restore) qs.set('restore', '1');
    if (opts.safety === false) qs.set('safety', '0');
    const qStr = qs.toString() ? `?${qs.toString()}` : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/backups/upload${qStr}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Backup-Filename': file.name,
        },
        body: file,
      }),
      'Error al subir la copia de seguridad'
    );
  },

  async setDatabaseSchedule(id: string, body: { enabled: boolean; cron?: string }): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/schedule`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar la programación'
    );
  },

  async setDatabaseRetention(id: string, body: { hourly?: number; daily: number; weekly: number }): Promise<ManagedDatabase> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${id}/retention`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar la retención'
    );
  },

  async listRemoteS3Objects(prefix?: string, maxKeys = 200): Promise<{ bucket?: string; prefix?: string; objects: RemoteS3Object[] }> {
    const qs = new URLSearchParams();
    if (prefix !== undefined) qs.set('prefix', prefix);
    qs.set('maxKeys', String(maxKeys));
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/storage/objects?${qs.toString()}`),
      'Error al listar objetos remotos en S3'
    );
  },

  async listInstanceBackups(): Promise<{ backups: InstanceBackupItem[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/backup/list`), 'Error al listar snapshots de instancia');
  },

  async exportInstanceSnapshot(body: { includeSecrets?: boolean; passphrase?: string; uploadToS3?: boolean } = {}): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/backup/instance/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'Error al exportar snapshot completo'
    );
  },

  async importInstanceSnapshot(body: {
    snapshot?: any;
    fileName?: string | null;
    passphrase?: string;
    dryRun?: boolean;
    mode?: 'merge' | 'overwrite';
  }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/backup/instance/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'Error al importar snapshot completo'
    );
  },

  async downloadInstanceSnapshotBlob(fileName: string): Promise<{ blob: Blob; fileName: string }> {
    const res = await apiFetch(`${API_BASE}/backup/download/${encodeURIComponent(fileName)}`);
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new Error((body && (body.error || body.message)) || `Error al descargar snapshot (HTTP ${res.status})`);
    }
    return { blob: await res.blob(), fileName };
  },

  async getDbStorage(): Promise<DbStorageConfig> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/databases/storage`), 'Error al leer el almacenamiento remoto');
  },

  async setDbStorage(body: Record<string, unknown> | null): Promise<DbStorageConfig> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/storage`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'Error al guardar el almacenamiento remoto'
    );
  },

  async testDbStorage(): Promise<{ success: boolean; endpoint: string; bucket: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/storage/test`, { method: 'POST' }),
      'Error al probar el almacenamiento remoto'
    );
  },

  // --- Despliegue a producción ---

  async getDeployStatus(projectId: string): Promise<DeployStatus> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/projects/${projectId}/deploy/status`), 'Error al leer el estado del despliegue');
  },

  async getDeployments(projectId: string, limit = 20): Promise<{ deployments: Deployment[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deployments?limit=${limit}`),
      'Error al leer el historial de despliegues'
    );
  },

  async getDeployment(projectId: string, deployId: string): Promise<Deployment> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deployments/${deployId}`),
      'Error al leer el despliegue'
    );
  },

  async getDeployStrategy(projectId: string): Promise<DeployStrategyPreview> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy/strategy`),
      'Error al analizar el proyecto'
    );
  },

  /** Responde 202 en cuanto arranca: el progreso llega por WebSocket. */
  async startDeploy(projectId: string, body: { commit?: string } = {}): Promise<{ accepted: boolean; message: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }),
      'No se pudo iniciar el despliegue'
    );
  },

  async rollbackDeploy(projectId: string, body: { targetDeploymentId?: string } = {}): Promise<Deployment> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo revertir'
    );
  },

  async cancelDeploy(projectId: string): Promise<{ cancelled: boolean; reason?: string; deploymentId?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy/cancel`, { method: 'POST' }),
      'No se pudo cancelar el despliegue'
    );
  },

  async getRuntimeLogs(projectId: string, opts: { tail?: number; target?: 'current' | 'previous' } = {}): Promise<{ ok: boolean; containerName?: string; output?: string; lines?: string[]; error?: string }> {
    const qs = new URLSearchParams();
    if (opts.tail) qs.set('tail', String(opts.tail));
    if (opts.target) qs.set('target', opts.target);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/runtime/logs?${qs.toString()}`),
      'No se pudieron leer los registros del contenedor'
    );
  },

  async getRuntimeStats(projectId: string): Promise<{ ok: boolean; containerName?: string; cpuPercent?: number | null; memoryUsage?: string; memoryPercent?: number | null; netIO?: string; blockIO?: string; pids?: string; status?: string; health?: string; error?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/runtime/stats`),
      'No se pudieron leer las estadísticas del contenedor'
    );
  },

  async execRuntimeCommand(projectId: string, body: { command: string; workdir?: string; timeoutMs?: number }): Promise<{ ok: boolean; exitCode: number; stdout: string; stderr: string; durationMs: number }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/runtime/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo ejecutar el comando en el contenedor'
    );
  },

  async getProjectCrons(projectId: string): Promise<{ jobs: CronJobItem[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons`),
      'No se pudieron cargar las tareas programadas'
    );
  },

  async createProjectCron(projectId: string, body: { name: string; schedule: string; command: string; enabled?: boolean; timeoutSec?: number }): Promise<CronJobItem> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo crear la tarea cron'
    );
  },

  async updateProjectCron(projectId: string, jobId: string, body: Partial<CronJobItem>): Promise<CronJobItem> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons/${encodeURIComponent(jobId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo actualizar la tarea cron'
    );
  },

  async deleteProjectCron(projectId: string, jobId: string): Promise<{ deleted: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons/${encodeURIComponent(jobId)}`, { method: 'DELETE' }),
      'No se pudo eliminar la tarea cron'
    );
  },

  async runProjectCron(projectId: string, jobId: string): Promise<{ run: CronRunItem }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons/${encodeURIComponent(jobId)}/run`, { method: 'POST' }),
      'No se pudo ejecutar la tarea cron'
    );
  },

  async getProjectCronRuns(projectId: string, jobId: string): Promise<{ runs: CronRunItem[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/crons/${encodeURIComponent(jobId)}/runs`),
      'No se pudo leer el historial de la tarea cron'
    );
  },

  async getProjectPreviews(projectId: string): Promise<{ config: any; previews: PreviewDeploymentItem[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/previews`),
      'No se pudieron cargar las vistas previas'
    );
  },

  async deployProjectPreview(projectId: string, body: { branch?: string; prNumber?: number | null; commit?: string | null; title?: string | null }): Promise<PreviewDeploymentItem> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/previews`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo desplegar la vista previa'
    );
  },

  async destroyProjectPreview(projectId: string, key: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/previews/${encodeURIComponent(key)}`, { method: 'DELETE' }),
      'No se pudo eliminar la vista previa'
    );
  },

  async getProjectPreviewLogs(projectId: string, key: string, tail = 150): Promise<{ output: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/previews/${encodeURIComponent(key)}/logs?tail=${tail}`),
      'No se pudieron leer los registros de la vista previa'
    );
  },

  async rotateDeployHook(projectId: string): Promise<{ projectId: string; deployHookToken: string; hookUrl: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy-hook/rotate`, { method: 'POST' }),
      'No se pudo rotar el token del Deploy Hook'
    );
  },

  async stopDeploy(projectId: string): Promise<{ stopped: boolean; reason?: string; error?: string | null }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy/stop`, { method: 'POST' }),
      'No se pudo detener el servicio'
    );
  },

  async resumeDeploy(projectId: string): Promise<{ started: boolean; reason?: string; error?: string | null }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/deploy/start`, { method: 'POST' }),
      'No se pudo reanudar el servicio'
    );
  },

  // --- Catálogo de servicios de un clic ---

  async getCatalog(): Promise<{ templates: ServiceTemplate[]; categories: ServiceCategory[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/catalog`), 'No se pudo cargar el catálogo');
  },

  async getInstallations(): Promise<{ installations: ServiceInstallation[] }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/catalog/installations`), 'No se pudieron cargar los servicios instalados');
  },

  async installService(body: { templateId: string; name?: string; domain?: string | null }): Promise<ServiceInstallation> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/install`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      }),
      'No se pudo iniciar la instalación'
    );
  },

  async getInstallationSecrets(id: string): Promise<ServiceSecrets> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/secrets`),
      'No se pudieron obtener las credenciales'
    );
  },

  async getInstallationLogs(id: string, lines = 300, role?: string): Promise<{ output: string; roles?: string[]; role?: string }> {
    const qs = new URLSearchParams({ lines: String(lines) });
    if (role) qs.set('role', role);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/logs?${qs.toString()}`),
      'No se pudieron leer los registros'
    );
  },

  async getInstallationEnv(id: string): Promise<{ id: string; env: Record<string, string>; overrides: Record<string, string>; secretKeys?: string[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/env`),
      'No se pudieron leer las variables del servicio'
    );
  },

  async updateInstallationEnv(id: string, env: Record<string, string>): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/env`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ env }),
      }),
      'No se pudieron actualizar las variables del servicio'
    );
  },

  async getInstallationStats(id: string): Promise<{ id: string; containers: Array<{ role: string; containerName: string; cpuPercent: number | null; memoryUsage: string; memoryPercent: number | null; netIO?: string; pids?: string; status?: string }> }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/stats`),
      'No se pudieron leer las estadísticas del servicio'
    );
  },

  async updateInstallationImage(id: string, image: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image }),
      }),
      'No se pudo actualizar la imagen del servicio'
    );
  },

  async controlInstallation(id: string, action: 'start' | 'stop' | 'restart'): Promise<ServiceInstallation> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/${action}`, { method: 'POST' }),
      'No se pudo cambiar el estado del servicio'
    );
  },

  async refreshInstallationHealth(id: string): Promise<ServiceInstallation> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/health`, { method: 'POST' }),
      'No se pudo comprobar la salud del servicio'
    );
  },

  async removeInstallation(id: string, deleteVolumes = false): Promise<{ removed: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}?deleteVolumes=${deleteVolumes ? '1' : '0'}`, {
        method: 'DELETE'
      }),
      'No se pudo desinstalar el servicio'
    );
  },

  async attachCatalogDomain(id: string, domain: string): Promise<{ installation: ServiceInstallation; ingress: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/catalog/installations/${id}/domain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      }),
      'No se pudo conectar el dominio al servicio'
    );
  },

  // --- Autenticación del plano de control ---

  async getAuthSession(): Promise<AuthSession> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/auth/session`), 'No se pudo verificar la sesión');
  },

  async verifyAuthToken(token: string): Promise<{ valid: boolean }> {
    return jsonOrThrow(
      await window.fetch(`${API_BASE}/auth/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ token })
      }),
      'Token inválido'
    );
  },

  async getWsTicket(): Promise<{ ticket: string; expiresInMs: number }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/ws-ticket`, { method: 'POST' }),
      'No se pudo generar un ticket de conexión en tiempo real'
    );
  },

  async rotateAuthToken(): Promise<{ rotated: boolean; token: string; message?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/rotate`, { method: 'POST' }),
      'No se pudo rotar el token de acceso'
    );
  },

  // --- Observabilidad y Diagnóstico (Doctor) ---

  async getObservabilitySnapshot(fresh = false): Promise<ObservabilitySnapshot> {
    const qs = fresh ? '?fresh=1' : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/snapshot${qs}`),
      'No se pudieron obtener las métricas del servidor'
    );
  },

  async getSystemDoctor(): Promise<SystemDoctorReport> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/doctor`),
      'No se pudo ejecutar el diagnóstico del sistema'
    );
  },

  async runDoctorFix(action: string): Promise<{ ok: boolean; action: string; message: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/doctor/fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      }),
      'No se pudo aplicar la corrección'
    );
  },

  // --- Live Sync (The Forge) ---

  async getSyncStatus(projectId: string): Promise<LiveSyncStatus> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/projects/${projectId}/sync/status`), 'No se pudo consultar el estado de sincronización');
  },

  async verifyProjectSync(projectId: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/sync/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      }),
      'No se pudo verificar el árbol Merkle'
    );
  },

  async rollbackProjectSync(projectId: string, steps = 1): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/sync/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ steps })
      }),
      'No se pudo revertir el último parche'
    );
  },

  async promoteForge(projectId: string, opts: { async?: boolean } = {}): Promise<any> {
    const qs = opts.async ? '?async=1' : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/sync/promote${qs}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts.async ? { async: true } : {}),
      }),
      'No se pudo promocionar el espacio de trabajo a producción'
    );
  },

  async getSyncFrameDiff(projectId: string, seq: number): Promise<LiveSyncFrameDiff> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/sync/frames/${seq}/diff`),
      'No se pudo cargar el diff del Commit Frame'
    );
  },

  async createSyncToken(projectId: string): Promise<{ projectId: string; ticket: string; expiresAt: string; wsUrl: string; command: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${projectId}/sync/token`, { method: 'POST' }),
      'No se pudo generar el token temporal de Live Sync'
    );
  },

  async runTlsAudit(opts: { warnDays?: number; probeLive?: boolean } = {}): Promise<{
    checkedAt: string;
    warnDays: number;
    ok: any[];
    expiring: any[];
    expired: any[];
    errors: any[];
  }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/tls-audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts),
      }),
      'No se pudo ejecutar la auditoría de caducidad TLS'
    );
  },

  async getCloudflareTunnelToken(tunnelId: string): Promise<{ tunnelId: string; token: string; mock?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/tunnels/${encodeURIComponent(tunnelId)}/token`),
      'No se pudo obtener el token del túnel'
    );
  },

  async routeCloudflareTunnel(tunnelId: string, body: { hostname: string; serviceUrl: string; zoneId?: string | null }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/tunnels/${encodeURIComponent(tunnelId)}/route`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo conectar el dominio al túnel de Cloudflare'
    );
  },

  async deleteCloudflareTunnel(tunnelId: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/tunnels/${encodeURIComponent(tunnelId)}`, { method: 'DELETE' }),
      'No se pudo eliminar el túnel de Cloudflare'
    );
  },

  async startCloudflareTunnelConnector(body: { tunnelToken: string; containerName?: string }): Promise<{ started: boolean; containerName?: string; error?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cloudflare/tunnels/connector/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
      'No se pudo iniciar el conector cloudflared en Docker'
    );
  },

  async getSystemAudit(opts: { limit?: number; source?: string; action?: string } = {}): Promise<{ events: AuditLogEvent[] }> {
    const qs = new URLSearchParams();
    if (opts.limit) qs.set('limit', String(opts.limit));
    if (opts.source) qs.set('source', opts.source);
    if (opts.action) qs.set('action', opts.action);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/audit?${qs.toString()}`),
      'No se pudo leer el registro de auditoría'
    );
  },

  async getSystemHealthSummary(fresh = false): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/health-summary${fresh ? '?fresh=1' : ''}`),
      'No se pudo consultar el resumen de salud del sistema'
    );
  },

  async getNotificationsHistory(limit = 30): Promise<{ notifications: NotificationHistoryItem[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/notifications/history?limit=${limit}`),
      'No se pudo leer el historial de notificaciones'
    );
  },

  async uploadWordPressSql(
    file: File,
    opts: { installationId: string; oldDomain?: string; newDomain?: string }
  ): Promise<any> {
    const qs = new URLSearchParams({ installationId: opts.installationId });
    if (opts.oldDomain) qs.set('oldDomain', opts.oldDomain);
    if (opts.newDomain) qs.set('newDomain', opts.newDomain);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/wordpress/import-sql/upload?${qs.toString()}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Sql-Filename': file.name,
        },
        body: file,
      }),
      'No se pudo subir e importar el volcado SQL'
    );
  },

  async configureWildcardDns01(domain: string, tokenEnv = 'CF_API_TOKEN', includeApex = true): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/wildcard-dns01`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, tokenEnv, includeApex })
      }),
      'No se pudo configurar el certificado wildcard DNS-01 en Caddy'
    );
  },

  async listWildcardPolicies(): Promise<{ policies: Array<{ rootDomain: string; subjects: string[]; tokenEnv: string; includeApex: boolean; addedAt?: string }> }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/ingress/wildcard-dns01`), 'No se pudieron leer las políticas wildcard');
  },

  async removeWildcardPolicy(domain: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/wildcard-dns01/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
      'No se pudo eliminar la política wildcard'
    );
  },

  async getIngressCapabilities(force = false): Promise<IngressCapabilities> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/capabilities${force ? '?force=1' : ''}`),
      'No se pudieron comprobar las capacidades de Caddy'
    );
  },

  async setAcmeEmail(email: string | null): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/acme-email`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      }),
      'No se pudo actualizar el correo ACME'
    );
  },

  async diagnoseDomain(id: string): Promise<DomainDiagnosisReport> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/domains/${encodeURIComponent(id)}/diagnose`, { method: 'POST' }),
      'No se pudo ejecutar el diagnóstico del dominio'
    );
  },

  async uploadCustomCertificate(payload: { domain: string; certPem: string; keyPem: string; provider?: string }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ssl/certificates/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo subir el certificado SSL'
    );
  },

  async deleteCertificate(id: string): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ssl/certificates/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'No se pudo revocar el certificado SSL'
    );
  },

  async linkProjectDatabase(projectId: string, databaseId: string): Promise<{ success: boolean; project: Project; note?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(databaseId)}/link`, {
        method: 'POST'
      }),
      'No se pudo vincular la base de datos al proyecto'
    );
  },

  async unlinkProjectDatabase(projectId: string, databaseId: string): Promise<{ success: boolean; project: Project }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(databaseId)}/link`, {
        method: 'DELETE'
      }),
      'No se pudo desvincular la base de datos'
    );
  },

  async toggleMaintenance(projectId: string, enabled: boolean): Promise<{ success: boolean; maintenanceMode: boolean; project: Project; ingress?: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/maintenance`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      }),
      'No se pudo cambiar el modo mantenimiento'
    );
  },

  async getDeployQueue(): Promise<{
    maxConcurrentBuilds: number;
    activeBuilds: number;
    queuedBuilds: Array<{ position: number; projectId: string; deploymentId: string; waitingMs: number }>;
    inFlightProjects: string[];
  }> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/deploy/queue`), 'No se pudo consultar la cola de despliegues');
  },

  async getSyncSummary(): Promise<any> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/sync/summary`), 'No se pudo consultar el resumen de Live Sync');
  },

  // --- Migrador WordPress ---

  async analyzeWordPress(url: string): Promise<WordPressAnalysis> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/wordpress/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      }),
      'No se pudo analizar la web WordPress'
    );
  },

  async provisionWordPress(payload: {
    name: string;
    domain?: string | null;
    sourceUrl?: string | null;
    useSslip?: boolean;
    serverIp?: string | null;
  }): Promise<{ success: boolean; installation: ServiceInstallation; previewUrl: string; wpAdminUrl: string; migrationChecklist: string[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/wordpress/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo aprovisionar WordPress'
    );
  },

  async importWordPressSql(payload: {
    installationId: string;
    sqlContent: string;
    oldDomain?: string;
    newDomain?: string;
  }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/wordpress/import-sql`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo importar el volcado SQL'
    );
  },

  // --- Importador Universal (Docker Compose, cualquier Git, Vercel/Netlify/Railway/Render/Dokploy) ---

  async parseCompose(yamlText: string): Promise<ComposeParseResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/compose/parse`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yamlText })
      }),
      'No se pudo analizar el archivo docker-compose.yml'
    );
  },

  async applyCompose(payload: { yamlText: string; projectName?: string; selectedServices?: string[] }): Promise<{ success: boolean; project: Project; importedServices: number; databasesDetected: any[]; warnings: string[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/compose/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo importar el stack Docker Compose'
    );
  },

  async inspectGitUrl(gitUrl: string, branch?: string): Promise<GitInspectResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/git/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gitUrl, branch })
      }),
      'No se pudo inspeccionar la URL del repositorio Git'
    );
  },

  async parsePlatformConfig(payload: { platform?: string; configText?: string; envText?: string }): Promise<PlatformParseResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/platform/parse`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo leer la configuración de la plataforma'
    );
  },

  async createImportedProject(payload: {
    name: string;
    description?: string;
    icon?: string;
    platform?: string;
    source?: string;
    gitRepo?: string;
    gitBranch?: string;
    buildCommand?: string;
    startCommand?: string;
    baseDirectory?: string;
    healthPath?: string;
    port?: number;
    envVars?: Record<string, string>;
    domains?: string[];
  }): Promise<{ success: boolean; project: Project }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/universal/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo crear el proyecto importado'
    );
  },

  // --- Acceso remoto, Notificaciones, Mantenimiento y MCP moderno ---

  async getRemoteAccess(): Promise<RemoteAccessInfo> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/system/remote-access`), 'No se pudo consultar el acceso remoto');
  },

  async setPanelDomain(domain: string): Promise<{ success: boolean; panelDomain: string | null; url?: string; ingress?: IngressOutcome }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/panel-domain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      }),
      'No se pudo guardar el dominio del panel'
    );
  },

  async getNotificationsConfig(): Promise<NotificationsConfig> {
    return jsonOrThrow(await apiFetch(`${API_BASE}/notifications/config`), 'No se pudo leer la configuración de notificaciones');
  },

  async saveNotificationsConfig(payload: Partial<NotificationsConfig>): Promise<NotificationsConfig> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/notifications/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }),
      'No se pudo guardar la configuración de notificaciones'
    );
  },

  async testNotifications(): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/notifications/test`, { method: 'POST' }),
      'No se pudo enviar la alerta de prueba'
    );
  },

  async pruneBuildCache(opts: { keepStorageGb?: number; untilHours?: number | null } = {}): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/deploy/prune-cache`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts)
      }),
      'No se pudo limpiar la caché de compilación'
    );
  },

  // --- Telemetría anónima y diagnóstico ---

  async getTelemetryStatus(): Promise<TelemetryStatus> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/telemetry/status`),
      'No se pudo consultar el estado de la telemetría'
    );
  },

  async setTelemetryEnabled(enabled: boolean): Promise<TelemetryStatus> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/telemetry/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      }),
      'No se pudo actualizar la preferencia de telemetría'
    );
  },

  async getTelemetryPreview(): Promise<TelemetryPreview> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/telemetry/preview`),
      'No se pudo cargar la vista previa de telemetría'
    );
  },

  async resetTelemetryId(): Promise<TelemetryStatus> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/telemetry/reset-id`, { method: 'POST' }),
      'No se pudo rotar el identificador anónimo'
    );
  },

  async callMcpModern(toolName: string, args: Record<string, unknown> = {}): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': toolName
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: {
            name: toolName,
            arguments: args,
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
              'io.modelcontextprotocol/clientInfo': { name: 'culkibo-dashboard', version: '1.0.0' }
            }
          }
        })
      }),
      'Error al invocar la herramienta MCP'
    );
  }
};
