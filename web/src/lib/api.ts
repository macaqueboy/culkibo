import { isDemoMode, handleDemoFetch } from './demoMode';

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
  if (isDemoMode()) {
    return handleDemoFetch(input, init);
  }
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

export interface LiveSyncConflict {
  id: string;
  projectId: string;
  path: string;
  seq: number;
  previousSeq?: number;
  reason?: 'concurrent_window' | 'stale_base_hash' | string;
  deltaMs?: number;
  incoming?: {
    clientId?: string;
    clientName?: string | null;
    sha256?: string;
    op?: string;
  };
  previous?: {
    clientId?: string;
    clientName?: string | null;
    sha256?: string;
    at?: string;
  };
  detectedAt?: string;
  policy?: string;
  resolved?: boolean;
}

export interface LiveSyncFileRevision {
  seq: number;
  appliedAt?: string;
  action: 'initial' | 'created' | 'modified' | 'deleted' | 'rolled_back' | string;
  clientId?: string | null;
  clientName?: string | null;
  existed?: boolean;
  byteLength?: number;
  sha256?: string | null;
  restorable?: boolean;
  restoredFromSeq?: number | null;
}

export interface LiveSyncFileHistory {
  projectId: string;
  path: string;
  existsOnDisk?: boolean;
  currentSha256?: string | null;
  revisionCount: number;
  revisions: LiveSyncFileRevision[];
}

export interface LiveSyncWireStats {
  rawBytes: number;
  wireBytes: number;
  savedPct: number;
  compressedFrames?: number;
  codec?: string | null;
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
  wireBytesReceived?: number;
  rawBytesReceived?: number;
  compressionSavedBytes?: number;
  compressionRatio?: number;
  lastCompression?: string | null;
  wireStats?: LiveSyncWireStats;
  conflictsCount?: number;
  recentConflicts?: LiveSyncConflict[];
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
  catalogImage?: string;
  updateAvailable?: boolean;
  extraPorts?: Record<string, number>;
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
  seq?: number;
  at?: string;
  timestamp?: string;
  source: string;
  action: string;
  target?: string | null;
  path?: string | null;
  method?: string | null;
  actor?: string | {
    userId?: string | null;
    email?: string | null;
    role?: string | null;
    teamId?: string | null;
    kind?: string | null;
  } | null;
  ip?: string | null;
  status?: number | string | null;
  prevHash?: string | null;
  entryHash?: string | null;
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
  status: 'active' | 'hibernated' | 'stopped' | 'sleeping';
  serverId?: string;
  teamId?: string;
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

// --- Multi-Server Fleet (SSH Orchestration) ---

export interface FleetServerProbe {
  os?: string | null;
  arch?: string | null;
  cpus?: number | null;
  load1m?: number | null;
  memoryTotalMb?: number | null;
  memoryAvailableMb?: number | null;
  diskTotalGb?: number | null;
  diskAvailableGb?: number | null;
  dockerVersion?: string | null;
  dockerReady?: boolean;
  caddyAvailable?: boolean;
  caddyMode?: string | null;
  latencyMs?: number | null;
  probedAt?: string | null;
  warnings?: string[];
  error?: string | null;
}

export interface FleetServer {
  id: string;
  name: string;
  isLocal?: boolean;
  host: string;
  port: number;
  user: string;
  keyId?: string | null;
  dockerSocketPath?: string;
  region?: string;
  tags?: string[];
  teamId?: string;
  status: 'online' | 'degraded' | 'offline' | 'host_key_mismatch' | 'pending' | 'unknown' | string;
  statusReason?: string | null;
  statusFix?: string | null;
  warnings?: string[];
  hostKeyPolicy?: 'tofu' | 'strict';
  hostKeyFingerprint?: string | null;
  hostKeyType?: string | null;
  hostKeyPinnedAt?: string | null;
  lastProbedAt?: string | null;
  resources?: FleetServerProbe | null;
  probe?: FleetServerProbe | null;
  lastError?: string | null;
  projectsCount?: number;
  createdAt?: string;
  updatedAt?: string;
}

export interface FleetSshKey {
  id: string;
  name: string;
  fingerprint: string;
  publicKey: string;
  keyType?: string;
  algorithm?: string;
  teamId?: string;
  serversUsing?: number;
  createdAt?: string;
}

// --- Teams, RBAC y Tokens con alcance ---

export type RbacRole = 'owner' | 'admin' | 'developer' | 'viewer';

export interface RbacIdentity {
  authenticated: boolean;
  method?: string | null;
  authKind?: string | null;
  multiUserEnabled?: boolean;
  isSuperAdmin?: boolean;
  userId?: string | null;
  email?: string | null;
  name?: string | null;
  role: RbacRole;
  teamId?: string | null;
  projectIds?: string[] | '*' | null;
  scopes?: string[];
}

export interface TeamSummary {
  id: string;
  slug?: string;
  name: string;
  isDefault?: boolean;
  memberCount?: number;
  role?: RbacRole;
  createdAt?: string;
}

export interface TeamMember {
  id: string;
  userId?: string;
  email: string;
  name?: string;
  role: RbacRole;
  status?: 'active' | 'disabled' | string;
  projectIds?: string[] | '*' | null;
  addedAt?: string;
  lastLoginAt?: string | null;
}

export interface TeamInvite {
  id: string;
  teamId: string;
  email: string;
  role: RbacRole;
  tokenPrefix?: string;
  projectIds?: string[] | null;
  createdAt?: string;
  expiresAt: string;
  usedAt?: string | null;
  revokedAt?: string | null;
}

export interface ScopedApiToken {
  id: string;
  name: string;
  tokenPrefix: string;
  role?: RbacRole;
  teamId?: string;
  scopes: string[];
  projectIds: string[] | '*' | null;
  createdAt?: string;
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  lastUsedIp?: string | null;
  revokedAt?: string | null;
}

// --- Entornos, Shared Vault y GitOps culkibo.yaml ---

export interface VaultSecretMeta {
  key: string;
  fingerprint?: string;
  hash?: string;
  scope?: 'runtime' | 'build' | 'both' | string;
  secret?: boolean;
  updatedAt?: string;
  createdAt?: string;
}

export interface ProjectEnvironmentItem {
  name: string;
  branch?: string | null;
  domains?: string[];
  serverId?: string | null;
  envKeys?: string[];
  envCount?: number;
  envVars?: Record<string, string>;
  lastRelease?: {
    version?: string;
    imageTag?: string;
    promotedAt?: string;
  } | null;
  promotionHistory?: Array<{
    id?: string;
    fromEnv: string;
    toEnv: string;
    at: string;
    actor?: string | null;
  }>;
  updatedAt?: string;
}

export interface EnvironmentDiffResult {
  projectId?: string;
  fromEnv: string;
  toEnv: string;
  added: Array<string | { key: string; fromHash?: string; fromFingerprint?: string }>;
  removed: Array<string | { key: string; toHash?: string; toFingerprint?: string }>;
  changed: Array<string | { key: string; fromHash?: string; toHash?: string }>;
  sameCount?: number;
  unchangedCount?: number;
}

export interface GitOpsPlanResult {
  valid?: boolean;
  dryRun?: boolean;
  create: Array<{ kind: string; name: string; detail?: string }>;
  update: Array<{ kind: string; name: string; changes?: Array<string | { field: string; from?: unknown; to?: unknown }>; detail?: string }>;
  delete: Array<{ kind: string; name: string; detail?: string }>;
  warnings: string[];
  manifestHash?: string;
}

export interface GitOpsDriftResult {
  inSync?: boolean;
  drifted?: boolean;
  hasDrift?: boolean;
  hasAppliedManifest?: boolean;
  manifestHash?: string | null;
  expectedHash?: string | null;
  liveHash?: string | null;
  lastAppliedAt?: string | null;
  drifts?: Array<{ kind: string; name: string; field?: string; expected?: string; actual?: string; detail?: string }>;
  differences?: {
    create?: Array<{ kind: string; name: string }>;
    update?: Array<{ kind: string; name: string }>;
    delete?: Array<{ kind: string; name: string }>;
  };
  summary?: {
    create: number;
    update: number;
    delete: number;
    hasChanges?: boolean;
  };
}

// --- Uptime Monitors, Páginas públicas de estado, Auto-Sleep y Cost Advisor ---

export interface UptimeMonitorCheckPoint {
  at: string;
  ok: boolean;
  status?: 'up' | 'degraded' | 'down' | string;
  statusCode?: number | null;
  latencyMs?: number | null;
  error?: string | null;
}

export interface UptimeHistoryBar {
  status: 'up' | 'degraded' | 'down' | 'nodata' | string;
  uptimePct: number | null;
}

export interface UptimeMonitor {
  id: string;
  name: string;
  type: 'http' | 'tcp' | 'managed_project' | string;
  target?: string;
  url?: string;
  host?: string;
  port?: number | null;
  projectId?: string | null;
  intervalSec: number;
  expectedStatus?: number;
  keyword?: string | null;
  maxLatencyMs?: number | null;
  enabled: boolean;
  public?: boolean;
  status: 'up' | 'degraded' | 'down' | 'pending' | string;
  uptime24h?: number | null;
  uptime7d?: number | null;
  uptime30d?: number | null;
  p50LatencyMs?: number | null;
  p95LatencyMs?: number | null;
  lastLatencyMs?: number | null;
  lastCheckedAt?: string | null;
  lastError?: string | null;
  incidentOpen?: boolean;
  activeIncidentId?: string | null;
  history30?: UptimeHistoryBar[];
  recentChecks?: UptimeMonitorCheckPoint[];
  createdAt?: string;
}

export interface PublicStatusPage {
  slug: string;
  title: string;
  description?: string;
  accentColor?: string;
  monitorIds: string[];
  publicUrl?: string;
  badgeUrl?: string;
  overallStatus?: 'operational' | 'degraded' | 'outage' | string;
  createdAt?: string;
  updatedAt?: string;
}

export interface SleepPolicy {
  projectId: string;
  enabled: boolean;
  idleMinutes: number;
  mode: 'pause' | 'stop';
  wakeTimeoutMs?: number;
  excludeCrons?: boolean;
  sleeping?: boolean;
  isSleeping?: boolean;
  lastSleptAt?: string | null;
  lastWokenAt?: string | null;
}

export interface AdvisorRecommendation {
  id?: string;
  severity: 'info' | 'warn' | 'critical' | string;
  category: 'auto_sleep' | 'oversized_ram' | 'oom_risk' | 'cost_savings' | string;
  projectId?: string | null;
  projectName?: string | null;
  title: string;
  detail: string;
  reclaimableRamMb?: number | null;
  estimatedMonthlySavingsEur?: number | null;
  estimatedSavingsEur?: number | null;
  actionLabel?: string | null;
}

export interface ResourceAdvisorReport {
  checkedAt?: string;
  generatedAt?: string;
  vpsMonthlyEur?: number;
  host?: {
    totalMemMb?: number;
    freeMemMb?: number;
    usedMemMb?: number;
    freeMemPct?: number;
    usedMemPct?: number;
    cpuCount?: number;
    totalRamMb?: number;
    usedRamMb?: number;
    freeRamMb?: number;
    freePercent?: number;
    cpus?: number;
  };
  summary?: {
    containersCount?: number;
    reclaimableRamMb?: number;
    oomRiskCount?: number;
    idleCandidatesCount?: number;
    oversizedCapsCount?: number;
  };
  costLedger?: {
    currency?: string;
    vpsMonthlyEur: number;
    saasAverageMonthlyEur: number;
    monthlySavingsEur: number;
    annualSavingsEur?: number;
    savingsPct?: number;
    potentialAdditionalSavingsEur?: number;
  };
  savingsLedger?: {
    vpsMonthlyEur: number;
    estimatedSaasMonthlyEur: number;
    monthlySavingsEur: number;
    annualSavingsEur?: number;
    reclaimableRamMb?: number;
  };
  sleepCandidates?: Array<{
    projectId: string;
    projectName: string;
    memoryMb: number;
    idleMinutes?: number;
    isSleeping?: boolean;
    policyEnabled?: boolean;
  }>;
  recommendations: AdvisorRecommendation[];
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

  async installService(body: { templateId: string; name?: string; domain?: string | null; env?: Record<string, string>; tz?: string }): Promise<ServiceInstallation> {
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
  },

  // --- Multi-Server Fleet (SSH Orchestration) ---

  async getServers(params: { tag?: string; region?: string } = {}): Promise<{ servers: FleetServer[] }> {
    const qs = new URLSearchParams();
    if (params.tag) qs.set('tag', params.tag);
    if (params.region) qs.set('region', params.region);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/servers${suffix}`),
      'No se pudieron cargar los servidores de la flota'
    );
    return Array.isArray(data) ? { servers: data } : { servers: data?.servers || [] };
  },

  async addServer(payload: {
    name: string;
    host: string;
    port?: number;
    user?: string;
    keyId?: string;
    generateKey?: boolean;
    privateKeyPem?: string;
    dockerSocketPath?: string;
    region?: string;
    tags?: string[];
    hostKeyPolicy?: 'tofu' | 'strict';
    expectedFingerprint?: string;
  }): Promise<FleetServer> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/servers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo añadir el servidor remoto'
    );
    return data?.server || data;
  },

  async updateServer(id: string, payload: Partial<{
    name: string;
    host: string;
    port: number;
    user: string;
    keyId: string;
    dockerSocketPath: string;
    region: string;
    tags: string[];
    hostKeyPolicy: 'tofu' | 'strict';
  }>): Promise<FleetServer> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/servers/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo actualizar el servidor'
    );
    return data?.server || data;
  },

  async deleteServer(id: string, force = false): Promise<{ deleted?: boolean; removed?: boolean }> {
    const qs = force ? '?force=1' : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/servers/${encodeURIComponent(id)}${qs}`, { method: 'DELETE' }),
      'No se pudo eliminar el servidor'
    );
  },

  async probeServer(id: string, force = true): Promise<{ server?: FleetServer; probe?: FleetServerProbe; resources?: FleetServerProbe | null; status?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/servers/${encodeURIComponent(id)}/probe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force }),
      }),
      'No se pudo sondear el servidor remoto'
    );
  },

  async repinServerHostKey(id: string, expectedFingerprint?: string): Promise<{ server?: FleetServer; fingerprint?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/servers/${encodeURIComponent(id)}/repin-host-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(expectedFingerprint ? { expectedFingerprint } : {}),
      }),
      'No se pudo volver a fijar la huella SSH'
    );
  },

  async getFleetKeys(): Promise<{ keys: FleetSshKey[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/keys`),
      'No se pudieron cargar las llaves SSH'
    );
    return Array.isArray(data) ? { keys: data } : { keys: data?.keys || [] };
  },

  async createFleetKey(payload: {
    name: string;
    mode?: 'generate' | 'import';
    privateKeyPem?: string;
  }): Promise<FleetSshKey> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo crear la llave SSH'
    );
    return data?.key || data;
  },

  async deleteFleetKey(id: string): Promise<{ deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/keys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'No se pudo eliminar la llave SSH'
    );
  },

  // --- Teams, RBAC y Tokens con alcance ---

  async getRbacMe(): Promise<RbacIdentity> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/me`),
      'No se pudo obtener la identidad de acceso'
    );
  },

  async getTeams(): Promise<{ teams: TeamSummary[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/teams`),
      'No se pudieron cargar los equipos'
    );
    return Array.isArray(data) ? { teams: data } : { teams: data?.teams || [] };
  },

  async getTeamMembers(teamId = 'team_default'): Promise<{ members: TeamMember[]; invites?: TeamInvite[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/members`),
      'No se pudieron cargar los miembros del equipo'
    );
    return Array.isArray(data)
      ? { members: data, invites: [] }
      : { members: data?.members || [], invites: data?.invites || [] };
  },

  async getTeamInvites(teamId = 'team_default'): Promise<{ invites: TeamInvite[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/invites`),
      'No se pudieron cargar las invitaciones pendientes'
    );
    return Array.isArray(data) ? { invites: data } : { invites: data?.invites || [] };
  },

  async createTeamInvite(payload: {
    teamId?: string;
    email: string;
    role: RbacRole;
    ttlHours?: number;
    projectIds?: string[] | null;
  }): Promise<{ invite: TeamInvite; token?: string; inviteToken?: string; inviteUrl?: string }> {
    const teamId = payload.teamId || 'team_default';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/invites`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo generar la invitación'
    );
  },

  async revokeTeamInvite(inviteId: string, teamId = 'team_default'): Promise<{ revoked?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/invites/${encodeURIComponent(inviteId)}`, {
        method: 'DELETE',
      }),
      'No se pudo revocar la invitación'
    );
  },

  async updateTeamMember(
    id: string,
    payload: { teamId?: string; role?: RbacRole; projectIds?: string[] | '*' | null }
  ): Promise<TeamMember> {
    const teamId = payload.teamId || 'team_default';
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo actualizar el miembro del equipo'
    );
    return data?.member || data;
  },

  async removeTeamMember(id: string, teamId = 'team_default'): Promise<{ removed?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
      'No se pudo eliminar el miembro del equipo'
    );
  },

  async getProjectAcl(projectId: string): Promise<{ teamId?: string; overrides: Record<string, string> }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/acl`),
      'No se pudieron cargar los permisos del proyecto'
    );
  },

  async setProjectAcl(projectId: string, payload: { userId: string; role: string }): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/acl`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo actualizar el permiso del proyecto'
    );
  },

  async removeProjectAcl(projectId: string, userId: string): Promise<{ removed?: boolean }> {
    return jsonOrThrow(
      await apiFetch(
        `${API_BASE}/projects/${encodeURIComponent(projectId)}/acl/${encodeURIComponent(userId)}`,
        { method: 'DELETE' }
      ),
      'No se pudo restablecer el permiso del proyecto'
    );
  },

  async getScopedTokens(): Promise<{ tokens: ScopedApiToken[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/tokens`),
      'No se pudieron cargar los tokens de API'
    );
    return Array.isArray(data) ? { tokens: data } : { tokens: data?.tokens || [] };
  },

  async createScopedToken(payload: {
    name: string;
    role?: RbacRole;
    scopes: string[];
    projectIds?: string[] | '*' | null;
    expiresInDays?: number | null;
    teamId?: string;
  }): Promise<{ token: string; record?: ScopedApiToken; meta?: ScopedApiToken }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo crear el token con alcance'
    );
  },

  async revokeScopedToken(id: string): Promise<{ revoked?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'No se pudo revocar el token'
    );
  },

  // --- Entornos y Shared Encrypted Vault ---

  async getVaultSecrets(): Promise<{ secrets: VaultSecretMeta[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/vault`),
      'No se pudieron cargar los secretos del Vault'
    );
    return Array.isArray(data) ? { secrets: data } : { secrets: data?.secrets || [] };
  },

  async setVaultSecret(key: string, value: string, opts: { scope?: 'runtime' | 'build' | 'both' } = {}): Promise<VaultSecretMeta> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/vault/${encodeURIComponent(key)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value, ...opts }),
      }),
      'No se pudo guardar el secreto en el Vault'
    );
    return data?.secret || data;
  },

  async deleteVaultSecret(key: string): Promise<{ deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/vault/${encodeURIComponent(key)}`, { method: 'DELETE' }),
      'No se pudo eliminar el secreto del Vault'
    );
  },

  async getProjectEnvironments(projectId: string): Promise<{ environments: ProjectEnvironmentItem[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/environments`),
      'No se pudieron cargar los entornos del proyecto'
    );
    return Array.isArray(data) ? { environments: data } : { environments: data?.environments || [] };
  },

  async saveProjectEnvironment(
    projectId: string,
    env: string,
    payload: { branch?: string; domains?: string[]; serverId?: string; envVars?: Record<string, string> }
  ): Promise<ProjectEnvironmentItem> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(env)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo guardar el entorno'
    );
    return data?.environment || data;
  },

  async diffProjectEnvironments(projectId: string, from: string, to: string): Promise<EnvironmentDiffResult> {
    const qs = new URLSearchParams({ from, to });
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/environments/diff?${qs.toString()}`),
      'No se pudo calcular el diff entre entornos'
    );
  },

  async promoteProjectEnvironment(
    projectId: string,
    payload: { fromEnv: string; toEnv: string; includeEnvVars?: boolean; dryRun?: boolean }
  ): Promise<any> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/environments/promote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo promocionar el entorno'
    );
  },

  // --- Declarative GitOps (culkibo.yaml) ---

  async exportGitOps(opts: { projectIds?: string[]; name?: string; includeCrons?: boolean; includeMonitors?: boolean } = {}): Promise<{ yaml: string; manifestHash?: string }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/gitops/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts),
      }),
      'No se pudo exportar culkibo.yaml'
    );
    return { yaml: data?.yaml || data?.yamlText || '', manifestHash: data?.manifestHash };
  },

  async planGitOps(yaml: string, prune = false): Promise<GitOpsPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/gitops/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml, yamlText: yaml, prune }),
      }),
      'No se pudo simular el plan GitOps'
    );
  },

  async applyGitOps(
    yaml: string,
    opts: { dryRun?: boolean; prune?: boolean; confirmDestructive?: boolean } = {}
  ): Promise<GitOpsPlanResult & { applied?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/gitops/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml, yamlText: yaml, ...opts }),
      }),
      'No se pudo aplicar el manifiesto GitOps'
    );
  },

  async getGitOpsDrift(): Promise<GitOpsDriftResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/gitops/drift`),
      'No se pudo comprobar el drift de GitOps'
    );
  },

  // --- Uptime Monitors y Páginas públicas de estado ---

  async getUptimeMonitors(): Promise<{ monitors: UptimeMonitor[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/monitors`),
      'No se pudieron cargar los monitores de disponibilidad'
    );
    return Array.isArray(data) ? { monitors: data } : { monitors: data?.monitors || [] };
  },

  async createUptimeMonitor(payload: {
    name: string;
    type: 'http' | 'tcp' | 'managed_project';
    url?: string;
    host?: string;
    port?: number;
    projectId?: string;
    intervalSec?: number;
    expectedStatus?: number;
    keyword?: string;
    maxLatencyMs?: number;
    public?: boolean;
  }): Promise<UptimeMonitor> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/monitors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo crear el monitor de disponibilidad'
    );
    return data?.monitor || data;
  },

  async deleteUptimeMonitor(id: string): Promise<{ deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/monitors/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'No se pudo eliminar el monitor'
    );
  },

  async runUptimeCheck(id: string): Promise<{ monitor?: UptimeMonitor; check?: UptimeMonitorCheckPoint }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/monitors/${encodeURIComponent(id)}/check`, { method: 'POST' }),
      'No se pudo ejecutar la comprobación manual'
    );
  },

  async getStatusPages(): Promise<{ pages: PublicStatusPage[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/pages`),
      'No se pudieron cargar las páginas de estado'
    );
    return Array.isArray(data) ? { pages: data } : { pages: data?.pages || [] };
  },

  async saveStatusPage(payload: {
    slug: string;
    title: string;
    description?: string;
    accentColor?: string;
    monitorIds: string[];
  }): Promise<PublicStatusPage> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/pages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo guardar la página pública de estado'
    );
    return data?.page || data;
  },

  async deleteStatusPage(slug: string): Promise<{ deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/pages/${encodeURIComponent(slug)}`, { method: 'DELETE' }),
      'No se pudo eliminar la página de estado'
    );
  },

  // --- Scale-to-Zero Auto-Sleep y VPS Cost/RAM Advisor ---

  async getSleepPolicy(projectId: string): Promise<SleepPolicy> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/sleep/${encodeURIComponent(projectId)}`),
      'No se pudo leer la política de auto-reposo'
    );
  },

  async saveSleepPolicy(
    projectId: string,
    payload: { enabled: boolean; idleMinutes?: number; mode?: 'pause' | 'stop'; excludeCrons?: boolean }
  ): Promise<SleepPolicy> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/sleep/${encodeURIComponent(projectId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo guardar la política de auto-reposo'
    );
  },

  async sleepProject(projectId: string): Promise<{ sleeping?: boolean; status?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/sleep/${encodeURIComponent(projectId)}/sleep`, { method: 'POST' }),
      'No se pudo suspender el proyecto'
    );
  },

  async wakeProject(projectId: string): Promise<{ awake?: boolean; status?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/sleep/${encodeURIComponent(projectId)}/wake`, { method: 'POST' }),
      'No se pudo despertar el proyecto'
    );
  },

  async getResourceAdvisor(vpsMonthlyEur?: number): Promise<ResourceAdvisorReport> {
    const qs = typeof vpsMonthlyEur === 'number' && Number.isFinite(vpsMonthlyEur)
      ? `?vpsMonthlyEur=${encodeURIComponent(String(vpsMonthlyEur))}`
      : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/advisor/resources${qs}`),
      'No se pudo analizar el ahorro y consumo del VPS'
    );
  },

  // --- Live Sync 2.0 (Per-File Time-Travel & Multi-Client Conflicts) ---

  async getSyncFileHistory(projectId: string, filePath: string): Promise<LiveSyncFileHistory> {
    const qs = new URLSearchParams({ path: filePath });
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/sync/files/history?${qs.toString()}`),
      'No se pudo cargar el historial del archivo'
    );
  },

  async rollbackSyncFile(
    projectId: string,
    filePath: string,
    seq: number,
    mode: 'to' | 'before' = 'to'
  ): Promise<{ reverted?: boolean; filePath?: string; targetSeq?: number; durationMs?: number }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/sync/files/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: filePath, seq, mode }),
      }),
      'No se pudo revertir el archivo a esa revisión'
    );
  },

  async resolveSyncConflict(projectId: string, conflictId: string): Promise<{ resolved?: boolean }> {
    return jsonOrThrow(
      await apiFetch(
        `${API_BASE}/projects/${encodeURIComponent(projectId)}/sync/conflicts/${encodeURIComponent(conflictId)}/resolve`,
        { method: 'POST' }
      ),
      'No se pudo marcar el conflicto como resuelto'
    );
  },

  // =====================================================================
  // v1.1.0 — Adversarial Fuzz, CLI DX, Observability Alerts & Topology
  // =====================================================================

  // --- Adversarial Fuzz & Crash Recovery ---

  async fuzzEndpoint(payload: {
    path: string;
    method?: string;
    rounds?: number;
    seed?: number;
    payloadSizeKb?: number;
  }): Promise<FuzzRunResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fuzz/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo ejecutar la sesión de fuzzing'
    );
  },

  async getFuzzHistory(limit = 20): Promise<{ runs: FuzzRunResult[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fuzz/history?limit=${limit}`),
      'No se pudo cargar el historial de fuzzing'
    );
  },

  async getCrashRecoveryStatus(): Promise<CrashRecoveryStatus> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/crash-recovery`),
      'No se pudo consultar el estado de crash recovery'
    );
  },

  async triggerCrashRecovery(): Promise<{ recovered: boolean; actions: string[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/crash-recovery`, { method: 'POST' }),
      'No se pudo ejecutar la recuperación tras fallo'
    );
  },

  // --- CLI DX (init, up, logs, env, exec, releases, rollback) ---

  async cliInit(payload: {
    name: string;
    template?: string;
    directory?: string;
  }): Promise<CliInitResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo inicializar el proyecto desde CLI'
    );
  },

  async cliUp(projectId: string, opts: { attach?: boolean; build?: boolean } = {}): Promise<CliUpResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/up`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, ...opts }),
      }),
      'No se pudo levantar el proyecto desde CLI'
    );
  },

  async cliLogs(projectId: string, opts: { tail?: number; follow?: boolean; since?: string } = {}): Promise<{ lines: string[] }> {
    const qs = new URLSearchParams();
    qs.set('projectId', projectId);
    if (opts.tail) qs.set('tail', String(opts.tail));
    if (opts.follow) qs.set('follow', '1');
    if (opts.since) qs.set('since', opts.since);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/logs?${qs.toString()}`),
      'No se pudieron obtener los logs desde CLI'
    );
  },

  async cliEnv(projectId: string, action: 'list' | 'set' | 'unset', payload?: { key?: string; value?: string }): Promise<CliEnvResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/env`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, action, ...payload }),
      }),
      'No se pudo gestionar las variables de entorno desde CLI'
    );
  },

  async cliExec(projectId: string, command: string, opts: { timeoutMs?: number; workdir?: string } = {}): Promise<CliExecResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, command, ...opts }),
      }),
      'No se pudo ejecutar el comando desde CLI'
    );
  },

  async cliReleases(projectId: string, limit = 10): Promise<{ releases: CliRelease[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/releases?projectId=${encodeURIComponent(projectId)}&limit=${limit}`),
      'No se pudieron listar las releases desde CLI'
    );
  },

  async cliRollback(projectId: string, target?: string): Promise<{ success: boolean; deployment: Deployment }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/cli/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, target }),
      }),
      'No se pudo hacer rollback desde CLI'
    );
  },

  // --- Observability Alerts, Metrics History & Topology ---

  async getAlertRules(): Promise<{ rules: AlertRule[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/alerts/rules`),
      'No se pudieron cargar las reglas de alertas'
    );
    return Array.isArray(data) ? { rules: data } : { rules: data?.rules || [] };
  },

  async createAlertRule(payload: {
    name: string;
    metric: string;
    condition: 'gt' | 'lt' | 'gte' | 'lte' | 'eq';
    threshold: number;
    windowSec?: number;
    cooldownSec?: number;
    channels?: string[];
    projectId?: string;
    enabled?: boolean;
  }): Promise<AlertRule> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/alerts/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo crear la regla de alerta'
    );
    return data?.rule || data;
  },

  async updateAlertRule(id: string, payload: Partial<AlertRule>): Promise<AlertRule> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/alerts/rules/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo actualizar la regla de alerta'
    );
    return data?.rule || data;
  },

  async deleteAlertRule(id: string): Promise<{ deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/alerts/rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'No se pudo eliminar la regla de alerta'
    );
  },

  async getAlertHistory(opts: { limit?: number; ruleId?: string; status?: string } = {}): Promise<{ alerts: AlertEvent[] }> {
    const qs = new URLSearchParams();
    if (opts.limit) qs.set('limit', String(opts.limit));
    if (opts.ruleId) qs.set('ruleId', opts.ruleId);
    if (opts.status) qs.set('status', opts.status);
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/alerts/history?${qs.toString()}`),
      'No se pudo cargar el historial de alertas'
    );
  },

  async getMetricsHistory(opts: {
    metric?: string;
    projectId?: string;
    fromTs?: number;
    toTs?: number;
    stepSec?: number;
  } = {}): Promise<{ series: MetricsHistorySeries[] }> {
    const qs = new URLSearchParams();
    if (opts.metric) qs.set('metric', opts.metric);
    if (opts.projectId) qs.set('projectId', opts.projectId);
    if (opts.fromTs) qs.set('from', String(opts.fromTs));
    if (opts.toTs) qs.set('to', String(opts.toTs));
    if (opts.stepSec) qs.set('step', String(opts.stepSec));
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/metrics/history?${qs.toString()}`),
      'No se pudo cargar el historial de métricas'
    );
  },

  async getTopology(): Promise<TopologyGraph> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/topology`),
      'No se pudo cargar la topología del sistema'
    );
  },

  // --- Edge Multi-DNS-01 & HTTP/3 (QUIC) v1.1 ---

  async getDnsProviders(): Promise<{ providers: DnsProviderInfo[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/dns-providers`),
      'No se pudieron cargar los proveedores DNS-01'
    );
    return Array.isArray(data) ? { providers: data } : { providers: data?.providers || [] };
  },

  async getHttp3Status(): Promise<Http3ProbeResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/ingress/http3`),
      'No se pudo comprobar el estado de HTTP/3 (QUIC)'
    );
  },

  // --- Enterprise Security v1.1 (TOTP 2FA, OIDC SSO, Hash-Chained Audit, Secret Scanner) ---

  async setup2FA(): Promise<TotpSetupResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/2fa/setup`, { method: 'POST' }),
      'No se pudo iniciar la configuración de 2FA (TOTP)'
    );
  },

  async verify2FA(code: string): Promise<TotpVerifyResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/2fa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      }),
      'Código TOTP inválido o caducado'
    );
  },

  async disable2FA(payload: { code: string; password?: string }): Promise<{ disabled?: boolean; alreadyDisabled?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/2fa/disable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo desactivar la autenticación en dos pasos'
    );
  },

  async getOidcProviders(): Promise<{ providers: OidcProviderSummary[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/oidc/providers`),
      'No se pudieron cargar los proveedores OIDC SSO'
    );
    return Array.isArray(data) ? { providers: data } : { providers: data?.providers || [] };
  },

  async getSecurityAuditLog(opts: { limit?: number; since?: string; action?: string } = {}): Promise<{ entries: AuditLogEvent[] }> {
    const qs = new URLSearchParams();
    if (opts.limit) qs.set('limit', String(opts.limit));
    if (opts.since) qs.set('since', opts.since);
    if (opts.action) qs.set('action', opts.action);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/security/audit-log${suffix}`),
      'No se pudo leer el registro de auditoría cifrado'
    );
    return Array.isArray(data) ? { entries: data } : { entries: data?.entries || data?.events || [] };
  },

  async verifyAuditLogIntegrity(): Promise<AuditChainVerification> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/audit-log/verify`, { method: 'POST' }),
      'No se pudo verificar la cadena criptográfica de auditoría'
    );
  },

  async scanSecrets(payload: {
    text?: string;
    envVars?: Record<string, string>;
    composeYaml?: string;
    culkiboYaml?: string;
    dockerfile?: string;
  }): Promise<SecretScanReport> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/scan-secrets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'No se pudo ejecutar el escáner de secretos'
    );
  },

  // --- Cycle-2 & Cycle-3 Pioneer Controls (Fast Restart, SmartPack, DirectPush, EdgeTunnel, Stream, Edition) ---

  async fastRestartProject(
    projectId: string,
    opts: { envVars?: Record<string, string> } = {}
  ): Promise<FastRestartResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/fast-restart`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts),
      }),
      'Could not restart container with updated environment variables'
    );
  },

  async getSmartPackPlan(payload: {
    dir?: string;
    dirPath?: string;
    projectId?: string;
    files?: string[] | Record<string, string>;
    containerPort?: number;
    memoryMb?: number;
    cpus?: number;
    zstdChunked?: boolean;
  } = {}): Promise<SmartPackPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/build/smartpack/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not generate SmartPack build plan'
    );
  },

  async planDirectPush(payload: {
    image: string;
    serverId?: string;
    sshHost?: string;
    sshPort?: number;
    sshUser?: string;
    localPort?: number;
    remotePort?: number;
    direction?: 'push' | 'pull';
    targetTag?: string;
    projectId?: string;
  }): Promise<DirectPushPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/deploy/direct-push/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not generate DirectPush SSH plan'
    );
  },

  async getEdgeTunnelStatus(): Promise<EdgeTunnelStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/edge-tunnel/status`),
      'Could not query EdgeTunnel status'
    );
  },

  async createEdgeTunnel(payload: {
    name: string;
    targetHost: string;
    targetPort: number;
    hostname?: string;
  }): Promise<EdgeTunnelCreateResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/edge-tunnel/tunnels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not create sovereign EdgeTunnel'
    );
  },

  async revokeEdgeTunnel(id: string): Promise<{ revoked: boolean; id?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/edge-tunnel/tunnels/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
      'Could not revoke EdgeTunnel'
    );
  },

  async planCoolifyStream(payload: Record<string, unknown>): Promise<CoolifyStreamPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/import/coolify/stream-plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not generate Coolify volume & database stream plan'
    );
  },

  async getEditionStatus(): Promise<EditionStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/system/edition`),
      'Could not query Culkibo edition'
    );
  },

  // --- Cycle-4 Native Zero-Dep OTLP/HTTP JSON Exporter ---

  async getOtlpStatus(): Promise<OtlpStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/otlp`),
      'Could not load OTLP exporter status'
    );
  },

  async updateOtlpConfig(payload: {
    enabled?: boolean;
    endpoint?: string;
    serviceName?: string;
    headers?: Record<string, string>;
  }): Promise<OtlpStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/otlp`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not update OTLP exporter configuration'
    );
  },

  async flushOtlp(): Promise<{ ok?: boolean; flushed?: number; status?: OtlpStatusResult }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/observability/otlp/flush`, { method: 'POST' }),
      'Could not flush OTLP spans'
    );
  },

  // --- Cycle-5 Cockpit Helpers (SLSA v1.1 DSSE, Atomic DB Migrations, Micro-Wasm) ---

  async attestProjectRelease(
    projectId: string,
    rev: string,
    payload: { imageDigest?: string; commitSha?: string; builderId?: string } = {}
  ): Promise<ReleaseAttestationResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/releases/${encodeURIComponent(rev)}/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not sign SLSA v1.1 release attestation'
    );
  },

  async verifyReleaseAttestation(
    envelope: Record<string, unknown>,
    publicKeyPem?: string
  ): Promise<AttestationVerifyResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/attestation/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(publicKeyPem ? { envelope, publicKeyPem } : { envelope }),
      }),
      'Could not verify SLSA v1.1 attestation'
    );
  },

  async planProjectMigration(
    projectId: string,
    command: string
  ): Promise<MigrationPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/migrations/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      }),
      'Could not plan atomic DB migration'
    );
  },

  async invokeProjectWasm(
    projectId: string,
    opts: { smokeTest?: boolean; wasmPath?: string; arg?: number; timeoutMs?: number } = { smokeTest: true }
  ): Promise<WasmInvokeResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/wasm/invoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts),
      }),
      'Could not invoke Micro-Wasm handler'
    );
  },

  // --- Cycle-6 Cockpit Helpers (Whole-Stack Time-Machine, Shadow Replay Gate, FinOps) ---

  async listTimeMachine(projectId: string): Promise<{ checkpoints: TimeMachineCheckpoint[] }> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/timemachine`),
      'Could not load Time-Machine checkpoints'
    );
    return Array.isArray(data) ? { checkpoints: data } : { checkpoints: data?.checkpoints || [] };
  },

  async createTimeMachineCheckpoint(
    projectId: string,
    payload: { label?: string; actor?: string } = {}
  ): Promise<TimeMachineCheckpoint> {
    const data = await jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/timemachine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not create Time-Machine checkpoint'
    );
    return data?.checkpoint || data;
  },

  async restoreTimeMachineCheckpoint(
    projectId: string,
    checkpointId: string,
    opts: { dryRun?: boolean } = { dryRun: true }
  ): Promise<TimeMachineRestoreResult> {
    return jsonOrThrow(
      await apiFetch(
        `${API_BASE}/projects/${encodeURIComponent(projectId)}/timemachine/${encodeURIComponent(checkpointId)}/restore`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ dryRun: opts.dryRun !== false }),
        }
      ),
      'Could not run Time-Machine restore'
    );
  },

  async runShadowReplay(
    projectId: string,
    payload: {
      baselineUrl?: string;
      candidateUrl?: string;
      allowLoopback?: boolean;
      requests?: Array<{ method?: string; path: string; headers?: Record<string, string>; body?: string }>;
      gate?: { max5xxDelta?: number; maxLatencyRatio?: number; maxStatusMismatchPct?: number; failOnSchemaDrift?: boolean };
    } = {}
  ): Promise<ShadowReplayReport> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/shadow-replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not execute Shadow Traffic Replay'
    );
  },

  async getFinOpsReport(): Promise<FinOpsReportResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/finops/report`),
      'Could not load FinOps savings report'
    );
  },

  async compareCloudFinOps(payload: {
    apps?: number;
    databases?: number;
    avgRamMbPerApp?: number;
    monthlyBandwidthGb?: number;
  }): Promise<FinOpsComparison> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/finops/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not calculate cloud savings comparison'
    );
  },

  // --- Cycle-7 Pioneer APIs (Web Terminal, Build Auto-Healer, WireGuard Mesh, Edge Shield, Cron Timeline & Heartbeats) ---

  async issueTerminalTicket(
    projectId: string,
    payload: { shell?: '/bin/sh' | '/bin/bash' | '/bin/ash'; containerName?: string; cols?: number; rows?: number } = {}
  ): Promise<TerminalTicketResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/terminal/ticket`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not issue container terminal ticket'
    );
  },

  async listTerminalSessions(): Promise<{ sessions: TerminalSessionInfo[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/terminal/sessions`),
      'Could not list terminal sessions'
    );
  },

  async diagnoseBuildLogs(
    projectId: string,
    payload: { logs: string }
  ): Promise<BuildHealerDiagnosis> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/build-healer/diagnose`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not diagnose build logs'
    );
  },

  async applyBuildHeal(
    projectId: string,
    payload: { logs?: string; code?: string; dryRun?: boolean } = { dryRun: true }
  ): Promise<BuildHealerApplyResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/build-healer/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...payload, dryRun: payload.dryRun !== false }),
      }),
      'Could not plan build auto-heal'
    );
  },

  async getFleetMesh(): Promise<FleetMeshStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/mesh`),
      'Could not load WireGuard fleet mesh'
    );
  },

  async planFleetMesh(payload: { dryRun?: boolean; includeRedactedTemplate?: boolean } = { dryRun: true }): Promise<FleetMeshPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/mesh/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dryRun: payload.dryRun !== false, includeRedactedTemplate: payload.includeRedactedTemplate }),
      }),
      'Could not generate WireGuard mesh plan'
    );
  },

  async rotateFleetMeshKey(payload: { nodeId: string; dryRun?: boolean }): Promise<FleetMeshRotateResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/fleet/mesh/rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId: payload.nodeId, dryRun: payload.dryRun !== false }),
      }),
      'Could not simulate WireGuard key rotation'
    );
  },

  async getEdgeShieldStatus(): Promise<EdgeShieldStatusResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/edge-shield/status`),
      'Could not load Edge Bot-Shield status'
    );
  },

  async getEdgeShieldChallenge(domain?: string): Promise<EdgeShieldChallengeResult> {
    const qs = new URLSearchParams({ format: 'json' });
    if (domain) qs.set('domain', domain);
    const res = await apiFetch(`${API_BASE}/edge-shield/challenge?${qs.toString()}`, {
      headers: { Accept: 'application/json' },
    });
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      return jsonOrThrow(res, 'Could not issue Edge Shield PoW challenge');
    }
    const text = await res.text();
    if (!res.ok) throw new Error(`Edge Shield challenge error (HTTP ${res.status})`);
    return {
      challengeId: 'html-challenge',
      salt: 'sha256-browser-gate',
      difficulty: 4,
      algorithm: 'sha256',
      domain: domain || 'edge',
      htmlPreviewBytes: text.length,
    };
  },

  async getCronTimeline(hours = 24): Promise<CronTimelineResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/crons/timeline?hours=${encodeURIComponent(String(hours))}`),
      'Could not load 24h cron timeline'
    );
  },

  async listHeartbeats(): Promise<{ heartbeats: HeartbeatMonitor[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/heartbeats`),
      'Could not load heartbeats'
    );
  },

  async createHeartbeat(payload: { name: string; projectId?: string; periodSec?: number; graceSec?: number }): Promise<{ heartbeat?: HeartbeatMonitor } & Partial<HeartbeatMonitor>> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/heartbeats`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not create heartbeat monitor'
    );
  },

  async deleteHeartbeat(id: string): Promise<{ ok?: boolean; deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/heartbeats/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'Could not delete heartbeat monitor'
    );
  },

  async pingHeartbeat(token: string, state?: 'start' | 'fail'): Promise<{ ok?: boolean; heartbeat?: HeartbeatMonitor; status?: string; lastPingAt?: string }> {
    const suffix = state ? `/${encodeURIComponent(state)}` : '';
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/heartbeat/${encodeURIComponent(token)}${suffix}`, { method: 'POST' }),
      'Could not send heartbeat check-in'
    );
  },

  // --- Cycle-8 Enterprise Sovereignty APIs (Passkeys FIDO2, Secret Leases, OSV CVE, OpenTofu IaC, Drift Check, Maintenance & Incidents) ---

  async listPasskeys(): Promise<{ passkeys: PasskeyRecord[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/passkeys`),
      'Could not load registered passkeys'
    );
  },

  async beginPasskeyRegistration(payload: { label?: string; rpId?: string } = {}): Promise<PasskeyRegisterBeginResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/passkeys/register/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not start WebAuthn passkey registration'
    );
  },

  async revokePasskey(id: string): Promise<{ ok?: boolean; revoked?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/auth/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'Could not revoke passkey'
    );
  },

  async listSecretLeases(): Promise<{ leases: SecretLeaseRecord[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/leases`),
      'Could not load secret leases'
    );
  },

  async issueSecretLease(payload: { projectId?: string; secretKey: string; scope?: string; ttlSec?: number; reason?: string }): Promise<{ lease: SecretLeaseRecord; token?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/leases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not issue ephemeral secret lease'
    );
  },

  async revokeSecretLease(id: string): Promise<{ ok?: boolean; revoked?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/leases/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'Could not revoke secret lease'
    );
  },

  async issueBreakGlass(payload: { reason: string; ttlSec?: number }): Promise<{ lease: SecretLeaseRecord; token?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/break-glass`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not issue break-glass escalation token'
    );
  },

  async getSecretRotationAudit(maxAgeDays = 90): Promise<SecretRotationAuditResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/rotation-audit?maxAgeDays=${encodeURIComponent(String(maxAgeDays))}`),
      'Could not run secret rotation audit'
    );
  },

  async runCveScan(payload: { allowNetwork?: boolean; forceRefresh?: boolean } = {}): Promise<CveScanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/security/cve-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not scan SBOM CVEs'
    );
  },

  async getLatestCveScan(): Promise<CveScanResult | null> {
    const res = await apiFetch(`${API_BASE}/security/cve-scan/latest`);
    if (!res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!data) return null;
    return (data.scan || (typeof data.scannedPackages === 'number' ? data : null)) as CveScanResult | null;
  },

  async exportIacEstate(payload: { format?: 'all' | 'terraform' | 'compose' } = { format: 'all' }): Promise<IacExportResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/iac/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not export OpenTofu / Compose IaC bundle'
    );
  },

  async checkProjectDrift(projectId: string): Promise<ProjectDriftResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/projects/${encodeURIComponent(projectId)}/drift/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }),
      'Could not check container configuration drift'
    );
  },

  async listMaintenanceWindows(): Promise<{ windows?: MaintenanceWindowRecord[]; maintenanceWindows?: MaintenanceWindowRecord[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/maintenance`),
      'Could not load maintenance windows'
    );
  },

  async createMaintenanceWindow(payload: {
    title: string;
    targetIds?: string[];
    kind?: 'once' | 'recurring';
    startAt: string;
    durationMin?: number;
    intervalDays?: number;
  }): Promise<{ window?: MaintenanceWindowRecord } & Partial<MaintenanceWindowRecord>> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/maintenance`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not schedule maintenance window'
    );
  },

  async deleteMaintenanceWindow(id: string): Promise<{ ok?: boolean; deleted?: boolean }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/maintenance/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      'Could not delete maintenance window'
    );
  },

  async listUptimeIncidents(): Promise<{ incidents: StatusIncidentRecord[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/incidents`),
      'Could not load incident timeline'
    );
  },

  async createUptimeIncident(payload: {
    title: string;
    severity?: 'minor' | 'major' | 'critical';
    status?: 'investigating' | 'identified' | 'monitoring' | 'resolved';
    affectedIds?: string[];
    message?: string;
  }): Promise<{ incident?: StatusIncidentRecord } & Partial<StatusIncidentRecord>> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/incidents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not log incident'
    );
  },

  async updateUptimeIncident(
    id: string,
    payload: { status: 'investigating' | 'identified' | 'monitoring' | 'resolved'; message?: string }
  ): Promise<{ incident?: StatusIncidentRecord } & Partial<StatusIncidentRecord>> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/incidents/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not update incident'
    );
  },

  async planGeoFailover(payload: {
    domain: string;
    primaryIp: string;
    secondaryIp: string;
    consecutiveFailures?: number;
    ttlSec?: number;
  }): Promise<GeoFailoverPlanResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/uptime/geo-failover/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not build DNS geo-failover plan'
    );
  },

  // --- Cycle-9 Pioneer APIs (White-Label Brand, Standard-Webhooks DLQ, Read-Only DB Studio, Post-MinIO S3, Agency Quotas & Billing Ledger) ---

  async getBrandTheme(): Promise<BrandThemeConfig> {
    const res = await jsonOrThrow(await apiFetch(`${API_BASE}/brand`), 'Could not load brand theme');
    return (res?.brand || res) as BrandThemeConfig;
  },

  async updateBrandTheme(patch: Partial<BrandThemeConfig>): Promise<BrandThemeConfig> {
    const res = await jsonOrThrow(
      await apiFetch(`${API_BASE}/brand`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      }),
      'Could not update brand theme'
    );
    return (res?.brand || res) as BrandThemeConfig;
  },

  async resetBrandTheme(): Promise<BrandThemeConfig> {
    const res = await jsonOrThrow(
      await apiFetch(`${API_BASE}/brand/reset`, { method: 'POST' }),
      'Could not reset brand theme'
    );
    return (res?.brand || res) as BrandThemeConfig;
  },

  async listOutboundWebhooks(): Promise<{ subscriptions: OutboundWebhookSubscription[] }> {
    const res = await jsonOrThrow(
      await apiFetch(`${API_BASE}/webhooks/outbound`),
      'Could not load outbound webhook subscriptions'
    );
    const list = Array.isArray(res?.subscriptions) ? res.subscriptions : Array.isArray(res) ? res : [];
    return { subscriptions: list };
  },

  async upsertOutboundWebhook(payload: {
    id?: string;
    url: string;
    events?: string[];
    description?: string;
    enabled?: boolean;
  }): Promise<{ subscription?: OutboundWebhookSubscription; secret?: string; secretPreview?: string }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/webhooks/outbound`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not save outbound webhook subscription'
    );
  },

  async rotateOutboundWebhookSecret(
    subscriptionId: string,
    opts: { graceSec?: number } = {}
  ): Promise<WebhookSecretRotateResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/webhooks/outbound/${encodeURIComponent(subscriptionId)}/rotate-secret`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts),
      }),
      'Could not rotate webhook dual-secret'
    );
  },

  async listWebhookDlq(limit = 50): Promise<{ entries: WebhookDlqEntry[] }> {
    const res = await jsonOrThrow(
      await apiFetch(`${API_BASE}/webhooks/dlq?limit=${encodeURIComponent(String(limit))}`),
      'Could not load webhook DLQ'
    );
    const entries = Array.isArray(res?.entries)
      ? res.entries
      : Array.isArray(res?.dlq)
        ? res.dlq
        : Array.isArray(res?.items)
          ? res.items
          : [];
    return { entries };
  },

  async replayWebhookDlqEntry(dlqId: string): Promise<WebhookDlqReplayResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/webhooks/dlq/${encodeURIComponent(dlqId)}/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }),
      'Could not replay webhook DLQ entry'
    );
  },

  async runDbStudioSql(
    databaseId: string,
    payload: { query: string; engine?: string; maxRows?: number }
  ): Promise<DbStudioSqlResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${encodeURIComponent(databaseId)}/studio/sql`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Read-Only SQL gate rejected query'
    );
  },

  async runDbStudioRedis(
    databaseId: string,
    payload: { argv: string[] | string }
  ): Promise<DbStudioRedisResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${encodeURIComponent(databaseId)}/studio/redis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Safe Redis inspector rejected command'
    );
  },

  async runDbStudioBloat(
    databaseId: string,
    payload: { tableStats?: Array<Record<string, unknown>> } = {}
  ): Promise<DbStudioBloatResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/databases/${encodeURIComponent(databaseId)}/studio/bloat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not analyze Postgres table bloat'
    );
  },

  async getStoragePresets(): Promise<{ presets: S3StoragePreset[] }> {
    const res = await jsonOrThrow(
      await apiFetch(`${API_BASE}/storage/presets`),
      'Could not load Post-MinIO S3 presets'
    );
    const presets = Array.isArray(res?.presets) ? res.presets : Array.isArray(res) ? res : [];
    return { presets };
  },

  async generateS3PresignedUrl(payload: {
    endpoint: string;
    region?: string;
    bucket: string;
    key: string;
    method?: 'GET' | 'PUT' | 'HEAD' | 'DELETE';
    accessKeyId: string;
    secretAccessKey: string;
    expiresIn?: number;
  }): Promise<S3PresignResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/storage/presign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      'Could not generate SigV4 presigned URL'
    );
  },

  async getBillingLedger(periodDays = 30): Promise<BillingLedgerResult> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/billing/ledger?periodDays=${encodeURIComponent(String(periodDays))}`),
      'Could not load Agency billing usage ledger'
    );
  },

  async getBillingLedgerCsv(periodDays = 30): Promise<string> {
    const res = await apiFetch(
      `${API_BASE}/billing/ledger?format=csv&periodDays=${encodeURIComponent(String(periodDays))}`
    );
    if (!res.ok) {
      let msg = 'Could not generate formula-safe CSV ledger';
      try {
        const d = await res.json();
        if (d?.error) msg = String(d.error);
      } catch {
        // ignore non-json
      }
      throw new Error(msg);
    }
    return res.text();
  },

  async listTenantQuotas(): Promise<{ quotas: Record<string, TenantQuotaSpec> | TenantQuotaSpec[]; items?: TenantQuotaSpec[] }> {
    return jsonOrThrow(
      await apiFetch(`${API_BASE}/quotas`),
      'Could not load tenant quotas'
    );
  },
};

// =====================================================================
// v1.1.0 Types
// =====================================================================

// --- Adversarial Fuzz & Crash Recovery ---

export interface FuzzRunResult {
  id: string;
  path: string;
  method: string;
  rounds: number;
  seed: number;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  totalRequests: number;
  crashesFound: number;
  timeoutsFound: number;
  unexpectedStatuses: number;
  findings: Array<{
    round: number;
    statusCode: number;
    error?: string | null;
    payload?: string | null;
    latencyMs: number;
  }>;
}

export interface CrashRecoveryStatus {
  healthy: boolean;
  lastCrashAt: string | null;
  lastRecoveryAt: string | null;
  consecutiveCrashes: number;
  watchdogEnabled: boolean;
  autoRestart: boolean;
  recoveryActions: string[];
}

// --- CLI DX ---

export interface CliInitResult {
  success: boolean;
  projectId: string;
  name: string;
  directory: string;
  template?: string;
  configFile: string;
}

export interface CliUpResult {
  success: boolean;
  projectId: string;
  status: string;
  url?: string | null;
  port?: number | null;
  pid?: number | null;
}

export interface CliEnvResult {
  success: boolean;
  action: 'list' | 'set' | 'unset';
  vars?: Record<string, string>;
  key?: string;
  value?: string;
}

export interface CliExecResult {
  ok: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export interface CliRelease {
  id: string;
  version: string;
  imageTag: string;
  status: string;
  git: DeployGitInfo | null;
  promotedAt: string;
  current: boolean;
}

// --- Observability Alerts, Metrics History & Topology ---

export interface AlertRule {
  id: string;
  name: string;
  metric: string;
  condition: 'gt' | 'lt' | 'gte' | 'lte' | 'eq';
  threshold: number;
  windowSec: number;
  cooldownSec: number;
  channels: string[];
  projectId?: string | null;
  enabled: boolean;
  lastTriggeredAt?: string | null;
  lastValue?: number | null;
  status?: 'ok' | 'firing' | 'pending' | string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AlertEvent {
  id: string;
  ruleId: string;
  ruleName: string;
  metric: string;
  value: number;
  threshold: number;
  condition: string;
  status: 'firing' | 'resolved' | string;
  firedAt: string;
  resolvedAt?: string | null;
  deliveredChannels?: string[];
  projectId?: string | null;
}

export interface MetricsHistorySeries {
  metric: string;
  projectId?: string | null;
  points: Array<{
    ts: number;
    value: number;
  }>;
}

export interface TopologyNode {
  id: string;
  kind: 'project' | 'database' | 'service' | 'server' | 'ingress' | 'pod' | string;
  label: string;
  status: string;
  health?: string;
  meta?: Record<string, unknown>;
}

export interface TopologyEdge {
  from: string;
  to: string;
  label?: string;
  kind?: 'depends_on' | 'routes_to' | 'linked_db' | 'deploys_on' | string;
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  generatedAt: string;
}

// --- Edge Multi-DNS-01 & HTTP/3 v1.1 ---

export interface DnsProviderField {
  name: string;
  label?: string;
  envVar?: string;
  secret?: boolean;
  required?: boolean;
}

export interface DnsProviderInfo {
  id: string;
  label: string;
  caddyModule: string;
  xcaddyModule: string;
  fields: DnsProviderField[];
}

export interface Http3ProbeResult {
  supported: boolean;
  configured: boolean;
  protocols: string[];
  automaticHttpsDisabled: boolean;
  udp443Published: boolean | null;
  listen: string[];
  reason: string | null;
}

// --- Security v1.1 (TOTP 2FA, OIDC SSO, Hash-Chained Audit, Secret Scanner) ---

export interface TotpSetupResult {
  secretBase32?: string;
  secret?: string;
  otpauthUri?: string;
  otpauthUrl?: string;
  qrUrl?: string;
  issuer?: string;
  accountName?: string;
  digits?: number;
  period?: number;
  algorithm?: string;
}

export interface TotpVerifyResult {
  enabled?: boolean;
  verified?: boolean;
  valid?: boolean;
  enabledAt?: string | null;
  recoveryCodes?: string[];
  recoveryCodesRemaining?: number;
}

export interface OidcProviderSummary {
  id: string;
  type: string;
  protocol: string;
  name: string;
  enabled: boolean;
  issuerUrl?: string | null;
  clientId?: string;
  hasClientSecret?: boolean;
  redirectUri?: string;
  scopes?: string[];
  autoProvision?: boolean;
  defaultRole?: string;
  teamId?: string;
  allowedDomains?: string[];
  enforceLocal2fa?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface AuditChainVerification {
  valid: boolean;
  checkedCount: number;
  filesChecked: string[];
  anchored: boolean;
  firstSeq: number | null;
  lastSeq: number | null;
  headHash: string | null;
  brokenAtSeq: number | null;
  brokenAtLine: number | null;
  brokenFile: string | null;
  reason: string | null;
}

export interface SecretScanFinding {
  ruleId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  key: string | null;
  line: number | null;
  preview: string;
  remediation: string;
}

export interface SecretScanReport {
  clean: boolean;
  blocked: boolean;
  mode: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: SecretScanFinding[];
}

// --- Cycle-2 & Cycle-3 Pioneer Types (Fast Restart, SmartPack, DirectPush, EdgeTunnel, Stream, Edition) ---

export interface FastRestartResult {
  restarted: boolean;
  rebuilt: boolean;
  durationMs?: number | null;
  containerName?: string | null;
  hostPort?: number | null;
  upstream?: string | null;
  message?: string;
  reason?: string | null;
}

export interface SmartPackCacheMount {
  id: string;
  target: string;
  sharing?: string;
}

export interface SmartPackResourceLimits {
  hostMemoryMb?: number;
  hostCpus?: number;
  buildMemoryMb?: number;
  buildCpus?: number;
  memory?: string;
  cpus?: number | string;
  maxParallelStages?: number;
  reservedHeadroomMb?: number;
  dockerBuildFlags?: string[];
  zstdChunked?: boolean;
  zstdChunkedFlags?: string[];
}

export interface SmartPackDockerignore {
  implicit: boolean;
  mergedWithExisting: boolean;
  patterns: string[];
  excludedCount: number;
  content: string;
}

export interface SmartPackPlanResult {
  schemaVersion?: string;
  stack: string;
  label?: string;
  runtime?: string | null;
  runtimeVersion?: string | null;
  packageManager?: string | null;
  detectedSignals?: string[];
  containerPort?: number | null;
  port?: number | null;
  baseImage?: string | null;
  runtimeImage?: string | null;
  aptPackages?: string[];
  apkPackages?: string[];
  cacheMounts?: Array<SmartPackCacheMount | string>;
  installCommand?: string | null;
  buildCommand?: string | null;
  startCommand?: string[] | string | null;
  layers?: Array<{ index: number; name: string; from: string; stepCount: number; cached: boolean }>;
  ociExport?: { zstdChunked: boolean; compression: string; flags: string[] };
  zstdChunked?: boolean;
  resourceLimits?: SmartPackResourceLimits | null;
  limits?: { memoryMb?: number; cpus?: number | string } | null;
  dockerignore?: SmartPackDockerignore | string[];
  warnings?: string[];
  deterministicHash?: string;
  dockerfile?: string | null;
}

export interface DirectPushStep {
  step: number;
  id: string;
  description: string;
  bin: string;
  argv: string[];
  shell: boolean;
  skippedForLocal?: boolean;
}

export interface DirectPushPlanResult {
  schemaVersion: string;
  protocol: string;
  zeroRegistryRequired: boolean;
  deltaTransfer: boolean;
  shell: boolean;
  direction: 'push' | 'pull';
  serverId: string;
  sourceImage: string;
  repository: string;
  tag: string;
  targetImageRef: string;
  tunnel: {
    sshHost: string;
    sshUser: string;
    sshPort: number;
    localPort: number;
    remotePort: number;
    loopbackOnly: boolean;
    forwardFlag: string;
  };
  steps: DirectPushStep[];
}

export interface EdgeTunnelRecord {
  id: string;
  name: string;
  hostname?: string | null;
  targetHost: string;
  targetPort: number;
  tokenPreview?: string;
  revoked?: boolean;
  status?: 'connected' | 'offline' | 'revoked' | string;
  connected?: boolean;
  activeStreams?: number;
  connectedAt?: string | null;
  lastHeartbeatAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface EdgeTunnelStatusResult {
  enabled?: boolean;
  protocol?: string;
  totalTunnels?: number;
  activeTunnels?: number;
  connectedTunnels?: number;
  connectedAgents?: number;
  activeStreams?: number;
  totalRequestsForwarded?: number;
  totalBytesIn?: number;
  totalBytesOut?: number;
  rejectedAuthCount?: number;
  tunnels?: EdgeTunnelRecord[];
}

export interface EdgeTunnelCreateResult extends EdgeTunnelRecord {
  token: string;
}

export interface CoolifyStreamPlanResult {
  schemaVersion?: string;
  totalStreams?: number;
  databases?: Array<Record<string, unknown>>;
  volumes?: Array<Record<string, unknown>>;
  steps?: Array<Record<string, unknown>>;
  warnings?: string[];
  [key: string]: unknown;
}

export interface EditionStatusResult {
  edition: 'oss' | 'pro' | 'enterprise' | string;
  licensed?: boolean;
  licensee?: string | null;
  expiresAt?: string | null;
  features?: Record<string, boolean>;
}

export interface OtlpStatusResult {
  enabled: boolean;
  endpoint: string;
  serviceName: string;
  protocol?: string;
  bufferedSpans?: number;
  maxBufferSize?: number;
  totalExported?: number;
  totalFailed?: number;
  circuitOpen?: boolean;
  circuitState?: string;
  lastFlushAt?: string | null;
  lastError?: string | null;
  headersRedacted?: Record<string, string>;
  hasAuthHeader?: boolean;
}

export interface ReleaseAttestationResult {
  projectId: string;
  revision: string;
  keyId?: string;
  predicateType?: string;
  subjectDigest?: string;
  envelope: Record<string, unknown>;
  statement?: {
    predicateType?: string;
    subject?: Array<{ name?: string; digest?: { sha256?: string } }>;
  };
  createdAt?: string;
}

export interface AttestationVerifyResult {
  valid: boolean;
  keyId?: string;
  predicateType?: string;
  subjectDigest?: string;
  statement?: {
    predicateType?: string;
    subject?: Array<{ name?: string; digest?: { sha256?: string } }>;
  };
  reason?: string | null;
}

export interface MigrationPlanResult {
  command: string;
  argv: string[];
  snapshotRequired: boolean;
  lockKey: string;
  timeoutMs: number;
  abortCutoverOnFailure: boolean;
  dockerArgs?: string[];
  shell?: boolean;
}

export interface WasmInvokeResult {
  ok?: boolean;
  status: number;
  headers?: Record<string, string>;
  body?: string;
  result?: number | string;
  execMs: number;
  memoryBytes?: number;
  engine?: string;
}

export interface TimeMachineCheckpoint {
  id: string;
  projectId: string;
  label?: string;
  actor?: string;
  sha256: string;
  imageTag?: string | null;
  envCount?: number;
  domainsCount?: number;
  cronsCount?: number;
  dbLinksCount?: number;
  counts?: { envVars?: number; envKeys?: number; domains?: number; crons?: number; dbLinks?: number; databases?: number };
  state?: {
    imageTag?: string | null;
    envCount?: number;
    domains?: unknown[];
    crons?: unknown[];
    dbLinks?: string[];
  };
  snapshot?: {
    imageTag?: string | null;
    envKeys?: string[];
    domains?: unknown[];
    crons?: unknown[];
    linkedDatabaseIds?: string[];
  };
  createdAt: string;
}

export interface TimeMachineRestoreMutationsObject {
  projectFields?: string[];
  imageTagChanged?: boolean;
  envKeysAdded?: string[];
  envKeysRemoved?: string[];
  envKeysChanged?: string[];
  domainsToAdd?: string[];
  domainsToRemove?: string[];
  domainsToUpdate?: string[];
  cronsToAdd?: string[];
  cronsToRemove?: string[];
  cronsToUpdate?: string[];
}

export interface TimeMachineRestoreResult {
  dryRun: boolean;
  restored?: boolean;
  checkpointId: string;
  safetyCheckpointId?: string | null;
  summary?: string;
  diff?: {
    changed?: boolean;
    imageChanged?: boolean;
    imageTag?: { changed?: boolean };
    configChanges?: Record<string, unknown>;
    envKeysAdded?: string[];
    envKeysRemoved?: string[];
    envKeysChanged?: string[];
    domainsChanged?: boolean;
    cronsChanged?: boolean;
  };
  mutations?: string[] | TimeMachineRestoreMutationsObject;
}

export type ShadowReplayBlocker = string | {
  code?: string;
  message?: string;
  actual?: number;
  threshold?: number;
};

export interface ShadowReplayReport {
  id?: string;
  pass: boolean;
  verdict: 'PROMOTE' | 'BLOCK_CUTOVER' | string;
  blockers: ShadowReplayBlocker[];
  summary: {
    totalRequests: number;
    baselineP95Ms?: number;
    candidateP95Ms?: number;
    baselineLatencyMs?: { p50?: number; p95?: number; p99?: number; avg?: number };
    candidateLatencyMs?: { p50?: number; p95?: number; p99?: number; avg?: number };
    latencyRatio?: number;
    latencyRatioP95?: number;
    delta5xx?: number;
    statusMismatchPct?: number;
    schemaDriftCount?: number;
    breakingSchemaDriftCount?: number;
  };
  createdAt?: string;
}

export interface FinOpsRecommendation {
  id?: string;
  projectId?: string;
  projectName?: string;
  kind?: string;
  type?: string;
  severity?: string;
  title?: string;
  detail?: string;
  message?: string;
  currentMemoryMb?: number;
  observedPeakRamMb?: number;
  recommendedMemoryMb?: number;
  reclaimableRamMb?: number;
  estimatedMonthlySavingsUsd?: number;
}

export interface FinOpsComparison {
  monthlyCloudUsd: number;
  monthlySelfHostedUsd: number;
  monthlySavingsUsd?: number;
  annualSavingsUsd: number;
  savingsPct: number;
  recommendedVps?: {
    provider: string;
    name?: string;
    plan?: string;
    vcpus?: number;
    ramGb?: number;
    monthlyUsd: number;
    totalMonthlyUsd?: number;
    nodeCount?: number;
  } | string;
  cloudBreakdown?: Array<{ provider: string; label?: string; monthlyUsd: number }> | Record<string, number>;
  providers?: Record<string, number>;
  footnote?: string;
  pricingFootnotes?: string[];
}

export interface FinOpsReportResult {
  costComparison?: FinOpsComparison;
  comparison?: FinOpsComparison;
  cloudComparison?: FinOpsComparison;
  monthlyCloudUsd?: number;
  monthlySelfHostedUsd?: number;
  annualSavingsUsd?: number;
  savingsPct?: number;
  recommendedVps?: FinOpsComparison['recommendedVps'];
  recommendations?: FinOpsRecommendation[];
  footnote?: string;
  pricingFootnotes?: string[];
}

export interface TerminalTicketResult {
  ticket: string;
  expiresAt: string;
  wsPath: string;
  containerName: string;
  shell: string;
}

export interface TerminalSessionInfo {
  sessionId: string;
  projectId: string;
  containerName: string;
  shell: string;
  username?: string;
  connectedAt: string;
}

export interface BuildHealerMatch {
  code: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  rootCause: string;
  confidence: number;
  matchedLine?: string;
  patchPreview?: string;
  autoFixAction?: string;
}

export interface BuildHealerDiagnosis {
  matched: boolean;
  totalMatches: number;
  primary: BuildHealerMatch | null;
  matches: BuildHealerMatch[];
  analyzedLines?: number;
  analyzedMs?: number;
}

export interface BuildHealerApplyResult {
  ok?: boolean;
  dryRun: boolean;
  applied?: boolean;
  code?: string;
  title?: string;
  summary?: string;
  changes?: string[];
  mutationsSummary?: string[];
  patchPlan?: {
    envAdditions?: Record<string, string>;
    memoryLimitMb?: number | null;
    logDriver?: string | null;
    smartPackHint?: string | null;
  } | null;
}

export interface FleetMeshPeer {
  nodeId: string;
  name: string;
  meshIp: string;
  publicKey: string;
  endpoint?: string | null;
  listenPort?: number;
  role?: string;
  keyVersion?: number;
  keyRotatedAt?: string | null;
  privateKeyEncrypted?: boolean;
  status?: string;
}

export interface FleetMeshStatusResult {
  cidr: string;
  interfaceName: string;
  peerCount: number;
  peers: FleetMeshPeer[];
  firewallGuard?: {
    blocksPublicDbPorts: boolean;
    ufwBypassWarning?: string;
  };
}

export interface FleetMeshConfigEntry {
  nodeId: string;
  name?: string;
  meshIp?: string;
  wgConfig?: string;
  config?: string;
}

export interface FleetMeshPlanResult {
  cidr?: string;
  interfaceName?: string;
  dryRun?: boolean;
  configs?: FleetMeshConfigEntry[];
  wgConfigs?: FleetMeshConfigEntry[] | Record<string, string>;
  nodes?: FleetMeshConfigEntry[];
  firewallRules?: string[];
  firewallPlan?: string | string[] | { ufw?: string[]; nftables?: string[]; rules?: string[] };
  diff?: { added?: string[]; updated?: string[]; removed?: string[] };
}

export interface FleetMeshRotateResult {
  dryRun: boolean;
  rotated?: boolean;
  nodeId: string;
  keyVersion?: number;
  nextKeyVersion?: number;
  oldPublicKey?: string;
  newPublicKey?: string;
  previewNewPublicKey?: string;
  oldFingerprint?: string;
  newFingerprint?: string;
  previewNewFingerprint?: string;
  rolloutPlan?: string[] | string;
  rolloutSteps?: string[];
  summary?: string;
}

export interface EdgeShieldStatusResult {
  enabledCount: number;
  powEnabledCount: number;
  blockedPathRules: number | string[];
  blockedUaPatterns: number | string[];
  activeChallenges: number;
  defaultDifficulty?: number;
}

export interface EdgeShieldChallengeResult {
  challengeId: string;
  salt: string;
  difficulty: number;
  expiresAt?: string;
  algorithm: string;
  domain?: string;
  htmlPreviewBytes?: number;
}

export interface CronTimelineSlot {
  hour?: number;
  label?: string;
  isoHour?: string;
  count?: number;
  runs?: Array<{ name?: string; jobName?: string; projectId?: string; at?: string }>;
  hasCollision?: boolean;
  collisions?: number;
}

export interface CronTimelineResult {
  hours: number;
  totalRuns?: number;
  slots: CronTimelineSlot[];
  collisionWarnings?: Array<string | { windowStart?: string; hour?: number; count?: number; jobs?: string[]; message?: string }>;
}

export interface HeartbeatMonitor {
  id: string;
  name: string;
  projectId?: string | null;
  token: string;
  pingUrl?: string;
  periodSec: number;
  graceSec: number;
  status: 'new' | 'up' | 'down' | 'missed' | string;
  lastPingAt?: string | null;
  lastDurationMs?: number | null;
}

export interface PasskeyRecord {
  id: string;
  userId?: string;
  label: string;
  alg?: number | string;
  signCount?: number;
  createdAt?: string;
  lastUsedAt?: string | null;
}

export interface PasskeyRegisterBeginResult {
  challengeId: string;
  challenge: string;
  rpId?: string;
  publicKey?: Record<string, unknown>;
  demoRegistered?: PasskeyRecord;
}

export interface SecretLeaseRecord {
  id: string;
  projectId?: string | null;
  secretKey: string;
  scope?: string;
  kind?: 'lease' | 'break_glass' | string;
  reason?: string;
  issuedBy?: string;
  ttlSec?: number;
  expiresAt: string;
  revoked?: boolean;
  createdAt?: string;
}

export interface SecretRotationAuditResult {
  totalKeys: number;
  staleCount: number;
  maxAgeDays?: number;
  staleKeys?: Array<{ projectId?: string; projectName?: string; key: string; ageDays?: number }>;
}

export interface CveFinding {
  id: string;
  packageName?: string;
  purl?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  summary?: string;
  fixedVersion?: string | null;
}

export interface CveScanResult {
  scannedPackages: number;
  vulnerablePackages: number;
  totalVulnerabilities: number;
  bySeverity?: { critical?: number; high?: number; medium?: number; low?: number };
  offline?: boolean;
  cached?: boolean;
  scannedAt?: string;
  findings?: CveFinding[];
}

export interface IacExportResult {
  ok?: boolean;
  format: string;
  generatedAt?: string;
  files: Record<string, string>;
  stats?: { projects?: number; databases?: number; domains?: number; crons?: number; meshPeers?: number };
  secretsRedactedCount?: number;
}

export interface ProjectDriftDiff {
  field: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  declared: unknown;
  actual: unknown;
  message?: string;
}

export interface ProjectDriftResult {
  ok?: boolean;
  drifted: boolean;
  runtimeOffline?: boolean;
  severity?: string;
  checkedAt?: string;
  declaredEnvKeyHash?: string;
  actualEnvKeyHash?: string;
  diffs?: ProjectDriftDiff[];
  reconcilePlan?: {
    dryRunDefault?: boolean;
    actionCount?: number;
    actions?: Array<string | { action?: string; field?: string; summary?: string }>;
  };
}

export interface MaintenanceWindowRecord {
  id: string;
  title: string;
  targetIds?: string[];
  kind: 'once' | 'recurring' | string;
  startAt: string;
  durationMin: number;
  intervalDays?: number;
  active?: boolean;
}

export interface StatusIncidentRecord {
  id: string;
  title: string;
  severity: 'minor' | 'major' | 'critical' | string;
  status: 'investigating' | 'identified' | 'monitoring' | 'resolved' | string;
  affectedIds?: string[];
  message?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface GeoFailoverPlanResult {
  domain: string;
  primaryIp: string;
  secondaryIp: string;
  consecutiveFailures?: number;
  ttlSec?: number;
  strategy?: string;
  summary?: string;
  steps?: string[];
  dnsPatch?: Record<string, unknown>;
}

// --- Cycle-9 Pioneer Types (White-Label Brand, Standard-Webhooks DLQ, DB Studio, Post-MinIO S3, Agency Quotas & Billing Ledger) ---

export interface BrandThemeConfig {
  brandName: string;
  tagline: string;
  accentHex: string;
  logoUrl: string;
  supportUrl: string;
  hidePoweredBy: boolean;
  updatedAt?: string | null;
}

export interface OutboundWebhookSubscription {
  id: string;
  url: string;
  events: string[];
  description?: string;
  enabled: boolean;
  secretPreview?: string;
  maskedSecret?: string;
  hasSecondarySecret?: boolean;
  secondaryExpiresAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface WebhookSecretRotateResult {
  ok?: boolean;
  subscription?: OutboundWebhookSubscription;
  secret?: string;
  primarySecret?: string;
  secretPreview?: string;
  graceSec?: number;
  secondaryExpiresAt?: string | null;
}

export interface WebhookDlqEntry {
  id: string;
  subscriptionId?: string;
  url: string;
  eventType: string;
  status?: 'failed' | 'replayed' | 'pending' | string;
  attempts?: number;
  lastError?: string;
  error?: string;
  httpStatus?: number | null;
  lastStatusCode?: number | null;
  createdAt?: string;
  replayedAt?: string | null;
}

export interface WebhookDlqReplayResult {
  ok?: boolean;
  replayed?: boolean;
  delivered?: boolean;
  entry?: WebhookDlqEntry;
  error?: string;
}

export interface DbStudioSqlResult {
  ok?: boolean;
  dryRunPreview?: boolean;
  readOnlyEnforced?: boolean;
  engine?: string;
  wrappedSql?: string;
  sanitizedQuery?: string;
  statementTimeoutMs?: number;
  rowCap?: number;
  rows?: Array<Record<string, unknown>>;
  columns?: string[];
  rowCount?: number;
  durationMs?: number;
  error?: string;
}

export interface DbStudioRedisResult {
  ok?: boolean;
  dryRunPreview?: boolean;
  readOnlyEnforced?: boolean;
  command?: string;
  normalizedArgv?: string[];
  clampedCount?: number | null;
  countClamped?: boolean;
  maxScanCount?: number;
  result?: unknown;
  output?: string;
  error?: string;
}

export interface DbStudioBloatTable {
  table?: string;
  tableName?: string;
  liveTuples?: number;
  deadTuples?: number;
  deadTupleRatio?: number;
  deadPct?: number;
  sizeBytes?: number;
  recommendation?: string;
}

export interface DbStudioBloatResult {
  ok?: boolean;
  checkedTables: number;
  bloatedTables?: DbStudioBloatTable[];
  unusedIndexes?: Array<{ indexName?: string; tableName?: string; sizeBytes?: number; idxScan?: number }>;
  recommendations?: Array<string | { message?: string; table?: string; action?: string }>;
}

export interface S3StoragePreset {
  id: string;
  name?: string;
  label?: string;
  image: string;
  licence?: string;
  license?: string;
  bindAddress?: string;
  defaultPort?: number;
  s3Port?: number;
  memoryMb?: number;
  ramEstimateMb?: number;
  summary?: string;
  description?: string;
  highlights?: string[];
  region?: string;
}

export interface S3PresignResult {
  ok?: boolean;
  url: string;
  method: string;
  bucket: string;
  key: string;
  expiresIn: number;
  expiresAt?: string;
  algorithm?: string;
  signature?: string;
}

export interface TenantQuotaSpec {
  projectId?: string;
  containers?: number;
  memoryMb?: number;
  cpuCores?: number;
  storageGb?: number;
  bandwidthGbMo?: number;
  updatedAt?: string;
}

export interface BillingLedgerProjectRow {
  projectId: string;
  projectName?: string;
  name?: string;
  cpuHours: number;
  ramGbHours: number;
  storageGb: number;
  bandwidthGb: number;
  estimatedCostUsd: number;
  containersCount?: number;
  memoryMb?: number;
  quota?: TenantQuotaSpec;
  quotaUtilizationPct?: number;
}

export interface BillingLedgerResult {
  ok?: boolean;
  periodDays?: number;
  generatedAt?: string;
  currency?: string;
  entries?: BillingLedgerProjectRow[];
  projects?: BillingLedgerProjectRow[];
  items?: BillingLedgerProjectRow[];
  rows?: BillingLedgerProjectRow[];
  totals?: {
    totalProjects?: number;
    totalDatabases?: number;
    cpuHours?: number;
    ramGbHours?: number;
    storageGb?: number;
    bandwidthGb?: number;
    estimatedCostUsd?: number;
  };
}
