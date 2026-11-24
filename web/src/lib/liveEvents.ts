import type { LogEntry, McpAuditEntry, Project } from './api';

export interface SyncAppliedEvent {
  projectId: string;
  seq: number;
  written: number;
  deleted: number;
  dedupSkipped: number;
  bytesSynced?: number;
  applyMs: number;
  mode: string;
  reason?: string;
  serverDigest?: string;
  timestamp?: string;
}

export interface SyncRollbackEvent {
  projectId: string;
  restoredFiles: string[];
  durationMs: number;
  steps?: number;
}

export interface SyncClientEvent {
  projectId: string;
  connected: boolean;
  connectedClients: number;
}

export interface ServiceProgressEvent {
  id: string;
  status?: string;
  progress?: {
    step: string;
    label: string;
    stepIndex: number;
    totalSteps: number;
    message?: string | null;
    failed?: boolean;
  } | null;
}

export interface ProjectChangeEvent {
  action: 'update' | 'created' | 'deleted';
  project?: Project;
  id?: string;
}

export interface CronRunEvent {
  jobId: string;
  projectId: string;
  run: {
    id: string;
    startedAt: string;
    finishedAt?: string | null;
    durationMs?: number | null;
    status: string;
    exitCode?: number | null;
    output?: string;
    trigger?: string;
  };
}

export interface PreviewLiveEvent {
  projectId: string;
  key: string;
  action?: string;
  status?: string;
  url?: string | null;
  branch?: string | null;
  prNumber?: number | null;
}

type Handler<T> = (payload: T) => void;

/**
 * Bus pub-sub fuera del estado raíz de React para todos los eventos en directo
 * que entran por WebSocket (`/ws`).
 *
 * Evita que cada log, frame de Live Sync, llamada MCP o tick de progreso
 * provoque un re-render del árbol completo en `App.tsx`.
 */
class LiveEventsBus {
  private logHandlers = new Set<Handler<LogEntry>>();
  private syncAppliedHandlers = new Set<Handler<SyncAppliedEvent>>();
  private syncRollbackHandlers = new Set<Handler<SyncRollbackEvent>>();
  private syncClientHandlers = new Set<Handler<SyncClientEvent>>();
  private mcpCallHandlers = new Set<Handler<McpAuditEntry>>();
  private serviceProgressHandlers = new Set<Handler<ServiceProgressEvent>>();
  private serviceInstalledHandlers = new Set<Handler<any>>();
  private serviceFailedHandlers = new Set<Handler<any>>();
  private projectChangeHandlers = new Set<Handler<ProjectChangeEvent>>();
  private cronRunHandlers = new Set<Handler<CronRunEvent>>();
  private previewEventHandlers = new Set<Handler<PreviewLiveEvent>>();

  private subscribe<T>(set: Set<Handler<T>>, handler: Handler<T>): () => void {
    set.add(handler);
    return () => { set.delete(handler); };
  }

  private dispatch<T>(set: Set<Handler<T>>, payload: T): void {
    for (const handler of set) {
      try {
        handler(payload);
      } catch {
        // Ningún suscriptor puede tumbar el bucle de recepción del WebSocket
      }
    }
  }

  onLog(handler: Handler<LogEntry>) { return this.subscribe(this.logHandlers, handler); }
  emitLog(payload: LogEntry) { this.dispatch(this.logHandlers, payload); }

  onSyncApplied(handler: Handler<SyncAppliedEvent>) { return this.subscribe(this.syncAppliedHandlers, handler); }
  emitSyncApplied(payload: SyncAppliedEvent) { this.dispatch(this.syncAppliedHandlers, payload); }

  onSyncRollback(handler: Handler<SyncRollbackEvent>) { return this.subscribe(this.syncRollbackHandlers, handler); }
  emitSyncRollback(payload: SyncRollbackEvent) { this.dispatch(this.syncRollbackHandlers, payload); }

  onSyncClient(handler: Handler<SyncClientEvent>) { return this.subscribe(this.syncClientHandlers, handler); }
  emitSyncClient(payload: SyncClientEvent) { this.dispatch(this.syncClientHandlers, payload); }

  onMcpCall(handler: Handler<McpAuditEntry>) { return this.subscribe(this.mcpCallHandlers, handler); }
  emitMcpCall(payload: McpAuditEntry) { this.dispatch(this.mcpCallHandlers, payload); }

  onServiceProgress(handler: Handler<ServiceProgressEvent>) { return this.subscribe(this.serviceProgressHandlers, handler); }
  emitServiceProgress(payload: ServiceProgressEvent) { this.dispatch(this.serviceProgressHandlers, payload); }

  onServiceInstalled(handler: Handler<any>) { return this.subscribe(this.serviceInstalledHandlers, handler); }
  emitServiceInstalled(payload: any) { this.dispatch(this.serviceInstalledHandlers, payload); }

  onServiceFailed(handler: Handler<any>) { return this.subscribe(this.serviceFailedHandlers, handler); }
  emitServiceFailed(payload: any) { this.dispatch(this.serviceFailedHandlers, payload); }

  onProjectChange(handler: Handler<ProjectChangeEvent>) { return this.subscribe(this.projectChangeHandlers, handler); }
  emitProjectChange(payload: ProjectChangeEvent) { this.dispatch(this.projectChangeHandlers, payload); }

  onCronRun(handler: Handler<CronRunEvent>) { return this.subscribe(this.cronRunHandlers, handler); }
  emitCronRun(payload: CronRunEvent) { this.dispatch(this.cronRunHandlers, payload); }

  onPreviewEvent(handler: Handler<PreviewLiveEvent>) { return this.subscribe(this.previewEventHandlers, handler); }
  emitPreviewEvent(payload: PreviewLiveEvent) { this.dispatch(this.previewEventHandlers, payload); }
}

export const liveEvents = new LiveEventsBus();
