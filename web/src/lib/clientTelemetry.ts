import { getAuthToken } from './api';

export interface ClientErrorReport {
  source: 'error_boundary' | 'window_error' | 'unhandled_rejection';
  view?: string;
  errorName?: string;
  message: string;
  stack?: string;
  componentStack?: string;
}

const MAX_REPORTS_PER_SESSION = 5;
const DEDUP_WINDOW_MS = 5 * 60 * 1000;

let _currentView = 'unknown';
let _sentCount = 0;
let _handlersInstalled = false;
const _recentFingerprints = new Map<string, number>();

export function setTelemetryCurrentView(view: string): void {
  if (view && typeof view === 'string') {
    _currentView = view.slice(0, 32);
  }
}

export function getTelemetryCurrentView(): string {
  return _currentView;
}

function getViewportBucket(): string {
  try {
    const w = window.innerWidth || 0;
    if (w < 640) return 'mobile';
    if (w < 1024) return 'tablet';
    if (w < 1440) return 'desktop';
    return 'wide';
  } catch {
    return 'unknown';
  }
}

function isNoisyBrowserError(message: string): boolean {
  const m = message.toLowerCase();
  return (
    m.includes('resizeobserver loop') ||
    m.includes('script error.') ||
    m.includes('loading chunk') && m.includes('abort')
  );
}

/**
 * Envía un informe anónimo de error de interfaz al daemon local (`/api/telemetry/client-error`),
 * que vuelve a sanear el payload y solo lo reenvía si la telemetría está activa.
 * Nunca lanza excepciones ni bloquea la interfaz.
 */
export function reportClientError(report: ClientErrorReport): void {
  try {
    if (_sentCount >= MAX_REPORTS_PER_SESSION) return;
    const message = String(report.message || '').trim().slice(0, 400);
    if (!message || isNoisyBrowserError(message)) return;

    const view = report.view || _currentView || 'unknown';
    const errorName = String(report.errorName || 'Error').slice(0, 60);
    const dedupKey = `${report.source}|${view}|${errorName}|${message.slice(0, 120)}`;
    const now = Date.now();
    const prev = _recentFingerprints.get(dedupKey);
    if (prev && now - prev < DEDUP_WINDOW_MS) return;
    _recentFingerprints.set(dedupKey, now);
    _sentCount++;

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = getAuthToken();
    if (token) headers.Authorization = `Bearer ${token}`;

    const body = JSON.stringify({
      source: report.source,
      view,
      errorName,
      message,
      stack: typeof report.stack === 'string' ? report.stack.slice(0, 2000) : '',
      componentStack: typeof report.componentStack === 'string' ? report.componentStack.slice(0, 1500) : '',
      viewportBucket: getViewportBucket(),
    });

    void window.fetch('/api/telemetry/client-error', {
      method: 'POST',
      headers,
      body,
      keepalive: true,
    }).catch(() => {
      // Silencioso: la telemetría jamás debe provocar errores en cascada
    });
  } catch {
    // Nunca romper el flujo del usuario
  }
}

/** Instala listeners globales de errores JS no capturados y promesas rechazadas. */
export function installGlobalErrorHandlers(): void {
  if (_handlersInstalled || typeof window === 'undefined') return;
  _handlersInstalled = true;

  window.addEventListener('error', (event: ErrorEvent) => {
    const err = event.error as Error | undefined;
    const msg = (err && err.message) || event.message || '';
    if (!msg) return;
    reportClientError({
      source: 'window_error',
      errorName: (err && err.name) || 'Error',
      message: msg,
      stack: err?.stack || `${event.filename || 'bundle'}:${event.lineno || 0}:${event.colno || 0}`,
    });
  });

  window.addEventListener('unhandledrejection', (event: PromiseRejectionEvent) => {
    const reason = event.reason;
    const isErr = reason instanceof Error;
    const msg = isErr
      ? reason.message
      : typeof reason === 'string'
        ? reason
        : reason && typeof reason === 'object' && 'message' in reason
          ? String((reason as { message?: unknown }).message || '')
          : 'Unhandled promise rejection';
    if (!msg) return;
    reportClientError({
      source: 'unhandled_rejection',
      errorName: isErr ? reason.name : 'UnhandledRejection',
      message: msg,
      stack: isErr ? reason.stack : '',
    });
  });
}
