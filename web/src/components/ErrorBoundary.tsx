import { Component, type ErrorInfo, type ReactNode } from 'react';
import { getTelemetryCurrentView, reportClientError } from '../lib/clientTelemetry';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
  componentStack?: string;
  retryCount: number;
  copied: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    retryCount: 0,
    copied: false,
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error, copied: false };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
    const componentStack = errorInfo?.componentStack || '';
    this.setState({ componentStack });
    reportClientError({
      source: 'error_boundary',
      view: getTelemetryCurrentView(),
      errorName: error?.name || 'Error',
      message: error?.message || 'Error de renderizado en React',
      stack: error?.stack || '',
      componentStack,
    });
  }

  private handleCopyDiagnostic = async () => {
    const summary = [
      `Culkibo UI Diagnostic (${new Date().toISOString()})`,
      `Vista: ${getTelemetryCurrentView()}`,
      `Error: ${this.state.error?.name || 'Error'}: ${this.state.error?.message || 'Desconocido'}`,
      this.state.error?.stack ? `Stack:\n${this.state.error.stack.split('\n').slice(0, 6).join('\n')}` : '',
    ].filter(Boolean).join('\n');
    try {
      await navigator.clipboard.writeText(summary);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2500);
    } catch {
      // portapapeles bloqueado
    }
  };

  private handleRetry = () => {
    this.setState((prev) => ({
      hasError: false,
      error: undefined,
      componentStack: undefined,
      retryCount: prev.retryCount + 1,
      copied: false,
    }));
  };

  public render() {
    if (this.state.hasError) {
      const canRetryInline = this.state.retryCount < 2;
      return (
        <div className="min-h-[60vh] flex items-center justify-center p-4 font-sans text-slate-900">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-7 max-w-md w-full text-center space-y-4">
            <h1 className="text-base font-semibold text-slate-900">Algo ha fallado en la interfaz</h1>
            <p className="text-xs text-slate-500 leading-relaxed">
              {canRetryInline
                ? 'Ha ocurrido un error inesperado al renderizar esta vista. Puedes reintentar o recargar el panel.'
                : 'El error se ha repetido al reintentar esta vista. Recarga el panel para restablecer el estado.'}
            </p>
            {this.state.error?.message && (
              <div className="text-[11px] font-mono text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-left break-words">
                {this.state.error.message.slice(0, 220)}
              </div>
            )}
            <div className="flex flex-wrap items-center justify-center gap-2">
              {canRetryInline && (
                <button
                  type="button"
                  className="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3.5 py-2 rounded-lg font-medium text-xs transition-colors cursor-pointer"
                  onClick={this.handleRetry}
                >
                  Reintentar vista
                </button>
              )}
              <button
                type="button"
                className="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3.5 py-2 rounded-lg font-medium text-xs transition-colors cursor-pointer"
                onClick={() => void this.handleCopyDiagnostic()}
              >
                {this.state.copied ? 'Diagnóstico copiado' : 'Copiar diagnóstico'}
              </button>
              <button
                type="button"
                className="bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-lg font-medium text-xs transition-colors cursor-pointer"
                onClick={() => window.location.reload()}
              >
                Recargar el panel
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
