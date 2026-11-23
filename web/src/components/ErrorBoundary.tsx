import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[60vh] flex items-center justify-center p-4 font-sans text-slate-900">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-7 max-w-md w-full text-center space-y-4">
            <h1 className="text-base font-semibold text-slate-900">Algo ha fallado en la interfaz</h1>
            <p className="text-xs text-slate-500 leading-relaxed">
              Ha ocurrido un error inesperado al renderizar esta vista. Puedes reintentar o recargar el panel.
            </p>
            <div className="flex items-center justify-center gap-2">
              <button
                type="button"
                className="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3.5 py-2 rounded-lg font-medium text-xs transition-colors cursor-pointer"
                onClick={() => this.setState({ hasError: false, error: undefined })}
              >
                Reintentar vista
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
