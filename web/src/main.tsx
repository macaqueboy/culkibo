import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary.tsx'
import { installGlobalErrorHandlers } from './lib/clientTelemetry.ts'
import { isDemoMode, loadDemoRuntime } from './lib/api.ts'

installGlobalErrorHandlers()

async function bootstrap() {
  if (isDemoMode()) {
    await loadDemoRuntime()
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>,
  )
}

void bootstrap()
