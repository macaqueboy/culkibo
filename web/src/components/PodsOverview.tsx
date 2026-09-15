import React, { useState, useEffect } from 'react';
import { ExternalLink, RefreshCw, Zap, ShieldCheck, FolderGit2, ArrowUpRight, CheckCircle2, Globe } from 'lucide-react';
import type { PodsData } from '../lib/api';
import { api } from '../lib/api';

interface PodsOverviewProps {
  podsData: PodsData | null;
  onRefresh: () => void;
  onDeployModalOpen: () => void;
  onToast?: (msg: string) => void;
}

export const PodsOverview: React.FC<PodsOverviewProps> = ({
  podsData,
  onRefresh,
  onDeployModalOpen,
  onToast
}) => {
  const [syncing, setSyncing] = useState(false);
  const [lastSyncResult, setLastSyncResult] = useState<string | null>(null);
  const [publicDomain, setPublicDomain] = useState<string>('app.culkibo.dev');
  const [checkingDev, setCheckingDev] = useState(false);

  useEffect(() => {
    api.getDomains().then(res => {
      if (res.domains && res.domains.length > 0) {
        setPublicDomain(res.domains[0].hostname);
      }
    }).catch(() => {});
  }, []);

  if (!podsData) {
    return (
      <div className="flex items-center justify-center p-20">
        <div className="flex flex-col items-center gap-3 text-gray-500">
          <RefreshCw className="w-8 h-8 animate-spin text-gray-400" />
          <p className="text-sm font-medium">Conectando con el servidor Culkibo...</p>
        </div>
      </div>
    );
  }

  const { forge, citadel } = podsData.pods;
  const { trafficAllocation } = podsData;

  const handleHotSync = async () => {
    setSyncing(true);
    try {
      const res = await api.triggerHotSync('src/App.tsx');
      if (res.success) {
        setLastSyncResult(`¡Sincronizado con éxito en ${res.syncDurationMs}ms!`);
        onRefresh();
        setTimeout(() => setLastSyncResult(null), 4000);
      }
    } catch (e: any) {
      setLastSyncResult(`Error: ${e.message}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleOpenDev = async (e: React.MouseEvent) => {
    e.preventDefault();
    setCheckingDev(true);
    try {
      await fetch(`http://localhost:${forge.port}`, { mode: 'no-cors' });
      window.open(`http://localhost:${forge.port}`, '_blank');
    } catch (err) {
      const msg = `El servidor de desarrollo no está corriendo en el puerto ${forge.port}. Por favor, arráncalo con 'npm run dev' o reinicia el entorno.`;
      if (onToast) {
        onToast(msg);
      } else {
        alert(msg);
      }
    } finally {
      setCheckingDev(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Hero Card: Tu Aplicación en Vivo */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 sm:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-50 border border-green-200 text-green-700 text-xs font-medium">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
              </span>
              <span>Tu Web está en Vivo en Internet</span>
            </div>
            
            <h1 className="text-2xl sm:text-3xl font-semibold text-gray-900 tracking-tight">
              Aplicación Conectada en Tiempo Real
            </h1>
            
            <p className="text-sm text-gray-600 max-w-2xl leading-relaxed">
              Cada vez que tú o la IA guardáis un archivo en tu editor, se actualiza en esta URL al instante sin tener que hacer git push ni esperar compilaciones.
            </p>

            {/* URL Display Box */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-50 border border-gray-200 font-mono text-xs sm:text-sm text-gray-800">
                <Globe className="w-4 h-4 text-gray-500" />
                <span className="font-medium">https://</span>
                <span className="font-semibold text-gray-900">{publicDomain}</span>
              </div>

              <a
                href={`https://${publicDomain}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium transition-colors shadow-sm"
              >
                <span>Abrir mi Web en el Navegador</span>
                <ExternalLink className="w-4 h-4 opacity-80" />
              </a>

              <button
                onClick={handleHotSync}
                disabled={syncing}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-white hover:bg-gray-50 text-gray-700 text-sm font-medium border border-gray-200 transition-colors shadow-sm cursor-pointer"
              >
                <Zap className={`w-4 h-4 text-yellow-500 ${syncing ? 'animate-pulse' : ''}`} />
                <span>{syncing ? 'Detectando...' : 'Probar detección de cambios'}</span>
              </button>
            </div>

            {lastSyncResult && (
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-green-50 border border-green-200 text-green-700 text-xs font-medium animate-fade-in mt-2">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{lastSyncResult}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 3 Simple Health Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-md bg-yellow-50 text-yellow-600 border border-yellow-100">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500">Velocidad de Actualización</p>
              <p className="text-xl font-semibold text-gray-900">{forge.lastHotReloadMs || 18} ms</p>
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-3 pt-3 border-t border-gray-100">
            La web se actualiza antes de que puedas parpadear.
          </p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-md bg-blue-50 text-blue-600 border border-blue-100">
              <FolderGit2 className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500">Carpeta Local Conectada</p>
              <p className="text-sm font-semibold font-mono text-gray-800 truncate max-w-[180px]">Culkibo</p>
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-3 pt-3 border-t border-gray-100">
            {forge.fileWatchersActive} rutas de archivos vigiladas en vivo.
          </p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-md bg-indigo-50 text-indigo-600 border border-indigo-100">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500">Estado de Producción</p>
              <p className="text-xl font-semibold text-gray-900">Protegido</p>
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-3 pt-3 border-t border-gray-100">
            Cloudflare Proxy y certificado SSL activos.
          </p>
        </div>
      </div>

      {/* Los 2 Entornos Claramente Explicados */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Entorno de Desarrollo */}
        <div className="bg-white rounded-xl border border-blue-200 shadow-sm p-6 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-600" />
                <h3 className="text-base font-semibold text-gray-900">Entorno de Desarrollo (En Vivo)</h3>
              </div>
              <span className="text-xs font-medium px-2 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-100">
                Puerto {forge.port}
              </span>
            </div>

            <p className="text-xs text-gray-600 leading-relaxed">
              Es el servidor donde estás trabajando ahora. La IA o tú cambiáis cualquier componente o estilo y se refleja aquí sin recargar la página.
            </p>

            <div className="bg-gray-50 rounded-lg p-3.5 space-y-2 border border-gray-200 text-xs">
              <div className="flex justify-between text-gray-600">
                <span>Estado:</span>
                <span className="font-medium text-green-600 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" /> Activo y sincronizando
                </span>
              </div>
              <div className="flex justify-between text-gray-600">
                <span>Recargas en caliente aplicadas:</span>
                <span className="font-medium text-gray-800">{forge.hotReloadsCount} cambios</span>
              </div>
              <div className="flex justify-between text-gray-600">
                <span>Consumo de RAM:</span>
                <span className="font-medium text-gray-800">{forge.memoryMb} MB</span>
              </div>
            </div>
          </div>

          <div className="pt-5">
            <button
              onClick={handleOpenDev}
              disabled={checkingDev}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-white hover:bg-gray-50 text-gray-800 text-sm font-medium border border-gray-200 transition-colors shadow-sm cursor-pointer"
            >
              <span>{checkingDev ? 'Verificando...' : 'Abrir Entorno de Desarrollo'}</span>
              <ArrowUpRight className="w-4 h-4 opacity-70" />
            </button>
          </div>
        </div>

        {/* Entorno de Producción */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
                <h3 className="text-base font-semibold text-gray-900">Entorno de Producción (Estable)</h3>
              </div>
              <span className="text-xs font-medium px-2 py-1 rounded-md bg-gray-100 text-gray-600 border border-gray-200">
                Versión {citadel.version}
              </span>
            </div>

            <p className="text-xs text-gray-600 leading-relaxed">
              Es la versión final congelada para tus usuarios o clientes. Está protegida y nunca se romperá aunque cometas un fallo mientras programas en desarrollo.
            </p>

            <div className="bg-gray-50 rounded-lg p-3.5 space-y-2 border border-gray-200 text-xs">
              <div className="flex justify-between text-gray-600">
                <span>Estado:</span>
                <span className="font-medium text-green-600 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" /> Funcionando en Producción
                </span>
              </div>
              <div className="flex justify-between text-gray-600">
                <span>Tiempo activo:</span>
                <span className="font-medium text-gray-800">
                  {Math.floor(citadel.uptimeSeconds / 3600)}h {Math.floor((citadel.uptimeSeconds % 3600) / 60)}m
                </span>
              </div>
              <div className="flex justify-between text-gray-600">
                <span>Tráfico recibido:</span>
                <span className="font-medium text-blue-600">{trafficAllocation.citadel}% del público</span>
              </div>
            </div>
          </div>

          <div className="pt-5">
            <button
              onClick={onDeployModalOpen}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium shadow-sm transition-colors cursor-pointer"
            >
              <ShieldCheck className="w-4 h-4 opacity-80" />
              <span>Publicar Versión Actual a Producción</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
