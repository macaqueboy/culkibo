import React, { useState, useEffect } from 'react';
import { CheckCircle2, Shield, Folder, Server, ExternalLink, Unlink, Key, AlertCircle, RefreshCw, LogOut } from 'lucide-react';
import { api, clearAuthToken, getAuthToken, type GitHubStatus } from '../lib/api';
import { McpInspector } from './McpInspector';

export const SettingsView: React.FC = () => {
  const [sysStatus, setSysStatus] = useState<any>(null);
  const [githubStatus, setGithubStatus] = useState<GitHubStatus | null>(null);
  const [tokenInput, setTokenInput] = useState('');
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [githubError, setGithubError] = useState<string | null>(null);
  const [githubSuccess, setGithubSuccess] = useState<string | null>(null);

  const fetchStatus = () => {
    api.getSystemStatus().then(setSysStatus).catch(console.error);
    api.getGitHubStatus().then(setGithubStatus).catch(console.error);
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) return;
    setConnecting(true);
    setGithubError(null);
    setGithubSuccess(null);
    try {
      await api.connectGitHub(tokenInput.trim());
      setGithubSuccess('¡Cuenta de GitHub vinculada con éxito!');
      setTokenInput('');
      fetchStatus();
    } catch (err: any) {
      setGithubError(err.message || 'Error al conectar con GitHub');
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!window.confirm('¿Seguro que deseas desconectar tu cuenta de GitHub?')) return;
    setDisconnecting(true);
    setGithubError(null);
    setGithubSuccess(null);
    try {
      await api.disconnectGitHub();
      setGithubSuccess('Cuenta de GitHub desconectada');
      fetchStatus();
    } catch (err: any) {
      setGithubError(err.message || 'Error al desconectar');
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Platform Version & Status Card */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-blue-50 border border-blue-100 text-blue-600">
              <Server className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-900 tracking-tight">
                Servidor Culkibo v1.0.0
              </h2>
              <p className="text-sm text-slate-500">
                Plataforma de hosting y despliegue en tiempo real para desarrollo con IA
              </p>
            </div>
          </div>

          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            SERVIDOR ONLINE
          </span>
        </div>

        {sysStatus && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-slate-100 text-xs">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
              <span className="text-slate-500 block font-medium">Versión de Node:</span>
              <span className="text-slate-900 font-bold font-mono text-sm">{sysStatus.nodeVersion}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
              <span className="text-slate-500 block font-medium">Tiempo Activo:</span>
              <span className="text-slate-900 font-bold font-mono text-sm">{Math.floor(sysStatus.uptimeSeconds / 60)} min</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
              <span className="text-slate-500 block font-medium">Memoria RAM:</span>
              <span className="text-slate-900 font-bold font-mono text-sm">{sysStatus.memoryUsageMb} MB</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
              <span className="text-slate-500 block font-medium">Puerto de API:</span>
              <span className="text-blue-700 font-bold font-mono text-sm">3030</span>
            </div>
          </div>
        )}
      </div>

      {/* Conexión con GitHub */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-slate-900 text-white flex items-center justify-center">
              <svg className="w-6 h-6 fill-current" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-900 tracking-tight">
                Conexión con GitHub
              </h2>
              <p className="text-sm text-slate-500">
                Vincula tu cuenta para importar repositorios, autodetectar stacks y desplegar en tiempo real con cada push
              </p>
            </div>
          </div>

          {githubStatus?.connected ? (
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              CUENTA VINCULADA
            </span>
          ) : (
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200 flex items-center gap-1.5">
              NO CONECTADO
            </span>
          )}
        </div>

        {githubSuccess && (
          <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
            <span>{githubSuccess}</span>
          </div>
        )}

        {githubError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
            <span>{githubError}</span>
          </div>
        )}

        {githubStatus?.connected && githubStatus.user ? (
          <div className="space-y-4 pt-2">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <img
                  src={githubStatus.user.avatar_url}
                  alt={githubStatus.user.login}
                  className="w-12 h-12 rounded-full border-2 border-white shadow-sm"
                />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900">{githubStatus.user.name || githubStatus.user.login}</span>
                    <a
                      href={githubStatus.user.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-600 hover:underline flex items-center gap-0.5"
                    >
                      @{githubStatus.user.login}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <p className="text-xs text-slate-500">{githubStatus.user.bio || 'Desarrollador en GitHub'}</p>
                </div>
              </div>

              <button
                onClick={handleDisconnect}
                disabled={disconnecting}
                className="px-3.5 py-2 bg-white hover:bg-red-50 text-red-600 border border-red-200 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Unlink className="w-3.5 h-3.5" />
                {disconnecting ? 'Desconectando...' : 'Desconectar Cuenta'}
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                <span className="text-slate-500 block font-medium">Repos Públicos:</span>
                <span className="text-slate-900 font-bold font-mono text-sm">{githubStatus.user.public_repos}</span>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                <span className="text-slate-500 block font-medium">Repos Privados:</span>
                <span className="text-slate-900 font-bold font-mono text-sm">{githubStatus.user.total_private_repos}</span>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                <span className="text-slate-500 block font-medium">Token Activo:</span>
                <span className="text-blue-700 font-bold font-mono text-sm">{githubStatus.tokenMasked || '••••••••'}</span>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                <span className="text-slate-500 block font-medium">Estado Webhooks:</span>
                <span className="text-emerald-700 font-bold text-sm flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Listo
                </span>
              </div>
            </div>
          </div>
        ) : (
          <form onSubmit={handleConnect} className="space-y-4 pt-2">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-800">
                <Key className="w-4 h-4 text-blue-600" />
                Introduce tu GitHub Personal Access Token (PAT)
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Necesitas un token de acceso personal con permisos de lectura y administración de repositorios (<code>repo</code> y <code>read:user</code>).
              </p>

              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="flex-1 px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                />
                <button
                  type="submit"
                  disabled={connecting || !tokenInput.trim()}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
                >
                  {connecting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Verificando...
                    </>
                  ) : (
                    'Conectar con GitHub'
                  )}
                </button>
              </div>

              <div className="flex items-center justify-between text-xs pt-1">
                <a
                  href="https://github.com/settings/tokens/new?scopes=repo,read:user&description=Culkibo%20Cloud"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-blue-800 font-medium inline-flex items-center gap-1 hover:underline"
                >
                  Crear token en GitHub en 1 clic
                  <ExternalLink className="w-3 h-3" />
                </a>
                <span className="text-slate-400 text-[11px]">Se almacena en local de forma segura</span>
              </div>
            </div>
          </form>
        )}
      </div>

      {/* Feature Capabilities Matrix */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
 <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-600" />
          Módulos y Capacidades Activas
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 flex items-center justify-between">
            <div>
              <div className="text-slate-900 font-semibold text-sm">Detección de cambios en caliente</div>
              <div className="text-slate-500 text-xs mt-0.5">Inyección en caliente de archivos con Chokidar</div>
            </div>
            <span className="text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVO
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 flex items-center justify-between">
            <div>
              <div className="text-slate-900 font-semibold text-sm">Validación automática de dominio</div>
              <div className="text-slate-500 text-xs mt-0.5">Verificación automática de registros TXT y Let's Encrypt</div>
            </div>
            <span className="text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVO
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 flex items-center justify-between">
            <div>
              <div className="text-slate-900 font-semibold text-sm">Dominios de prueba automáticos</div>
              <div className="text-slate-500 text-xs mt-0.5">Dominios wildcard inmediatos sin configurar DNS</div>
            </div>
            <span className="text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVO
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80 flex items-center justify-between">
            <div>
              <div className="text-slate-900 font-semibold text-sm">Control Nativo por IA (MCP)</div>
              <div className="text-slate-500 text-xs mt-0.5">Autonomía de Cursor, Windsurf y Claude vía stdio y Streamable HTTP (revisión 2026-07-28)</div>
            </div>
            <span className="text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVO
            </span>
          </div>
        </div>
      </div>

      {/* Persistent Storage Directories */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
 <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Folder className="w-4 h-4 text-blue-600" />
          Rutas de Almacenamiento Local
        </h3>

        <div className="space-y-2 text-xs font-mono text-slate-700">
          <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 flex justify-between items-center">
            <span className="text-slate-500 font-sans font-medium">Almacén de Certificados SSL:</span>
            <span className="text-blue-700 font-bold">./data/certs/</span>
          </div>
          <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 flex justify-between items-center">
            <span className="text-slate-500 font-sans font-medium">Registro de Enrutamiento:</span>
            <span className="text-blue-700 font-bold">./data/domains.json</span>
          </div>
          <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 flex justify-between items-center">
            <span className="text-slate-500 font-sans font-medium">Configuración de Cloudflare:</span>
            <span className="text-blue-700 font-bold">./data/cloudflare-config.json</span>
          </div>
        </div>

        {getAuthToken() && (
          <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-600">Sesión remota autenticada con token en este navegador.</span>
            <button
              onClick={() => { clearAuthToken(); window.location.reload(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-rose-700 bg-rose-50 border border-rose-200 hover:bg-rose-100 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Cerrar sesión</span>
            </button>
          </div>
        )}
      </div>

      {/* Inspector MCP 2026-07-28 integrado */}
      <McpInspector />
    </div>
  );
};
