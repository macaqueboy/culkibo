import React, { useState } from 'react';
import { KeyRound, AlertCircle, ArrowRight, Eye, EyeOff, HelpCircle, Copy, Check } from 'lucide-react';
import { api, setAuthToken } from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';

interface AuthGateProps {
  tokenSource?: string;
  onAuthenticated: () => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ tokenSource = 'data/auth.json', onAuthenticated }) => {
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEnvSource = tokenSource === 'env' || tokenSource === 'CULKIBO_TOKEN';
  const vpsCmd = isEnvSource ? 'echo "$CULKIBO_TOKEN"' : `cat ${tokenSource}`;
  const dockerCmd = 'docker exec culkibo-daemon cat /app/data/auth.json';

  const copyText = async (text: string, id: string) => {
    const ok = await copyToClipboard(text);
    if (!ok) return;
    setCopiedCmd(id);
    window.setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = token.trim();
    if (!clean) return;
    setChecking(true);
    setError(null);
    try {
      const res = await api.verifyAuthToken(clean);
      if (res.valid) {
        setAuthToken(clean);
        onAuthenticated();
      } else {
        setError('La clave no coincide con la de este servidor.');
      }
    } catch (err: any) {
      setError(err?.message || 'Clave incorrecta o servidor inaccesible.');
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-white rounded-xl border border-slate-200 shadow-lg p-7 space-y-6">
        <div className="flex items-center gap-3">
          <svg width="36" height="36" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" className="shrink-0">
            <rect width="32" height="32" rx="8" fill="#18181B" />
            <path d="M16 6.5L25 22.5H7L16 6.5Z" stroke="#FFFFFF" strokeWidth="2.2" strokeLinejoin="round" />
            <circle cx="16" cy="17.5" r="3" fill="#FFFFFF" />
          </svg>
          <div>
            <h1 className="text-base font-semibold text-slate-900 tracking-tight">Entra a tu panel de Culkibo</h1>
            <p className="text-xs text-slate-500">El acceso remoto solicita la clave de control del servidor.</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="culkibo-token" className="block text-xs font-medium text-slate-700 mb-1.5">
              Clave de acceso del servidor
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="culkibo-token"
                type={showToken ? 'text' : 'password'}
                autoComplete="current-password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Pega aquí tu clave hexadecimal de 64 caracteres"
                className="w-full pl-9 pr-10 py-2 rounded-lg border border-slate-200 text-sm font-mono text-slate-900 placeholder:text-slate-400 bg-white"
              />
              <button
                type="button"
                onClick={() => setShowToken((prev) => !prev)}
                aria-label={showToken ? 'Ocultar clave' : 'Mostrar clave'}
                className="absolute right-2.5 top-2 p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                title={showToken ? 'Ocultar clave' : 'Mostrar clave'}
              >
                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div role="alert" className="flex items-start gap-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={checking || !token.trim()}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 transition-colors cursor-pointer"
          >
            <span>{checking ? 'Comprobando…' : 'Entrar al panel'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="border-t border-slate-100 pt-4 space-y-3">
          <button
            type="button"
            onClick={() => setShowHelp((prev) => !prev)}
            className="w-full flex items-center justify-between text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
          >
            <span className="inline-flex items-center gap-1.5">
              <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
              ¿Dónde encuentro la clave?
            </span>
            <span className="text-slate-400">{showHelp ? 'Ocultar' : 'Ver comandos'}</span>
          </button>

          {showHelp && (
            <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-3">
              <p className="leading-relaxed">
                {isEnvSource ? (
                  <>
                    Esta instancia toma la clave de la variable de entorno{' '}
                    <code className="font-mono text-slate-800">CULKIBO_TOKEN</code>.
                  </>
                ) : (
                  <>
                    Culkibo genera una clave aleatoria al arrancar por primera vez en{' '}
                    <code className="font-mono text-slate-800">{tokenSource}</code> (o mediante{' '}
                    <code className="font-mono text-slate-800">CULKIBO_TOKEN</code>).
                  </>
                )}
              </p>

              <div className="space-y-2">
                <div>
                  <span className="block text-[11px] font-medium text-slate-500 mb-1">En el servidor (SSH / terminal):</span>
                  <div className="flex items-center justify-between gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 font-mono text-[11px] text-slate-800">
                    <span className="truncate">{vpsCmd}</span>
                    <button
                      type="button"
                      aria-label="Copiar comando SSH"
                      onClick={() => copyText(vpsCmd, 'vps')}
                      className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer shrink-0"
                    >
                      {copiedCmd === 'vps' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="block text-[11px] font-medium text-slate-500 mb-1">Si usas Docker:</span>
                  <div className="flex items-center justify-between gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 font-mono text-[11px] text-slate-800">
                    <span className="truncate">{dockerCmd}</span>
                    <button
                      type="button"
                      aria-label="Copiar comando Docker"
                      onClick={() => copyText(dockerCmd, 'docker')}
                      className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer shrink-0"
                    >
                      {copiedCmd === 'docker' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
