import React, { useState } from 'react';
import { KeyRound, ShieldCheck, AlertCircle, ArrowRight, Eye, EyeOff, HelpCircle, Copy, Check } from 'lucide-react';
import { api, setAuthToken } from '../lib/api';

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

  const vpsCmd = `cat ${tokenSource}`;
  const dockerCmd = 'docker exec culkibo cat data/auth.json';

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
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
      <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200 shadow-lg p-7 space-y-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-900 tracking-tight">Entra a tu panel de Culkibo</h1>
            <p className="text-xs text-slate-500">Por tu seguridad, el acceso remoto pide la clave del servidor.</p>
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
                placeholder="Pega aquí tu clave (ckb_...)"
                className="w-full pl-9 pr-10 py-2 rounded-lg border border-slate-200 text-sm font-mono text-slate-900 placeholder:text-slate-400 bg-white"
              />
              <button
                type="button"
                onClick={() => setShowToken((prev) => !prev)}
                className="absolute right-2.5 top-2 p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                title={showToken ? 'Ocultar clave' : 'Mostrar clave'}
              >
                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-start gap-2 text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-xl p-3">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={checking || !token.trim()}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 transition-colors cursor-pointer"
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
              ¿Dónde encuentro mi clave?
            </span>
            <span className="text-slate-400">{showHelp ? 'Ocultar' : 'Ver comandos'}</span>
          </button>

          {showHelp && (
            <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-3">
              <p className="leading-relaxed">
                Culkibo crea una clave automática al arrancar por primera vez y la guarda en{' '}
                <code className="font-mono text-slate-800">{tokenSource}</code> (o en la variable{' '}
                <code className="font-mono text-slate-800">CULKIBO_TOKEN</code>).
              </p>

              <div className="space-y-2">
                <div>
                  <span className="block text-[11px] font-medium text-slate-500 mb-1">En tu servidor (SSH / terminal):</span>
                  <div className="flex items-center justify-between gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 font-mono text-[11px] text-slate-800">
                    <span className="truncate">{vpsCmd}</span>
                    <button type="button" onClick={() => copyText(vpsCmd, 'vps')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer shrink-0">
                      {copiedCmd === 'vps' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="block text-[11px] font-medium text-slate-500 mb-1">Si usas Docker:</span>
                  <div className="flex items-center justify-between gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 font-mono text-[11px] text-slate-800">
                    <span className="truncate">{dockerCmd}</span>
                    <button type="button" onClick={() => copyText(dockerCmd, 'docker')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer shrink-0">
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
