import React, { useState } from 'react';
import { KeyRound, ShieldCheck, AlertCircle, ArrowRight } from 'lucide-react';
import { api, setAuthToken } from '../lib/api';

interface AuthGateProps {
  tokenSource?: string;
  onAuthenticated: () => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ tokenSource = 'data/auth.json', onAuthenticated }) => {
  const [token, setToken] = useState('');
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        setError('El token no coincide con el configurado en este servidor.');
      }
    } catch (err: any) {
      setError(err?.message || 'Token inválido o servidor inaccesible.');
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
            <h1 className="text-lg font-semibold text-slate-900 tracking-tight">Acceso a Culkibo</h1>
            <p className="text-xs text-slate-500">El plano de control remoto exige token de acceso.</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="culkibo-token" className="block text-xs font-medium text-slate-700 mb-1.5">
              Token del servidor
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="culkibo-token"
                type="password"
                autoComplete="current-password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Pega aquí tu token de acceso"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-200 text-sm font-mono text-slate-900 placeholder:text-slate-400 bg-white"
              />
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
            <span>{checking ? 'Verificando…' : 'Entrar al panel'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-xl p-3.5 leading-relaxed">
          El token se genera automáticamente en el primer arranque y reside en{' '}
          <code className="font-mono text-slate-700">{tokenSource}</code> (o en la variable de entorno{' '}
          <code className="font-mono text-slate-700">CULKIBO_TOKEN</code>).
        </div>
      </div>
    </div>
  );
};
