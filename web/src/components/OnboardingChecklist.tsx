import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Circle,
  Globe,
  Bot,
  X,
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
  GitBranch,
  Download,
} from 'lucide-react';
import { api } from '../lib/api';

const DISMISS_KEY = 'culkibo_onboarding_dismissed_v1';

interface OnboardingChecklistProps {
  projectsCount: number;
  domainsCount: number;
  onCreateProject: () => void;
  onOpenWordPress: () => void;
  onOpenImport: () => void;
  onOpenCatalog: () => void;
  onOpenDomains: () => void;
  onOpenAi: () => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

export const OnboardingChecklist: React.FC<OnboardingChecklistProps> = ({
  projectsCount,
  domainsCount,
  onCreateProject,
  onOpenWordPress,
  onOpenImport,
  onOpenDomains,
  onOpenAi,
  onNotify,
}) => {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [expanded, setExpanded] = useState<boolean>(() => projectsCount === 0);
  const [serverIp, setServerIp] = useState<string | null>(null);
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [caddyOk, setCaddyOk] = useState<boolean | null>(null);
  const [startingCaddy, setStartingCaddy] = useState(false);

  useEffect(() => {
    if (dismissed) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: null })),
      api.getDbDockerStatus().catch(() => ({ available: false })),
      api.getIngressStatus({ probe: false }).catch(() => null),
    ]).then(([ipRes, docRes, ingRes]) => {
      if (!active) return;
      setServerIp(ipRes?.ip || null);
      setDockerOk(Boolean(docRes?.available));
      setCaddyOk(Boolean(ingRes?.available));
    });
    return () => { active = false; };
  }, [dismissed]);

  if (dismissed) return null;

  const step1Done = Boolean(caddyOk && dockerOk);
  const step2Done = projectsCount > 0;
  const step3Done = domainsCount > 0;
  const completedCount = [step1Done, step2Done, step3Done].filter(Boolean).length;

  const handleDismiss = () => {
    setDismissed(true);
    try {
      window.localStorage.setItem(DISMISS_KEY, '1');
    } catch {
      // ignorar si localStorage no está disponible
    }
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      if (res.started || res.alreadyRunning) {
        setCaddyOk(true);
        onNotify?.('Caddy activado: HTTPS automático disponible.', 'success');
      } else {
        onNotify?.(res.message || 'No se pudo iniciar Caddy.', 'error');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al activar Caddy', 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      {/* Rail compacto en una sola fila */}
      <div className="px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-2 text-xs font-semibold text-slate-900 cursor-pointer hover:text-slate-700"
          >
            <span>Puesta en marcha</span>
            <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-600 tabular-nums">
              {completedCount}/3
            </span>
          </button>

          <div className="hidden md:flex items-center gap-3 text-xs text-slate-500">
            <span className="inline-flex items-center gap-1">
              {step1Done ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <Circle className="w-3.5 h-3.5 text-slate-300" />}
              <span>Servidor{serverIp ? ` (${serverIp})` : ''}</span>
            </span>
            <span className="inline-flex items-center gap-1">
              {step2Done ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <Circle className="w-3.5 h-3.5 text-slate-300" />}
              <span>Proyecto</span>
            </span>
            <span className="inline-flex items-center gap-1">
              {step3Done ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <Circle className="w-3.5 h-3.5 text-slate-300" />}
              <span>Dominio HTTPS</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {caddyOk === false && (
            <button
              type="button"
              onClick={() => void handleStartCaddy()}
              disabled={startingCaddy}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-900 hover:bg-slate-800 text-white cursor-pointer disabled:opacity-50"
            >
              {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              <span>Activar Caddy</span>
            </button>
          )}
          <button
            type="button"
            onClick={onOpenAi}
            className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
          >
            <Bot className="w-3.5 h-3.5" />
            <span>Agente IA (MCP)</span>
          </button>
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            aria-label={expanded ? 'Contraer guía' : 'Expandir guía'}
            className="p-1 rounded-md text-slate-500 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={handleDismiss}
            aria-label="Ocultar guía"
            className="p-1 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-4 py-3 border-t border-slate-100 bg-slate-50/60 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2 text-slate-600">
            <span className={`px-2 py-0.5 rounded border text-[11px] font-medium ${dockerOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-white text-slate-600 border-slate-200'}`}>
              Docker: {dockerOk === null ? '…' : dockerOk ? 'Activo' : 'Sin Docker'}
            </span>
            <span className={`px-2 py-0.5 rounded border text-[11px] font-medium ${caddyOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
              Caddy: {caddyOk === null ? '…' : caddyOk ? 'Activo' : 'Detenido'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={onCreateProject}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 font-medium cursor-pointer"
            >
              <GitBranch className="w-3.5 h-3.5 text-slate-500" />
              <span>Repositorio Git</span>
            </button>
            <button
              type="button"
              onClick={onOpenWordPress}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 font-medium cursor-pointer"
            >
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              <span>Migrar WordPress</span>
            </button>
            <button
              type="button"
              onClick={onOpenImport}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 font-medium cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              <span>Importar stack</span>
            </button>
            <button
              type="button"
              onClick={onOpenDomains}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 font-medium cursor-pointer"
            >
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              <span>Conectar dominio</span>
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
