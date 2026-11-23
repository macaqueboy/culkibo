import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Circle,
  Globe,
  Bot,
  Server,
  Rocket,
  Download,
  GitBranch,
  Package,
  X,
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
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
  onOpenCatalog,
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
  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [serverIp, setServerIp] = useState<string | null>(null);
  const [ipChecked, setIpChecked] = useState<boolean>(false);
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
      setIpChecked(true);
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
      <div className="px-5 py-3.5 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h2 className="text-sm font-semibold text-slate-900">Primeros pasos</h2>
            <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-white border border-slate-200 text-slate-600 tabular-nums">
              {completedCount}/3 pasos básicos
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Comprueba el servidor, sube tu primera aplicación, conecta un dominio HTTPS y enlaza tu agente de IA.
          </p>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => setCollapsed((prev) => !prev)}
            aria-label={collapsed ? 'Expandir guía' : 'Contraer guía'}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-200/60 cursor-pointer"
            title={collapsed ? 'Expandir guía' : 'Contraer guía'}
          >
            {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={handleDismiss}
            aria-label="Ocultar guía"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-200/60 cursor-pointer"
            title="Ocultar guía"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {!collapsed && (
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
          {/* Paso 1: Servidor */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-500">Paso 1</span>
                {step1Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Server className="w-4 h-4 text-slate-600" />
                Estado del servidor
              </div>
              <div className="text-xs text-slate-600 space-y-1.5">
                <div>
                  IP pública:{' '}
                  <span className="font-mono font-medium text-slate-900 tabular-nums">
                    {!ipChecked ? 'Comprobando…' : serverIp || 'Red local'}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-medium border ${dockerOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'}`}>
                    Docker: {dockerOk === null ? '…' : dockerOk ? 'Activo' : 'Sin Docker'}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-medium border ${caddyOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
                    Caddy: {caddyOk === null ? '…' : caddyOk ? 'Activo' : 'Detenido'}
                  </span>
                </div>
              </div>
            </div>

            {caddyOk === false && (
              <button
                type="button"
                onClick={handleStartCaddy}
                disabled={startingCaddy}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-white cursor-pointer disabled:opacity-50"
              >
                {startingCaddy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{startingCaddy ? 'Activando Caddy…' : 'Activar Caddy'}</span>
              </button>
            )}
          </div>

          {/* Paso 2: Subir web o proyecto */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-500">Paso 2</span>
                {step2Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Rocket className="w-4 h-4 text-slate-600" />
                Añade tu primer proyecto
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">Elige el origen y sigue el asistente:</p>
            </div>

            <div className="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onClick={onOpenWordPress}
                className="px-2.5 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <Globe className="w-3 h-3 text-slate-500 shrink-0" />
                <span className="truncate">WordPress</span>
              </button>
              <button
                type="button"
                onClick={onCreateProject}
                className="px-2.5 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <GitBranch className="w-3 h-3 text-slate-500 shrink-0" />
                <span className="truncate">Repositorio Git</span>
              </button>
              <button
                type="button"
                onClick={onOpenImport}
                className="px-2.5 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <Download className="w-3 h-3 text-slate-500 shrink-0" />
                <span className="truncate">Coolify / Otros</span>
              </button>
              <button
                type="button"
                onClick={onOpenCatalog}
                className="px-2.5 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <Package className="w-3 h-3 text-slate-500 shrink-0" />
                <span className="truncate">Catálogo</span>
              </button>
            </div>
          </div>

          {/* Paso 3: Conectar dominio */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-500">Paso 3</span>
                {step3Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-slate-600" />
                Conecta un dominio HTTPS
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Dominio propio, comodín <code className="font-mono">*.tudominio.com</code> o URL gratuita <code className="font-mono">sslip.io</code>.
              </p>
            </div>

            <button
              type="button"
              onClick={onOpenDomains}
              className="w-full px-3 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 transition-colors cursor-pointer"
            >
              Abrir asistente de dominios →
            </button>
          </div>

          {/* Paso extra opcional: Enlazar agente IA */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-500">Opcional</span>
                <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                  MCP
                </span>
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Bot className="w-4 h-4 text-slate-600" />
                Conecta tu agente de IA
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Enlaza Claude, Cursor, Windsurf o VS Code con 49 herramientas reales y auditoría en vivo.
              </p>
            </div>

            <button
              type="button"
              onClick={onOpenAi}
              className="w-full px-3 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 transition-colors cursor-pointer"
            >
              Configurar agentes de IA →
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
