import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Circle,
  Globe,
  Bot,
  Server,
  Rocket,
  Download,
  Package,
  X,
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
  Sparkles
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
  onNotify?: (msg: string) => void;
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
  onNotify
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
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [caddyOk, setCaddyOk] = useState<boolean | null>(null);
  const [startingCaddy, setStartingCaddy] = useState(false);

  useEffect(() => {
    if (dismissed) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: null })),
      api.getDbDockerStatus().catch(() => ({ available: false })),
      api.getIngressStatus({ probe: false }).catch(() => null)
    ]).then(([ipRes, docRes, ingRes]) => {
      if (!active) return;
      setServerIp(ipRes?.ip || null);
      setDockerOk(Boolean(docRes?.available));
      setCaddyOk(Boolean(ingRes?.available));
    });
    return () => { active = false; };
  }, [dismissed]);

  if (dismissed) return null;

  const step1Done = Boolean(caddyOk || dockerOk);
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
        onNotify?.('Caddy activado: ya tienes HTTPS automático listo.');
      } else {
        onNotify?.(res.message || 'No se pudo iniciar Caddy.');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al activar Caddy');
    } finally {
      setStartingCaddy(false);
    }
  };

  return (
    <section className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
      <div className="px-5 py-4 bg-slate-50/80 border-b border-slate-200/80 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-slate-900 text-white flex items-center justify-center shrink-0">
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-sm font-bold text-slate-900">Guía rápida para poner tu servidor en marcha</h2>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-white border border-slate-200 text-slate-600 tabular-nums">
                {completedCount}/3 completados
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Sin comandos raros: sigue estos pasos para publicar tu web, conectar tu dominio y enlazar tu agente IA.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => setCollapsed((prev) => !prev)}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-200/60 cursor-pointer"
            title={collapsed ? 'Expandir guía' : 'Contraer guía'}
          >
            {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={handleDismiss}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-200/60 cursor-pointer"
            title="Ocultar guía"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {!collapsed && (
        <div className="p-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {/* Paso 1: Servidor */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-500">Paso 1</span>
                {step1Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Server className="w-4 h-4 text-slate-600" />
                Estado de tu servidor
              </div>
              <div className="text-xs text-slate-600 space-y-1">
                <div>IP pública: <span className="font-mono font-semibold text-slate-800">{serverIp || 'Detectando…'}</span></div>
                <div className="flex items-center gap-2 flex-wrap pt-0.5">
                  <span className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${dockerOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'}`}>
                    Docker: {dockerOk === null ? '…' : dockerOk ? 'Listo' : 'No detectado'}
                  </span>
                  <span className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${caddyOk ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
                    Caddy HTTPS: {caddyOk === null ? '…' : caddyOk ? 'Activo' : 'Detenido'}
                  </span>
                </div>
              </div>
            </div>

            {caddyOk === false && (
              <button
                type="button"
                onClick={handleStartCaddy}
                disabled={startingCaddy}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-white cursor-pointer disabled:opacity-50"
              >
                {startingCaddy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{startingCaddy ? 'Activando Caddy…' : 'Activar Caddy ahora'}</span>
              </button>
            )}
          </div>

          {/* Paso 2: Subir web o proyecto */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-500">Paso 2</span>
                {step2Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Rocket className="w-4 h-4 text-blue-600" />
                Sube tu web o proyecto
              </div>
              <p className="text-xs text-slate-500">Elige de dónde vienes y te guiamos paso a paso:</p>
            </div>

            <div className="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onClick={onOpenWordPress}
                className="px-2.5 py-2 rounded-lg text-[11px] font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer"
              >
                Traer WordPress
              </button>
              <button
                type="button"
                onClick={onCreateProject}
                className="px-2.5 py-2 rounded-lg text-[11px] font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer"
              >
                Conectar Git
              </button>
              <button
                type="button"
                onClick={onOpenImport}
                className="px-2.5 py-2 rounded-lg text-[11px] font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <Download className="w-3 h-3 text-slate-500 shrink-0" />
                <span>Coolify / Otros</span>
              </button>
              <button
                type="button"
                onClick={onOpenCatalog}
                className="px-2.5 py-2 rounded-lg text-[11px] font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 text-left transition-colors cursor-pointer flex items-center gap-1"
              >
                <Package className="w-3 h-3 text-slate-500 shrink-0" />
                <span>App en 1 clic</span>
              </button>
            </div>
          </div>

          {/* Paso 3: Conectar dominio */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-500">Paso 3</span>
                {step3Done ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Circle className="w-4 h-4 text-slate-300" />}
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-emerald-600" />
                Conecta tu dominio y HTTPS
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Asistente guiado para dominios propios, comodín <code className="font-mono">*.tudominio.com</code> o URL gratis <code className="font-mono">sslip.io</code>.
              </p>
            </div>

            <button
              type="button"
              onClick={onOpenDomains}
              className="w-full px-3 py-2 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 transition-colors cursor-pointer"
            >
              Abrir asistente de dominios →
            </button>
          </div>

          {/* Paso 4: Enlazar agente IA */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/40 p-4 flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-500">Paso 4</span>
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                  MCP 2026-07-28
                </span>
              </div>
              <div className="font-semibold text-sm text-slate-900 flex items-center gap-1.5">
                <Bot className="w-4 h-4 text-blue-600" />
                Enlaza tu Agente IA en directo
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Conecta Claude, Cursor, Windsurf o VS Code en 1 clic y mira cada acción en tiempo real.
              </p>
            </div>

            <button
              type="button"
              onClick={onOpenAi}
              className="w-full px-3 py-2 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-800 transition-colors cursor-pointer"
            >
              Configurar Agentes IA →
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
