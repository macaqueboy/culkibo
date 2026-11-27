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
  Boxes,
  ShieldCheck,
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import { api } from '../lib/api';

const DISMISS_KEY = 'culkibo_onboarding_dismissed_v1';
const MCP_SEEN_KEY = 'culkibo_onboarding_mcp_seen_v1';

interface OnboardingChecklistProps {
  projectsCount: number;
  domainsCount: number;
  onCreateProject: () => void;
  onOpenWordPress: () => void;
  onOpenImport: () => void;
  onOpenCatalog: () => void;
  onOpenDomains: () => void;
  onOpenAi: () => void;
  onOpenSecurity?: () => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  restoreTick?: number;
}

export const OnboardingChecklist: React.FC<OnboardingChecklistProps> = ({
  projectsCount,
  domainsCount,
  onCreateProject,
  onOpenImport,
  onOpenCatalog,
  onOpenDomains,
  onOpenAi,
  onOpenSecurity,
  onNotify,
  restoreTick = 0,
}) => {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [expanded, setExpanded] = useState<boolean>(() => projectsCount === 0);
  const [prevRestoreTick, setPrevRestoreTick] = useState(restoreTick);
  if (restoreTick !== prevRestoreTick) {
    setPrevRestoreTick(restoreTick);
    if (restoreTick > 0) {
      setDismissed(false);
      setExpanded(true);
    }
  }

  const [serverIp, setServerIp] = useState<string | null>(null);
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [caddyOk, setCaddyOk] = useState<boolean | null>(null);
  const [installationsCount, setInstallationsCount] = useState<number>(0);
  const [mcpUsed, setMcpUsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(MCP_SEEN_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [startingCaddy, setStartingCaddy] = useState(false);

  useEffect(() => {
    if (dismissed) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: null })),
      api.getDbDockerStatus().catch(() => ({ available: false })),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getInstallations().catch(() => ({ installations: [] })),
      api.getMcpAudit().catch(() => ({ auditLog: [] })),
    ]).then(([ipRes, docRes, ingRes, instRes, mcpRes]) => {
      if (!active) return;
      setServerIp(ipRes?.ip || null);
      setDockerOk(Boolean(docRes?.available));
      setCaddyOk(Boolean(ingRes?.available));
      setInstallationsCount(Array.isArray(instRes?.installations) ? instRes.installations.length : 0);
      if (Array.isArray(mcpRes?.auditLog) && mcpRes.auditLog.length > 0) {
        setMcpUsed(true);
      }
    });
    return () => {
      active = false;
    };
  }, [dismissed]);

  if (dismissed) return null;

  const stepInfraDone = Boolean(caddyOk && dockerOk);
  const stepAppDone = projectsCount > 0 || installationsCount > 0;
  const stepMcpDone = mcpUsed;
  const stepTlsSecDone = domainsCount > 0;

  const steps = [
    {
      id: 'infra',
      done: stepInfraDone,
      title: 'Motor y HTTPS listos',
      desc: stepInfraDone
        ? `Docker y Caddy activos${serverIp ? ` en ${serverIp}` : ''}.`
        : 'Activa Caddy para emitir TLS automático y HTTP/3 sin configurar nada.',
    },
    {
      id: 'app',
      done: stepAppDone,
      title: 'Primera app en vivo',
      desc: stepAppDone
        ? `${projectsCount + installationsCount} ${projectsCount + installationsCount === 1 ? 'recurso activo' : 'recursos activos'} en tu servidor.`
        : 'Despliega desde Git, migra Coolify v4 o instala del catálogo (140+ apps).',
    },
    {
      id: 'mcp',
      done: stepMcpDone,
      title: 'Agente IA (MCP 2026)',
      desc: stepMcpDone
        ? 'Agente conectado al plano de control con 109 herramientas.'
        : 'Conecta Claude Code, Antigravity o Cursor en 1 clic (~81% menos tokens).',
    },
    {
      id: 'tls',
      done: stepTlsSecDone,
      title: 'Dominio HTTPS y 2FA',
      desc: stepTlsSecDone
        ? `${domainsCount} ${domainsCount === 1 ? 'dominio HTTPS conectado' : 'dominios HTTPS conectados'}.`
        : 'Publica tu dominio con SSL automático y protege tu cuenta con TOTP 2FA.',
    },
  ];

  const completedCount = steps.filter((s) => s.done).length;
  const progressPct = Math.round((completedCount / steps.length) * 100);
  const allDone = completedCount === steps.length;

  const handleDismiss = () => {
    setDismissed(true);
    try {
      window.localStorage.setItem(DISMISS_KEY, '1');
    } catch {
      // ignorar si localStorage no está disponible
    }
  };

  const handleOpenAiStep = () => {
    try {
      window.localStorage.setItem(MCP_SEEN_KEY, '1');
    } catch {
      // ignorar
    }
    setMcpUsed(true);
    onOpenAi();
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      if (res.started || res.alreadyRunning) {
        setCaddyOk(true);
        onNotify?.('Caddy activado: HTTPS automático y HTTP/3 disponibles.', 'success');
      } else {
        onNotify?.(res.message || 'No se pudo iniciar Caddy.', 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al activar Caddy';
      onNotify?.(msg, 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  return (
    <section
      aria-label="Guía de puesta en marcha rápida"
      className="culkibo-surface rounded-2xl overflow-hidden"
    >
      {/* Barra superior compacta con progreso real */}
      <div className="px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="inline-flex items-center gap-2 text-xs font-semibold text-slate-900 cursor-pointer hover:text-slate-700"
          >
            <Sparkles className={`w-3.5 h-3.5 shrink-0 ${allDone ? 'text-emerald-600' : 'text-amber-500'}`} />
            <span>{allDone ? 'Entorno listo para producción' : 'Arranque rápido (<2 min)'}</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[11px] font-medium border tabular-nums ${
                allDone
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-100 text-slate-700 border-slate-200'
              }`}
            >
              {completedCount}/{steps.length}
            </span>
          </button>

          {/* Barra de progreso limpia */}
          <div
            aria-hidden="true"
            className="hidden sm:block w-24 h-1.5 rounded-full bg-slate-100 overflow-hidden shrink-0"
          >
            <div
              className={`h-full rounded-full transition-[width] duration-300 ease-out ${
                allDone ? 'bg-emerald-500' : 'bg-slate-900'
              }`}
              style={{ width: `${progressPct}%` }}
            />
          </div>

          <div className="hidden lg:flex items-center gap-3 text-xs text-slate-500">
            {steps.map((s) => (
              <span key={s.id} className="inline-flex items-center gap-1">
                {s.done ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                ) : (
                  <Circle className="w-3.5 h-3.5 text-slate-300 shrink-0" />
                )}
                <span className={s.done ? 'text-slate-700 font-medium' : ''}>{s.title}</span>
              </span>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {caddyOk === false && (
            <button
              type="button"
              onClick={() => void handleStartCaddy()}
              disabled={startingCaddy}
              className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-white cursor-pointer disabled:opacity-50"
            >
              {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              <span>Activar Caddy</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            aria-label={expanded ? 'Contraer guía' : 'Expandir guía'}
            className="inline-flex items-center justify-center w-9 h-9 sm:w-8 sm:h-8 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={handleDismiss}
            aria-label="Ocultar guía de primeros pasos"
            title="Ocultar (restaurable en Ajustes o Ctrl+K)"
            className="inline-flex items-center justify-center w-9 h-9 sm:w-8 sm:h-8 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Tarjetas paso a paso accionables */}
      {expanded && (
        <div className="px-4 pb-4 pt-2 border-t border-slate-100 bg-slate-50/55 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5">
          {/* Paso 1: Infraestructura */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 flex flex-col justify-between gap-3">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                  {stepInfraDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  ) : (
                    <span className="w-4 h-4 rounded-full bg-slate-900 text-white text-[10px] font-mono flex items-center justify-center shrink-0">
                      1
                    </span>
                  )}
                  <span>Motor y HTTPS</span>
                </span>
                {serverIp && (
                  <span className="font-mono text-[10px] text-slate-400 tabular-nums truncate max-w-[100px]">
                    {serverIp}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">{steps[0].desc}</p>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span
                className={`px-2 py-0.5 rounded-md border text-[11px] font-medium ${
                  dockerOk
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-50 text-slate-600 border-slate-200'
                }`}
              >
                Docker: {dockerOk === null ? '…' : dockerOk ? 'OK' : 'Offline'}
              </span>
              <span
                className={`px-2 py-0.5 rounded-md border text-[11px] font-medium ${
                  caddyOk
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}
              >
                Caddy: {caddyOk === null ? '…' : caddyOk ? 'OK' : 'Detenido'}
              </span>
            </div>
          </div>

          {/* Paso 2: Primera app */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 flex flex-col justify-between gap-3">
            <div className="space-y-1.5">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                {stepAppDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                ) : (
                  <span className="w-4 h-4 rounded-full bg-slate-900 text-white text-[10px] font-mono flex items-center justify-center shrink-0">
                    2
                  </span>
                )}
                <span>Despliega tu primera app</span>
              </span>
              <p className="text-[11px] text-slate-500 leading-relaxed">{steps[1].desc}</p>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={onCreateProject}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-medium cursor-pointer"
              >
                <GitBranch className="w-3 h-3" />
                <span>Git</span>
              </button>
              <button
                type="button"
                onClick={onOpenImport}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-[11px] font-medium cursor-pointer"
              >
                <Download className="w-3 h-3 text-slate-500" />
                <span>Coolify</span>
              </button>
              <button
                type="button"
                onClick={onOpenCatalog}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-[11px] font-medium cursor-pointer"
              >
                <Boxes className="w-3 h-3 text-slate-500" />
                <span>140+ Apps</span>
              </button>
            </div>
          </div>

          {/* Paso 3: Conectar MCP IA */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 flex flex-col justify-between gap-3">
            <div className="space-y-1.5">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                {stepMcpDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                ) : (
                  <span className="w-4 h-4 rounded-full bg-slate-900 text-white text-[10px] font-mono flex items-center justify-center shrink-0">
                    3
                  </span>
                )}
                <span>Conecta tu Agente IA</span>
              </span>
              <p className="text-[11px] text-slate-500 leading-relaxed">{steps[2].desc}</p>
            </div>
            <div>
              <button
                type="button"
                onClick={handleOpenAiStep}
                className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 text-[11px] font-medium cursor-pointer"
              >
                <Bot className="w-3.5 h-3.5 text-slate-600" />
                <span>Claude / Antigravity MCP</span>
                <ArrowRight className="w-3 h-3 text-slate-400" />
              </button>
            </div>
          </div>

          {/* Paso 4: Dominio HTTPS + Seguridad 2FA */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 flex flex-col justify-between gap-3">
            <div className="space-y-1.5">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                {stepTlsSecDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                ) : (
                  <span className="w-4 h-4 rounded-full bg-slate-900 text-white text-[10px] font-mono flex items-center justify-center shrink-0">
                    4
                  </span>
                )}
                <span>HTTPS y Seguridad 2FA</span>
              </span>
              <p className="text-[11px] text-slate-500 leading-relaxed">{steps[3].desc}</p>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={onOpenDomains}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 text-[11px] font-medium cursor-pointer"
              >
                <Globe className="w-3 h-3 text-slate-500" />
                <span>Dominio</span>
              </button>
              {onOpenSecurity && (
                <button
                  type="button"
                  onClick={onOpenSecurity}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 text-[11px] font-medium cursor-pointer"
                >
                  <ShieldCheck className="w-3 h-3 text-emerald-600" />
                  <span>2FA y Auditoría</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
