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
import { useI18n } from '../lib/i18n';

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
  const { t, locale } = useI18n();
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

  const totalResources = projectsCount + installationsCount;
  const stepInfraDone = Boolean(caddyOk && dockerOk);
  const stepAppDone = totalResources > 0;
  const stepMcpDone = mcpUsed;
  const stepTlsSecDone = domainsCount > 0;

  const steps = [
    {
      id: 'infra',
      done: stepInfraDone,
      title: t('onb.step1Title'),
      desc: stepInfraDone
        ? t('onb.step1Done', { ip: serverIp ? ` (${serverIp})` : '' })
        : t('onb.step1Todo'),
    },
    {
      id: 'app',
      done: stepAppDone,
      title: t('onb.step2Title'),
      desc: stepAppDone
        ? t('onb.step2Done', {
            count: totalResources,
            unit: totalResources === 1 ? t('onb.resourceSingular') : t('onb.resourcePlural'),
          })
        : t('onb.step2Todo'),
    },
    {
      id: 'mcp',
      done: stepMcpDone,
      title: t('onb.step3Title'),
      desc: stepMcpDone ? t('onb.step3Done') : t('onb.step3Todo'),
    },
    {
      id: 'tls',
      done: stepTlsSecDone,
      title: t('onb.step4Title'),
      desc: stepTlsSecDone
        ? t('onb.step4Done', {
            count: domainsCount,
            unit: domainsCount === 1 ? t('onb.domainSingular') : t('onb.domainPlural'),
          })
        : t('onb.step4Todo'),
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
      // ignore
    }
  };

  const handleOpenAiStep = () => {
    try {
      window.localStorage.setItem(MCP_SEEN_KEY, '1');
    } catch {
      // ignore
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
        onNotify?.(
          locale === 'es'
            ? 'Caddy activado: HTTPS automático y HTTP/3 disponibles.'
            : 'Caddy started: automatic HTTPS & HTTP/3 enabled.',
          'success'
        );
      } else {
        onNotify?.(res.message || 'Could not start Caddy.', 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error starting Caddy';
      onNotify?.(msg, 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  return (
    <section
      aria-label={t('onb.title')}
      className="culkibo-surface rounded-2xl overflow-hidden"
    >
      <div className="px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="inline-flex items-center gap-2 text-xs font-semibold text-slate-900 cursor-pointer hover:text-slate-700"
          >
            <Sparkles className={`w-3.5 h-3.5 shrink-0 ${allDone ? 'text-emerald-600' : 'text-amber-500'}`} />
            <span>{allDone ? t('onb.ready') : t('onb.title')}</span>
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
              <span>{t('onb.activateCaddy')}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            aria-label={expanded ? 'Collapse guide' : 'Expand guide'}
            className="inline-flex items-center justify-center w-9 h-9 sm:w-8 sm:h-8 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={handleDismiss}
            aria-label="Dismiss quick start"
            title="Dismiss (restorable in Settings or Ctrl+K)"
            className="inline-flex items-center justify-center w-9 h-9 sm:w-8 sm:h-8 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-2 border-t border-slate-100 bg-slate-50/55 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5">
          {/* Step 1 */}
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
                  <span>{steps[0].title}</span>
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
                Caddy: {caddyOk === null ? '…' : caddyOk ? 'OK' : 'Stopped'}
              </span>
            </div>
          </div>

          {/* Step 2 */}
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
                <span>{steps[1].title}</span>
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
                <span>{t('onb.git')}</span>
              </button>
              <button
                type="button"
                onClick={onOpenImport}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-[11px] font-medium cursor-pointer"
              >
                <Download className="w-3 h-3 text-slate-500" />
                <span>{t('onb.coolify')}</span>
              </button>
              <button
                type="button"
                onClick={onOpenCatalog}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-[11px] font-medium cursor-pointer"
              >
                <Boxes className="w-3 h-3 text-slate-500" />
                <span>{t('onb.apps140')}</span>
              </button>
            </div>
          </div>

          {/* Step 3 */}
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
                <span>{steps[2].title}</span>
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

          {/* Step 4 */}
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
                <span>{steps[3].title}</span>
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
                <span>{t('onb.domain')}</span>
              </button>
              {onOpenSecurity && (
                <button
                  type="button"
                  onClick={onOpenSecurity}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 text-[11px] font-medium cursor-pointer"
                >
                  <ShieldCheck className="w-3 h-3 text-emerald-600" />
                  <span>{t('onb.security2fa')}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
