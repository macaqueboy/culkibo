import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldCheck,
  Zap,
  Cloud,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Lock,
  Loader2,
  KeyRound,
  ExternalLink,
  Upload,
} from 'lucide-react';
import {
  api,
  type Project,
  type ServiceInstallation,
  type DomainWizardPreset,
  type IngressCapabilities,
  type DomainDiagnosisReport,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';

type WizardKind = 'custom' | 'wildcard' | 'sslip';
type DnsProvider = 'cloudflare' | 'godaddy' | 'namecheap' | 'ovh' | 'ionos' | 'dondominio' | 'otro';

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.es', 'nom.es', 'org.es', 'edu.es',
  'com.mx', 'com.ar', 'com.br', 'com.co', 'com.pe', 'com.ve', 'com.au', 'net.au',
  'co.jp', 'co.kr', 'co.nz', 'co.za', 'com.tr', 'com.sg', 'com.hk',
]);

function isApexDomain(hostname: string): boolean {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length < 2) return false;
  if (parts.length === 2) return true;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  return MULTI_PART_TLDS.has(lastTwo) && parts.length === 3;
}

function computeDnsRecordName(kind: WizardKind, rootDomain: string): string {
  if (kind === 'wildcard') return '*';
  const parts = rootDomain.split('.').filter(Boolean);
  if (parts.length <= 2) return '@';
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  const apexLen = MULTI_PART_TLDS.has(lastTwo) ? 3 : 2;
  if (parts.length <= apexLen) return '@';
  return parts.slice(0, parts.length - apexLen).join('.');
}

const PROVIDER_GUIDES: Record<DnsProvider, { label: string; steps: string[] }> = {
  cloudflare: {
    label: 'Cloudflare',
    steps: [
      'Entra a dash.cloudflare.com y abre tu dominio.',
      'En el menú izquierdo pulsa «DNS» → «Registros» → «Añadir registro».',
      'Crea el registro A con los valores de la tabla inferior y guarda.',
    ],
  },
  godaddy: {
    label: 'GoDaddy',
    steps: [
      'Entra a GoDaddy → «Mis productos» → pulsa «DNS» junto a tu dominio.',
      'Pulsa «Añadir nuevo registro» (o edita el registro A que apunte a @).',
      'Copia el Nombre y la IP de abajo, deja TTL en 600 s y guarda.',
    ],
  },
  namecheap: {
    label: 'Namecheap',
    steps: [
      'Abre «Domain List» → «Manage» → pestaña «Advanced DNS».',
      'En Host Records pulsa «Add New Record» → elige «A Record».',
      'Pega el Host y la IP de abajo y confirma.',
    ],
  },
  ovh: {
    label: 'OVH',
    steps: [
      'Accede al Área de Cliente de OVH → «Dominios» → «Zona DNS».',
      'Pulsa «Añadir una entrada» → selecciona «A».',
      'Introduce el subdominio (o vacío para la raíz) y pega la IP del servidor.',
    ],
  },
  ionos: {
    label: 'IONOS',
    steps: [
      'Entra a IONOS → «Dominios y SSL» → «DNS».',
      'Pulsa «Añadir registro» → tipo «A».',
      'Pega el nombre de host y la dirección IPv4 indicada abajo y guarda.',
    ],
  },
  dondominio: {
    label: 'DonDominio',
    steps: [
      'En DonDominio abre «Dominios» → elige tu dominio → «Zona DNS».',
      'Pulsa «Añadir registro DNS» → tipo «A».',
      'Rellena Nombre e IP destino exactamente como ves abajo y guarda.',
    ],
  },
  otro: {
    label: 'Otro proveedor',
    steps: [
      'Abre el panel de tu registrador y busca «Zona DNS» o «Registros DNS».',
      'Crea un registro de tipo «A» con el Nombre y la IP de abajo (TTL 300 o Automático).',
      'Vuelve aquí y pulsa «Comprobar DNS ahora».',
    ],
  },
};

const CADDY_WILDCARD_CMD = 'docker build -f Dockerfile.caddy -t culkibo-caddy:cloudflare .';

interface DomainWizardModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: () => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  projectId?: string;
  initialKind?: WizardKind;
  preset?: DomainWizardPreset | null;
  onOpenOriginCa?: (suggestedDomain?: string) => void;
}

export const DomainWizardModal: React.FC<DomainWizardModalProps> = ({
  isOpen,
  onClose,
  onComplete,
  onNotify,
  projectId: fixedProjectId,
  initialKind = 'custom',
  preset = null,
  onOpenOriginCa,
}) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [kind, setKind] = useState<WizardKind>(initialKind);
  const [hostnameInput, setHostnameInput] = useState('');
  // Destino unificado: '' | 'project:<id>' | 'service:<id>' | 'port'
  const [destinationKey, setDestinationKey] = useState<string>(fixedProjectId ? `project:${fixedProjectId}` : '');
  const [customPort, setCustomPort] = useState<number>(8080);
  const [projects, setProjects] = useState<Project[]>([]);
  const [services, setServices] = useState<ServiceInstallation[]>([]);
  const [serverIp, setServerIp] = useState('');
  const [cfConfigured, setCfConfigured] = useState(false);
  const [autoCfDns, setAutoCfDns] = useState(true);
  const [cfProxied, setCfProxied] = useState(false);
  const [includeWwwRedirect, setIncludeWwwRedirect] = useState(true);
  const [alsoAddWildcard, setAlsoAddWildcard] = useState(false);
  const [capabilities, setCapabilities] = useState<IngressCapabilities | null>(null);

  const [showCfSetup, setShowCfSetup] = useState(false);
  const [cfTokenInput, setCfTokenInput] = useState('');
  const [cfSaving, setCfSaving] = useState(false);
  const [cfError, setCfError] = useState<string | null>(null);

  const [provider, setProvider] = useState<DnsProvider>('cloudflare');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [checkingDns, setCheckingDns] = useState(false);
  const [dnsCheck, setDnsCheck] = useState<any>(null);

  const [activating, setActivating] = useState(false);
  const [activationError, setActivationError] = useState<string | null>(null);
  const [activationResult, setActivationResult] = useState<{
    domainId?: string;
    hostname: string;
    ingressApplied: boolean;
    ingressMessage: string;
    wildcardNote?: string;
    httpsReady: boolean;
  } | null>(null);
  const [reprobingStep3, setReprobingStep3] = useState(false);
  const [step3Diagnosis, setStep3Diagnosis] = useState<DomainDiagnosisReport | null>(null);

  const [prevOpen, setPrevOpen] = useState(isOpen);
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (isOpen) {
      setStep(1);
      setKind(preset?.suggestedHostname?.startsWith('*.') ? 'wildcard' : initialKind);
      setHostnameInput(preset?.suggestedHostname ? preset.suggestedHostname.replace(/^\*\./, '') : '');
      setActivationError(null);
      setActivationResult(null);
      setStep3Diagnosis(null);
      setDnsCheck(null);
      setShowCfSetup(false);
      setCfTokenInput('');
      setCfError(null);
      setIncludeWwwRedirect(true);
      setAlsoAddWildcard(false);
      if (fixedProjectId) {
        setDestinationKey(`project:${fixedProjectId}`);
      } else if (preset?.serviceId) {
        setDestinationKey(`service:${preset.serviceId}`);
        if (preset.targetPort) setCustomPort(preset.targetPort);
      } else if (preset?.targetPort) {
        setDestinationKey('port');
        setCustomPort(preset.targetPort);
      } else {
        setDestinationKey('');
        setCustomPort(8080);
      }
    }
  }

  useEffect(() => {
    if (!isOpen) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: '' })),
      api.getCloudflareConfig().catch(() => ({ isConfigured: false })),
      api.getIngressCapabilities().catch(() => null),
      fixedProjectId ? Promise.resolve([]) : api.getProjects().catch(() => []),
      fixedProjectId ? Promise.resolve({ installations: [] }) : api.getInstallations().catch(() => ({ installations: [] })),
    ]).then(([ipRes, cfRes, capsRes, projList, instRes]) => {
      if (!active) return;
      if (ipRes?.ip) setServerIp(ipRes.ip);
      setCfConfigured(Boolean(cfRes?.isConfigured));
      if (capsRes) setCapabilities(capsRes);
      if (Array.isArray(projList)) setProjects(projList);
      const list = Array.isArray((instRes as any)?.installations) ? (instRes as any).installations : [];
      setServices(list);
    });
    return () => { active = false; };
  }, [isOpen, fixedProjectId]);

  const handleHostnameChange = (raw: string) => {
    const trimmed = raw.trim();
    if (kind === 'custom' && trimmed.startsWith('*.')) {
      setKind('wildcard');
      setHostnameInput(trimmed.slice(2));
      return;
    }
    setHostnameInput(raw);
  };

  const cleanInput = hostnameInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const rootDomain = cleanInput.replace(/^\*\./, '');
  const finalHostname = kind === 'wildcard'
    ? (rootDomain ? `*.${rootDomain}` : '')
    : kind === 'sslip'
      ? (serverIp ? `${(cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app'}.${serverIp.replace(/\./g, '-')}.sslip.io` : '')
      : cleanInput;

  const isApex = kind === 'custom' && Boolean(rootDomain) && !rootDomain.startsWith('www.') && isApexDomain(rootDomain);
  const dnsRecordName = computeDnsRecordName(kind, rootDomain);

  const selectedService = destinationKey.startsWith('service:')
    ? services.find((s) => s.id === destinationKey.slice('service:'.length)) ||
      (preset?.serviceId === destinationKey.slice('service:'.length)
        ? { id: preset.serviceId, name: preset.serviceName || 'Servicio', hostPort: preset.targetPort || customPort }
        : null)
    : null;

  const selectedProjectId = fixedProjectId || (destinationKey.startsWith('project:') ? destinationKey.slice('project:'.length) : '');

  const copyValue = async (val: string, key: string) => {
    const ok = await copyToClipboard(val);
    if (!ok) return;
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleInlineCfSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cfTokenInput.trim()) return;
    setCfSaving(true);
    setCfError(null);
    try {
      const verify = await api.verifyCloudflareToken(cfTokenInput.trim());
      if (verify.error || verify.valid === false) {
        throw new Error(verify.message || verify.error || 'El token de Cloudflare no es válido');
      }
      await api.saveCloudflareConfig({ apiToken: cfTokenInput.trim(), useMock: false });
      setCfConfigured(true);
      setAutoCfDns(true);
      setShowCfSetup(false);
      setCfTokenInput('');
      onNotify?.('Cloudflare conectado: ya podemos crear tus registros DNS automáticamente.', 'success');
    } catch (err: any) {
      setCfError(err?.message || 'No se pudo verificar el token de Cloudflare');
    } finally {
      setCfSaving(false);
    }
  };

  const handleCheckDns = async () => {
    const target = kind === 'wildcard' ? `test.${rootDomain}` : finalHostname;
    if (!target) return;
    setCheckingDns(true);
    try {
      const res = await api.verifyDns(target);
      setDnsCheck(res);
    } catch (err: any) {
      setDnsCheck({ error: err?.message || 'Error consultando DNS' });
    } finally {
      setCheckingDns(false);
    }
  };

  const handleActivate = async () => {
    setActivating(true);
    setActivationError(null);
    try {
      let targetHostname = finalHostname;
      let domainId: string | undefined;
      let ingressApplied = false;
      let ingressMessage = '';
      let wildcardNote: string | undefined;

      const cleanIp = serverIp.trim() || null;
      const canonicalRedirect: 'none' | 'www_to_apex' =
        isApex && includeWwwRedirect ? 'www_to_apex' : 'none';

      if (kind === 'sslip') {
        if (!cleanIp) throw new Error('Indica la dirección IPv4 del servidor para generar el host sslip.io');
        const sslipRes = await api.issueOnDemandSslip(cleanIp, 'sslip.io');
        if (!sslipRes.success) throw new Error(sslipRes.error || 'No se pudo registrar el host sslip.io');
        const prefix = (cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app';
        targetHostname = `${prefix}.${sslipRes.cert.rootDomain}`;
      }

      if (selectedProjectId) {
        const attached = await api.attachDomainToProject(selectedProjectId, {
          hostname: targetHostname,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns,
          serverIp: cleanIp,
          canonicalRedirect,
          securityHeaders: true,
        });
        domainId = attached.domain?.id;
        ingressApplied = Boolean(attached.ingress?.applied);
        ingressMessage = attached.ingress?.message || (ingressApplied ? 'Ruta publicada en Caddy.' : 'Pendiente de Caddy.');
      } else if (selectedService) {
        const svcPort = Number(selectedService.hostPort || customPort || 8080);
        const added = await api.addDomain({
          hostname: targetHostname,
          targetPod: 'service',
          targetPort: svcPort,
          serviceId: selectedService.id,
          serviceName: selectedService.name,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns,
          serverIp: cleanIp,
          canonicalRedirect,
          securityHeaders: true,
        });
        domainId = added.id;
        ingressApplied = Boolean(added.ingress?.applied);
        ingressMessage = added.ingress?.message || (ingressApplied ? `Ruta publicada hacia ${selectedService.name} (:${svcPort}).` : 'Pendiente de Caddy.');
      } else {
        const portToUse = destinationKey === 'port' ? Math.max(1, Math.min(65535, Number(customPort) || 8080)) : 8080;
        const added = await api.addDomain({
          hostname: targetHostname,
          targetPod: 'citadel',
          targetPort: portToUse,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns,
          serverIp: cleanIp,
          canonicalRedirect,
          securityHeaders: true,
        });
        domainId = added.id;
        ingressApplied = Boolean(added.ingress?.applied);
        ingressMessage = added.ingress?.message || (ingressApplied ? 'Ruta publicada en Caddy.' : 'Pendiente de Caddy.');
      }

      // Si el usuario eligió comodín, o pidió añadir también *.dominio junto al apex
      const wantsWildcard = (kind === 'wildcard' || (isApex && alsoAddWildcard)) && Boolean(rootDomain);
      if (wantsWildcard) {
        if (isApex && alsoAddWildcard) {
          try {
            const wcHost = `*.${rootDomain}`;
            if (selectedProjectId) {
              await api.attachDomainToProject(selectedProjectId, {
                hostname: wcHost,
                cloudflareProxied: cfProxied,
                autoCreateDns: cfConfigured && autoCfDns,
                serverIp: cleanIp,
                securityHeaders: true,
              });
            } else {
              await api.addDomain({
                hostname: wcHost,
                targetPod: selectedService ? 'service' : 'citadel',
                targetPort: selectedService ? Number(selectedService.hostPort || customPort || 8080) : (destinationKey === 'port' ? customPort : 8080),
                serviceId: selectedService?.id || null,
                serviceName: selectedService?.name || null,
                cloudflareProxied: cfProxied,
                autoCreateDns: cfConfigured && autoCfDns,
                serverIp: cleanIp,
                securityHeaders: true,
              });
            }
          } catch {
            // Si ya existía el wildcard, continuamos configurando su política DNS-01
          }
        }
        try {
          const wc = await api.configureWildcardDns01(rootDomain);
          wildcardNote = wc.message || `Política ACME DNS-01 (Cloudflare) guardada para *.${rootDomain}.`;
        } catch (wcErr: any) {
          wildcardNote = `Aviso Wildcard DNS-01: ${wcErr?.message || 'requiere un binario de Caddy compilado con caddy-dns/cloudflare y CF_API_TOKEN (o un certificado Origin CA de Cloudflare).'}`;
        }
      }

      const ingStatus = await api.getIngressStatus({ probe: true }).catch(() => null);
      const tlsProbe = (ingStatus?.tls || []).find((t) => t.hostname === targetHostname);
      const httpsReady = Boolean(tlsProbe?.reachable && tlsProbe?.trusted && !tlsProbe?.expired);

      setActivationResult({
        domainId,
        hostname: targetHostname,
        ingressApplied: ingressApplied || Boolean(ingStatus?.available),
        ingressMessage,
        wildcardNote,
        httpsReady,
      });
      setStep(3);
      onComplete();
      onNotify?.(`Dominio ${targetHostname} configurado`, 'success');
    } catch (err: any) {
      setActivationError(err?.message || 'Error al activar el dominio');
    } finally {
      setActivating(false);
    }
  };

  const handleReprobeStep3 = async () => {
    if (!activationResult?.domainId) return;
    setReprobingStep3(true);
    try {
      const report = await api.diagnoseDomain(activationResult.domainId);
      setStep3Diagnosis(report);
      if (report.tls?.reachable && report.tls?.trusted && !report.tls?.expired) {
        setActivationResult((prev) => (prev ? { ...prev, httpsReady: true } : prev));
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo comprobar el estado ahora', 'error');
    } finally {
      setReprobingStep3(false);
    }
  };

  const canProceedStep1 = kind === 'sslip' ? Boolean(serverIp.trim()) : Boolean(rootDomain.includes('.'));
  const resolvedIps: string[] = Array.isArray(dnsCheck?.resolvedIps) ? dnsCheck.resolvedIps : [];
  const dnsMatchesServer = Boolean(serverIp && resolvedIps.includes(serverIp.trim()));
  const clickableHost = activationResult?.hostname
    ? activationResult.hostname.replace(/^\*\./, '')
    : '';

  return (
    <Modal
      open={isOpen}
      onClose={onClose}
      title="Conectar dominio con HTTPS"
      subtitle={`Paso ${step} de 3 — Configuración guiada con Caddy`}
      maxWidthClass="max-w-2xl"
      closeDisabled={activating}
    >
      {/* Indicador de pasos */}
      <div className="px-5 py-3 bg-slate-50/70 border-b border-slate-200 grid grid-cols-3 gap-2 text-xs">
        {[
          { num: 1, label: '1. Dominio y destino' },
          { num: 2, label: '2. Apuntar DNS' },
          { num: 3, label: '3. Verificación HTTPS' },
        ].map((s) => (
          <div
            key={s.num}
            className={`px-2.5 py-1.5 rounded-lg font-medium text-center border ${
              step === s.num
                ? 'bg-slate-900 text-white border-slate-900'
                : step > s.num
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-white text-slate-400 border-slate-200'
            }`}
          >
            {s.label}
          </div>
        ))}
      </div>

      {/* Cuerpo */}
      <div className="p-5 space-y-5">
        {activationError && (
          <div role="alert" className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
            <span>{activationError}</span>
          </div>
        )}

        {/* PASO 1 */}
        {step === 1 && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {([
                {
                  id: 'custom' as const,
                  icon: Globe,
                  title: 'Dominio propio',
                  desc: 'Un dominio o subdominio normal (miweb.com, app.miweb.com).',
                },
                {
                  id: 'wildcard' as const,
                  icon: ShieldCheck,
                  title: 'Comodín (*.dominio)',
                  desc: 'Un solo certificado cubre infinitos subdominios (DNS-01).',
                },
                {
                  id: 'sslip' as const,
                  icon: Zap,
                  title: 'URL gratis sslip.io',
                  desc: 'Sin comprar dominio ni tocar DNS: app.IP.sslip.io al instante.',
                },
              ]).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setKind(opt.id)}
                  className={`p-3.5 rounded-xl border text-left transition-colors cursor-pointer space-y-1.5 ${
                    kind === opt.id ? 'border-slate-900 bg-slate-50' : 'border-slate-200 hover:border-slate-300 bg-white'
                  }`}
                >
                  <opt.icon className="w-4 h-4 text-slate-700" />
                  <div className="text-xs font-semibold text-slate-900">{opt.title}</div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">{opt.desc}</p>
                </button>
              ))}
            </div>

            {kind === 'sslip' ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Nombre del subdominio</label>
                  <input
                    type="text"
                    value={hostnameInput}
                    onChange={(e) => setHostnameInput(e.target.value)}
                    placeholder="mi-app"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">IP pública del servidor</label>
                  <input
                    type="text"
                    value={serverIp}
                    onChange={(e) => setServerIp(e.target.value)}
                    placeholder="203.0.113.10"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono tabular-nums"
                  />
                </div>
                {finalHostname && (
                  <div className="sm:col-span-2 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                    Dirección resultante: <strong className="font-mono">https://{finalHostname}</strong>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    {kind === 'wildcard' ? 'Dominio raíz (sin *. delante)' : 'Nombre de dominio'}
                  </label>
                  <div className="flex items-center">
                    {kind === 'wildcard' && (
                      <span className="px-3 py-2 bg-slate-100 border border-r-0 border-slate-200 rounded-l-lg text-sm font-mono text-slate-600">
                        *.
                      </span>
                    )}
                    <input
                      type="text"
                      value={hostnameInput}
                      onChange={(e) => handleHostnameChange(e.target.value)}
                      placeholder={kind === 'wildcard' ? 'miempresa.com' : 'miempresa.com o app.miempresa.com'}
                      className={`w-full px-3 py-2 bg-white border border-slate-200 text-sm font-mono ${kind === 'wildcard' ? 'rounded-r-lg' : 'rounded-lg'}`}
                    />
                  </div>
                </div>

                {/* Opciones inteligentes para dominios raíz (apex) */}
                {isApex && (
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={includeWwwRedirect}
                        onChange={(e) => setIncludeWwwRedirect(e.target.checked)}
                        className="rounded border-slate-300 accent-slate-900"
                      />
                      <span>
                        Incluir también <code className="font-mono font-semibold text-slate-900">www.{rootDomain}</code> (redirección 301 automática a <code className="font-mono">{rootDomain}</code>)
                      </span>
                    </label>
                    <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={alsoAddWildcard}
                        onChange={(e) => setAlsoAddWildcard(e.target.checked)}
                        className="rounded border-slate-300 accent-slate-900"
                      />
                      <span>
                        Añadir también comodín <code className="font-mono font-semibold text-slate-900">*.{rootDomain}</code> (DNS-01 Cloudflare)
                      </span>
                    </label>
                  </div>
                )}
              </div>
            )}

            {/* Pre-flight honesto de capacidades Wildcard */}
            {(kind === 'wildcard' || (isApex && alsoAddWildcard)) && (
              <div className={`text-[11px] rounded-xl border p-3.5 space-y-2 leading-relaxed ${
                capabilities?.hasCloudflareDnsPlugin === true
                  ? 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
                  : 'bg-amber-50/80 border-amber-200 text-amber-950'
              }`}>
                {capabilities?.hasCloudflareDnsPlugin === true ? (
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                    <div>
                      <strong>Caddy listo para múltiples comodines DNS-01:</strong> el módulo <code className="font-mono">caddy-dns/cloudflare</code> está activo
                      {capabilities.hasCfTokenEnv ? ' y CF_API_TOKEN está presente.' : '. Falta exportar CF_API_TOKEN en el entorno de Caddy.'}
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                      <div>
                        <strong>Comprobación Wildcard DNS-01:</strong> Let&apos;s Encrypt exige validación DNS-01 para certificados <code className="font-mono">*.dominio</code>.
                        {capabilities?.hasCloudflareDnsPlugin === false
                          ? ' Tu binario actual de Caddy no incluye el plugin caddy-dns/cloudflare.'
                          : ' Asegúrate de usar la imagen con caddy-dns/cloudflare o subir un certificado Cloudflare Origin CA.'}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => void copyValue(CADDY_WILDCARD_CMD, 'dockerfile')}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white border border-amber-300 text-amber-950 font-mono text-[11px] hover:bg-amber-100/60 cursor-pointer"
                      >
                        {copiedKey === 'dockerfile' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>Copiar comando Dockerfile.caddy</span>
                      </button>
                      {onOpenOriginCa && (
                        <button
                          type="button"
                          onClick={() => {
                            onClose();
                            onOpenOriginCa(rootDomain ? `*.${rootDomain}` : undefined);
                          }}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 text-white text-[11px] font-medium hover:bg-slate-800 cursor-pointer"
                        >
                          <Upload className="w-3 h-3" />
                          <span>O subir Origin CA de Cloudflare (15 años)</span>
                        </button>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Destino unificado: Proyecto, Servicio de Catálogo (WordPress/n8n/...) o Puerto local */}
            {!fixedProjectId && (
              <div className="space-y-2.5">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    ¿Dónde debe apuntar este dominio?
                  </label>
                  <select
                    value={destinationKey}
                    onChange={(e) => setDestinationKey(e.target.value)}
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm text-slate-800"
                  >
                    <option value="">Registrar ruta base (:8080) — asignar después</option>
                    {projects.length > 0 && (
                      <optgroup label="Proyectos">
                        {projects.map((p) => (
                          <option key={p.id} value={`project:${p.id}`}>
                            Proyecto: {p.name}
                          </option>
                        ))}
                      </optgroup>
                    )}
                    {(services.length > 0 || preset?.serviceId) && (
                      <optgroup label="Servicios instalados (WordPress, Catálogo…)">
                        {preset?.serviceId && !services.some((s) => s.id === preset.serviceId) && (
                          <option value={`service:${preset.serviceId}`}>
                            Servicio: {preset.serviceName || preset.serviceId} (:{preset.targetPort || customPort})
                          </option>
                        )}
                        {services.map((s) => (
                          <option key={s.id} value={`service:${s.id}`}>
                            Servicio: {s.name} {s.hostPort ? `(:${s.hostPort})` : ''}
                          </option>
                        ))}
                      </optgroup>
                    )}
                    <optgroup label="Avanzado">
                      <option value="port">Puerto local personalizado en este servidor…</option>
                    </optgroup>
                  </select>
                </div>

                {destinationKey === 'port' && (
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Puerto local (127.0.0.1)</label>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={customPort}
                      onChange={(e) => setCustomPort(Number(e.target.value))}
                      className="w-40 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono tabular-nums"
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* PASO 2 */}
        {step === 2 && (
          <div className="space-y-4">
            {kind === 'sslip' ? (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 space-y-1.5">
                <div className="font-semibold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  No necesitas tocar ningún registro DNS
                </div>
                <p>
                  <strong className="font-mono">{finalHostname}</strong> resuelve automáticamente a{' '}
                  <strong className="font-mono">{serverIp}</strong>. Pulsa «Activar HTTPS» para publicarlo.
                </p>
              </div>
            ) : (
              <>
                <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/70 space-y-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Cloud className="w-4 h-4 text-slate-600" />
                      <span className="text-xs font-semibold text-slate-900">
                        {cfConfigured ? 'Cloudflare conectado: registro DNS automático' : '¿Usas Cloudflare? Configura el DNS en 1 clic'}
                      </span>
                    </div>
                    {!cfConfigured && (
                      <button
                        type="button"
                        onClick={() => setShowCfSetup((prev) => !prev)}
                        className="text-xs font-medium text-slate-700 underline hover:text-slate-900 cursor-pointer"
                      >
                        {showCfSetup ? 'Ocultar' : 'Conectar token'}
                      </button>
                    )}
                  </div>

                  {cfConfigured ? (
                    <div className="space-y-2">
                      <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={autoCfDns}
                          onChange={(e) => setAutoCfDns(e.target.checked)}
                          className="rounded border-slate-300 accent-slate-900"
                        />
                        <span>
                          Crear automáticamente el registro A apuntando a{' '}
                          <strong className="font-mono">{serverIp || 'la IP pública detectada'}</strong>
                        </span>
                      </label>
                      <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={cfProxied}
                          onChange={(e) => setCfProxied(e.target.checked)}
                          className="rounded border-slate-300 accent-slate-900"
                        />
                        <span>Activar proxy de Cloudflare (nube naranja)</span>
                      </label>
                    </div>
                  ) : showCfSetup ? (
                    <form onSubmit={handleInlineCfSave} className="space-y-2.5 pt-2 border-t border-slate-200">
                      <p className="text-[11px] text-slate-600">
                        Crea un API Token en Cloudflare con permiso <strong>Zone → DNS → Edit</strong>:
                      </p>
                      <div className="flex gap-2">
                        <div className="relative flex-1">
                          <KeyRound className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                          <input
                            type="password"
                            value={cfTokenInput}
                            onChange={(e) => setCfTokenInput(e.target.value)}
                            placeholder="Pega tu Cloudflare API Token"
                            className="w-full pl-8 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={cfSaving || !cfTokenInput.trim()}
                          className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                        >
                          {cfSaving ? 'Verificando…' : 'Conectar'}
                        </button>
                      </div>
                      {cfError && <p className="text-xs text-red-700">{cfError}</p>}
                    </form>
                  ) : null}
                </div>

                {/* Guía manual */}
                <div className="space-y-3">
                  <div className="text-xs font-medium text-slate-700">
                    O añade este registro A en tu proveedor DNS:
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {(Object.keys(PROVIDER_GUIDES) as DnsProvider[]).map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setProvider(p)}
                        className={`px-2.5 py-1 rounded-lg text-xs font-medium border cursor-pointer transition-colors ${
                          provider === p
                            ? 'bg-slate-900 text-white border-slate-900'
                            : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                        }`}
                      >
                        {PROVIDER_GUIDES[p].label}
                      </button>
                    ))}
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                    <ol className="list-decimal list-inside text-xs text-slate-600 space-y-1">
                      {PROVIDER_GUIDES[provider].steps.map((s, idx) => (
                        <li key={idx}>{s}</li>
                      ))}
                    </ol>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-200 text-xs">
                      <div className="bg-white border border-slate-200 rounded-lg p-2.5">
                        <div className="text-[10px] text-slate-400">Tipo</div>
                        <div className="font-mono font-semibold text-slate-900 mt-0.5">A</div>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-lg p-2.5 flex items-center justify-between gap-1">
                        <div className="min-w-0">
                          <div className="text-[10px] text-slate-400">Nombre / Host</div>
                          <div className="font-mono font-semibold text-slate-900 truncate mt-0.5">{dnsRecordName}</div>
                        </div>
                        <button type="button" aria-label="Copiar host" onClick={() => void copyValue(dnsRecordName, 'host')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer">
                          {copiedKey === 'host' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-lg p-2.5 flex items-center justify-between gap-1">
                        <div className="min-w-0">
                          <div className="text-[10px] text-slate-400">Valor (IP servidor)</div>
                          <div className="font-mono font-semibold text-slate-900 truncate mt-0.5 tabular-nums">{serverIp || 'Tu IP pública'}</div>
                        </div>
                        {serverIp && (
                          <button type="button" aria-label="Copiar IP" onClick={() => void copyValue(serverIp, 'ip')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer">
                            {copiedKey === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        )}
                      </div>
                    </div>

                    {isApex && includeWwwRedirect && (
                      <div className="text-[11px] text-slate-600 pt-1">
                        Recuerda añadir también un registro <code className="font-mono">A</code> o <code className="font-mono">CNAME</code> para <strong className="font-mono">www</strong> apuntando a la misma IP (o a <code className="font-mono">{rootDomain}</code>) para la redirección 301.
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => void handleCheckDns()}
                        disabled={checkingDns}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${checkingDns ? 'animate-spin' : ''}`} />
                        <span>{checkingDns ? 'Comprobando…' : 'Comprobar DNS'}</span>
                      </button>
                      {dnsCheck && (
                        <span
                          className={`text-xs font-medium ${
                            resolvedIps.length === 0
                              ? 'text-amber-700'
                              : !serverIp || dnsMatchesServer
                                ? 'text-emerald-700'
                                : 'text-amber-800'
                          }`}
                        >
                          {resolvedIps.length > 0
                            ? dnsMatchesServer
                              ? `Apunta a este servidor (${resolvedIps.join(', ')})`
                              : serverIp
                                ? `Apunta a ${resolvedIps.join(', ')} (esperado ${serverIp})`
                                : `Resuelve a: ${resolvedIps.join(', ')}`
                            : dnsCheck.error || 'Aún no resuelve (puede tardar 1–5 min)'}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* PASO 3 */}
        {step === 3 && activationResult && (
          <div className="space-y-4 py-2">
            <div className="text-center space-y-2">
              <div className={`w-12 h-12 rounded-xl mx-auto flex items-center justify-center border ${
                activationResult.httpsReady
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-600'
                  : 'bg-slate-100 border-slate-200 text-slate-700'
              }`}>
                <Lock className="w-6 h-6" />
              </div>

              <div>
                <h4 className="text-base font-semibold text-slate-900">
                  {activationResult.httpsReady ? 'Certificado HTTPS verificado y activo' : `Dominio ${activationResult.hostname} guardado`}
                </h4>
                <p className="text-xs text-slate-600 mt-1 max-w-md mx-auto leading-relaxed">
                  {activationResult.ingressMessage}
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                {clickableHost && (
                  <a
                    href={`https://${clickableHost}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-mono font-medium text-slate-800"
                  >
                    <span>https://{clickableHost}</span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                  </a>
                )}
                {activationResult.domainId && (
                  <button
                    type="button"
                    disabled={reprobingStep3}
                    onClick={() => void handleReprobeStep3()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${reprobingStep3 ? 'animate-spin' : ''}`} />
                    <span>{reprobingStep3 ? 'Comprobando…' : 'Comprobar DNS y TLS ahora'}</span>
                  </button>
                )}
              </div>
            </div>

            {activationResult.wildcardNote && (
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900">
                {activationResult.wildcardNote}
              </div>
            )}

            {step3Diagnosis && (
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="text-[11px] font-semibold text-slate-700">Comprobación en directo</div>
                {step3Diagnosis.checks.map((c) => (
                  <div key={c.id} className="flex items-start justify-between gap-2 text-xs bg-white border border-slate-200 rounded-lg px-3 py-2">
                    <div className="min-w-0">
                      <div className="font-medium text-slate-900">{c.title}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{c.detail}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold shrink-0 ${
                      c.status === 'ok'
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : c.status === 'warn'
                          ? 'bg-amber-50 text-amber-800 border border-amber-200'
                          : 'bg-red-50 text-red-700 border border-red-200'
                    }`}>
                      {c.status === 'ok' ? 'OK' : c.status === 'warn' ? 'Aviso' : 'Pendiente'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {!activationResult.httpsReady && !step3Diagnosis && (
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 leading-relaxed">
                Caddy emitirá el certificado TLS automáticamente en la primera visita en cuanto el DNS apunte a este servidor.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Pie */}
      <div className="px-5 py-3.5 bg-slate-50 border-t border-slate-200 flex items-center justify-between gap-2">
        {step === 1 && (
          <>
            <button type="button" onClick={onClose} className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-200/70 cursor-pointer">
              Cancelar
            </button>
            <button
              type="button"
              disabled={!canProceedStep1}
              onClick={() => setStep(2)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
            >
              <span>Siguiente: DNS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </>
        )}

        {step === 2 && (
          <>
            <button
              type="button"
              onClick={() => setStep(1)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-200/70 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Atrás</span>
            </button>
            <button
              type="button"
              disabled={activating}
              onClick={() => void handleActivate()}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
            >
              {activating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{activating ? 'Activando HTTPS…' : 'Activar HTTPS'}</span>
            </button>
          </>
        )}

        {step === 3 && (
          <button
            type="button"
            onClick={onClose}
            className="ml-auto px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
          >
            Volver a dominios
          </button>
        )}
      </div>
    </Modal>
  );
};
