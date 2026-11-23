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
} from 'lucide-react';
import { api, type Project } from '../lib/api';
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

interface DomainWizardModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: () => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  projectId?: string;
  initialKind?: WizardKind;
}

export const DomainWizardModal: React.FC<DomainWizardModalProps> = ({
  isOpen,
  onClose,
  onComplete,
  onNotify,
  projectId: fixedProjectId,
  initialKind = 'custom',
}) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [kind, setKind] = useState<WizardKind>(initialKind);
  const [hostnameInput, setHostnameInput] = useState('');
  const [selectedProjectId, setSelectedProjectId] = useState<string>(fixedProjectId || '');
  const [projects, setProjects] = useState<Project[]>([]);
  const [serverIp, setServerIp] = useState('');
  const [cfConfigured, setCfConfigured] = useState(false);
  const [autoCfDns, setAutoCfDns] = useState(true);
  const [cfProxied, setCfProxied] = useState(false);

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
    hostname: string;
    ingressApplied: boolean;
    ingressMessage: string;
    wildcardNote?: string;
    httpsReady: boolean;
  } | null>(null);

  const [prevOpen, setPrevOpen] = useState(isOpen);
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (isOpen) {
      setStep(1);
      setKind(initialKind);
      setHostnameInput('');
      setActivationError(null);
      setActivationResult(null);
      setDnsCheck(null);
      setShowCfSetup(false);
      setCfTokenInput('');
      setCfError(null);
      setSelectedProjectId(fixedProjectId || '');
    }
  }

  useEffect(() => {
    if (!isOpen) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: '' })),
      api.getCloudflareConfig().catch(() => ({ isConfigured: false })),
      fixedProjectId ? Promise.resolve([]) : api.getProjects().catch(() => []),
    ]).then(([ipRes, cfRes, projList]) => {
      if (!active) return;
      if (ipRes?.ip) setServerIp(ipRes.ip);
      setCfConfigured(Boolean(cfRes?.isConfigured));
      if (Array.isArray(projList)) setProjects(projList);
    });
    return () => { active = false; };
  }, [isOpen, fixedProjectId]);

  const cleanInput = hostnameInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const rootDomain = cleanInput.replace(/^\*\./, '');
  const finalHostname = kind === 'wildcard'
    ? (rootDomain ? `*.${rootDomain}` : '')
    : kind === 'sslip'
      ? (serverIp ? `${(cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app'}.${serverIp.replace(/\./g, '-')}.sslip.io` : '')
      : cleanInput;

  const dnsRecordName = computeDnsRecordName(kind, rootDomain);

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
      let ingressApplied = false;
      let ingressMessage = '';
      let wildcardNote: string | undefined;

      const cleanIp = serverIp.trim() || null;

      if (kind === 'sslip') {
        if (!cleanIp) throw new Error('Indica la dirección IPv4 del servidor para generar el host sslip.io');
        const sslipRes = await api.issueOnDemandSslip(cleanIp, 'sslip.io');
        if (!sslipRes.success) throw new Error(sslipRes.error || 'No se pudo registrar el host sslip.io');
        const prefix = (cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app';
        targetHostname = `${prefix}.${sslipRes.cert.rootDomain}`;
      }

      const targetProjectId = fixedProjectId || selectedProjectId || null;
      if (targetProjectId) {
        const attached = await api.attachDomainToProject(targetProjectId, {
          hostname: targetHostname,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns,
          serverIp: cleanIp,
        });
        ingressApplied = Boolean(attached.ingress?.applied);
        ingressMessage = attached.ingress?.message || (ingressApplied ? 'Ruta publicada en Caddy.' : 'Pendiente de Caddy.');
      } else {
        const added = await api.addDomain({
          hostname: targetHostname,
          targetPod: 'citadel',
          targetPort: 8080,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns,
          serverIp: cleanIp,
        });
        const ing = (added as any).ingress;
        ingressApplied = Boolean(ing?.applied);
        ingressMessage = ing?.message || (ingressApplied ? 'Ruta publicada en Caddy.' : 'Pendiente de Caddy.');
      }

      if (kind === 'wildcard' && rootDomain) {
        try {
          const wc = await api.configureWildcardDns01(rootDomain);
          wildcardNote = wc.message || `Política ACME DNS-01 (Cloudflare) configurada para *.${rootDomain}.`;
        } catch (wcErr: any) {
          wildcardNote = `Aviso Wildcard DNS-01: ${wcErr?.message || 'requiere un binario de Caddy compilado con caddy-dns/cloudflare y CF_API_TOKEN.'}`;
        }
      }

      const ingStatus = await api.getIngressStatus({ probe: true }).catch(() => null);
      const tlsProbe = (ingStatus?.tls || []).find((t) => t.hostname === targetHostname);
      const httpsReady = Boolean(tlsProbe?.reachable && tlsProbe?.trusted && !tlsProbe?.expired);

      setActivationResult({
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

  const canProceedStep1 = kind === 'sslip' ? Boolean(serverIp.trim()) : Boolean(rootDomain.includes('.'));
  const resolvedIps: string[] = Array.isArray(dnsCheck?.resolvedIps) ? dnsCheck.resolvedIps : [];
  const dnsMatchesServer = Boolean(serverIp && resolvedIps.includes(serverIp.trim()));

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
          { num: 1, label: '1. Tipo de dominio' },
          { num: 2, label: '2. Apuntar DNS' },
          { num: 3, label: '3. Estado HTTPS' },
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
                  desc: 'Cubre todos tus subdominios mediante Cloudflare DNS-01.',
                },
                {
                  id: 'sslip' as const,
                  icon: Zap,
                  title: 'URL gratis sslip.io',
                  desc: 'Sin comprar dominio ni tocar DNS: genera app.IP.sslip.io.',
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
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                  />
                </div>
                {finalHostname && (
                  <div className="sm:col-span-2 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                    Dirección resultante: <strong className="font-mono">https://{finalHostname}</strong>
                  </div>
                )}
              </div>
            ) : (
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
                    onChange={(e) => setHostnameInput(e.target.value)}
                    placeholder={kind === 'wildcard' ? 'miempresa.com' : 'app.miempresa.com'}
                    className={`w-full px-3 py-2 bg-white border border-slate-200 text-sm font-mono ${kind === 'wildcard' ? 'rounded-r-lg' : 'rounded-lg'}`}
                  />
                </div>
              </div>
            )}

            {kind === 'wildcard' && (
              <p className="text-[11px] text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-3 leading-relaxed">
                Los certificados comodín requieren validación DNS-01 y un binario de Caddy compilado con el módulo <code className="font-mono">caddy-dns/cloudflare</code> y <code className="font-mono">CF_API_TOKEN</code>.
              </p>
            )}

            {!fixedProjectId && projects.length > 0 && (
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Proyecto destino (opcional)
                </label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm text-slate-800"
                >
                  <option value="">Registrar en Caddy sin proyecto asignado aún</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
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
                        {cfConfigured ? 'Cloudflare conectado: registro DNS automático' : '¿Usas Cloudflare? Configura el DNS automáticamente'}
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
                          className="rounded border-slate-300"
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
                          className="rounded border-slate-300"
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
                          <KeyRound className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
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
          <div className="space-y-4 text-center py-2">
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

            {activationResult.wildcardNote && (
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 text-left">
                {activationResult.wildcardNote}
              </div>
            )}

            {!activationResult.httpsReady && (
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 text-left leading-relaxed">
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
