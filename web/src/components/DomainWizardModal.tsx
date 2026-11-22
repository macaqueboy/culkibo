import React, { useState, useEffect } from 'react';
import {
  X,
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
  KeyRound
} from 'lucide-react';
import { api, type Project } from '../lib/api';

type WizardKind = 'custom' | 'wildcard' | 'sslip';
type DnsProvider = 'cloudflare' | 'godaddy' | 'namecheap' | 'ovh' | 'ionos' | 'dondominio' | 'otro';

const PROVIDER_GUIDES: Record<DnsProvider, { label: string; steps: string[] }> = {
  cloudflare: {
    label: 'Cloudflare',
    steps: [
      'Entra a dash.cloudflare.com y abre tu dominio.',
      'En el menú izquierdo pulsa «DNS» → «Registros» → «Añadir registro».',
      'Crea el registro A con los valores de la tabla de abajo y pulsa Guardar.'
    ]
  },
  godaddy: {
    label: 'GoDaddy',
    steps: [
      'Entra a tu panel de GoDaddy → «Mis productos» → pulsa «DNS» junto a tu dominio.',
      'Pulsa «Añadir nuevo registro» (o edita el registro A existente que apunte a @).',
      'Copia el Nombre y el Valor IP de abajo, deja TTL en 600 segundos y guarda.'
    ]
  },
  namecheap: {
    label: 'Namecheap',
    steps: [
      'Abre «Domain List» → pulsa «Manage» en tu dominio → pestaña «Advanced DNS».',
      'En Host Records pulsa «Add New Record» → elige «A Record».',
      'Pega el Host y la IP de abajo y confirma con el icono verde.'
    ]
  },
  ovh: {
    label: 'OVH',
    steps: [
      'Accede al Área de Cliente de OVH → «Dominios» → elige tu dominio → «Zona DNS».',
      'Pulsa «Añadir una entrada» → selecciona «A».',
      'Introduce el subdominio (o vacío para la raíz) y pega la IP de tu servidor.'
    ]
  },
  ionos: {
    label: 'IONOS',
    steps: [
      'Entra a IONOS → «Dominios y SSL» → pulsa el engranaje de tu dominio → «DNS».',
      'Pulsa «Añadir registro» → tipo «A».',
      'Pega el nombre de host y la dirección IPv4 indicada abajo y guarda.'
    ]
  },
  dondominio: {
    label: 'DonDominio',
    steps: [
      'En tu panel de DonDominio abre «Dominios» → selecciona tu dominio → «Zona DNS».',
      'Pulsa «Añadir registro DNS» → tipo «A».',
      'Rellena Nombre e IP destino exactamente como ves abajo y guarda.'
    ]
  },
  otro: {
    label: 'Otro proveedor',
    steps: [
      'Abre el panel donde compraste el dominio y busca la sección «Zona DNS» o «Registros DNS».',
      'Crea un registro de tipo «A» con el Nombre y la IP de abajo (TTL 300 o Automático).',
      'Vuelve aquí y pulsa «Comprobar DNS ahora».'
    ]
  }
};

interface DomainWizardModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: () => void;
  onNotify?: (msg: string) => void;
  projectId?: string;
  initialKind?: WizardKind;
}

export const DomainWizardModal: React.FC<DomainWizardModalProps> = ({
  isOpen,
  onClose,
  onComplete,
  onNotify,
  projectId: fixedProjectId,
  initialKind = 'custom'
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

  // Inline Cloudflare quick setup
  const [showCfSetup, setShowCfSetup] = useState(false);
  const [cfTokenInput, setCfTokenInput] = useState('');
  const [cfSaving, setCfSaving] = useState(false);
  const [cfError, setCfError] = useState<string | null>(null);

  // Provider guide & DNS check
  const [provider, setProvider] = useState<DnsProvider>('cloudflare');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [checkingDns, setCheckingDns] = useState(false);
  const [dnsCheck, setDnsCheck] = useState<any>(null);

  // Step 3 activation
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
      setActivationError(null);
      setActivationResult(null);
      setDnsCheck(null);
      if (fixedProjectId) setSelectedProjectId(fixedProjectId);
    }
  }

  useEffect(() => {
    if (!isOpen) return;
    let active = true;
    Promise.all([
      api.getServerIp().catch(() => ({ ip: '' })),
      api.getCloudflareConfig().catch(() => ({ isConfigured: false })),
      fixedProjectId ? Promise.resolve([]) : api.getProjects().catch(() => [])
    ]).then(([ipRes, cfRes, projList]) => {
      if (!active) return;
      if (ipRes?.ip) setServerIp(ipRes.ip);
      setCfConfigured(Boolean(cfRes?.isConfigured));
      if (Array.isArray(projList)) setProjects(projList);
    });
    return () => { active = false; };
  }, [isOpen, fixedProjectId]);

  if (!isOpen) return null;

  const cleanInput = hostnameInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const rootDomain = cleanInput.replace(/^\*\./, '');
  const finalHostname = kind === 'wildcard'
    ? (rootDomain ? `*.${rootDomain}` : '')
    : kind === 'sslip'
      ? (serverIp ? `${(cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app'}.${serverIp.replace(/\./g, '-')}.sslip.io` : '')
      : cleanInput;

  // Calcular qué nombre de registro A mostrar al usuario
  const dnsRecordName = (() => {
    if (kind === 'wildcard') return '*';
    const parts = rootDomain.split('.').filter(Boolean);
    if (parts.length <= 2) return '@';
    return parts.slice(0, parts.length - 2).join('.');
  })();

  const copyValue = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleInlineCfSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cfTokenInput.trim()) return;
    setCfSaving(true);
    setCfError(null);
    try {
      const verify = await api.verifyCloudflareToken(cfTokenInput.trim());
      if (verify.error || verify.valid === false) {
        throw new Error(verify.error || 'El token de Cloudflare no es válido');
      }
      await api.saveCloudflareConfig({ apiToken: cfTokenInput.trim(), useMock: false });
      setCfConfigured(true);
      setAutoCfDns(true);
      setShowCfSetup(false);
      setCfTokenInput('');
      onNotify?.('Cloudflare conectado: ya podemos crear tus DNS automáticamente.');
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

      if (kind === 'sslip') {
        const ip = serverIp.trim();
        if (!ip) throw new Error('Necesitamos la IP IPv4 de tu servidor para crear la dirección sslip.io');
        const sslipRes = await api.issueOnDemandSslip(ip, 'sslip.io');
        if (!sslipRes.success) throw new Error(sslipRes.error || 'No se pudo registrar el host sslip.io');
        const prefix = (cleanInput || 'app').replace(/[^a-z0-9-]/g, '') || 'app';
        targetHostname = `${prefix}.${sslipRes.cert.rootDomain}`;
      }

      const targetProjectId = fixedProjectId || selectedProjectId || null;
      if (targetProjectId) {
        const attached = await api.attachDomainToProject(targetProjectId, {
          hostname: targetHostname,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns
        });
        ingressApplied = Boolean(attached.ingress?.applied);
        ingressMessage = attached.ingress?.message || (ingressApplied ? 'Ruta publicada en Caddy.' : 'Pendiente de Caddy.');
      } else {
        const added = await api.addDomain({
          hostname: targetHostname,
          targetPod: 'citadel',
          targetPort: 8080,
          cloudflareProxied: kind === 'sslip' ? false : cfProxied,
          autoCreateDns: kind !== 'sslip' && cfConfigured && autoCfDns
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
          wildcardNote = `Aviso Wildcard DNS-01: ${wcErr?.message || 'requiere Caddy con módulo caddy-dns/cloudflare y CF_API_TOKEN'}`;
        }
      }

      // Verificar estado real en Caddy
      const ingStatus = await api.getIngressStatus({ probe: true }).catch(() => null);
      const tlsProbe = (ingStatus?.tls || []).find((t) => t.hostname === targetHostname);
      const httpsReady = Boolean(tlsProbe?.reachable && tlsProbe?.trusted && !tlsProbe?.expired);

      setActivationResult({
        hostname: targetHostname,
        ingressApplied: ingressApplied || Boolean(ingStatus?.available),
        ingressMessage,
        wildcardNote,
        httpsReady
      });
      setStep(3);
      onComplete();
      onNotify?.(`Dominio ${targetHostname} configurado`);
    } catch (err: any) {
      setActivationError(err?.message || 'Error al activar el dominio');
    } finally {
      setActivating(false);
    }
  };

  const canProceedStep1 = kind === 'sslip' ? Boolean(serverIp.trim()) : Boolean(rootDomain.includes('.'));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-[2px] p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-white border border-slate-200 rounded-2xl shadow-2xl overflow-hidden my-6">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900">Conectar dominio con HTTPS automático</h3>
            <p className="text-xs text-slate-500 mt-0.5">Paso {step} de 3 — Sin tocar archivos de servidor</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-900 hover:bg-slate-200/70 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Stepper Bar */}
        <div className="px-6 py-3 bg-white border-b border-slate-100 grid grid-cols-3 gap-2 text-xs">
          {[
            { num: 1, label: '1. Elige tipo de dominio' },
            { num: 2, label: '2. Apunta tu DNS' },
            { num: 3, label: '3. Activar HTTPS' }
          ].map((s) => (
            <div
              key={s.num}
              className={`px-3 py-1.5 rounded-lg font-medium text-center border ${
                step === s.num
                  ? 'bg-slate-900 text-white border-slate-900'
                  : step > s.num
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-50 text-slate-400 border-slate-200'
              }`}
            >
              {s.label}
            </div>
          ))}
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
          {activationError && (
            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-600" />
              <span>{activationError}</span>
            </div>
          )}

          {/* STEP 1 */}
          {step === 1 && (
            <div className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setKind('custom')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer space-y-1.5 ${
                    kind === 'custom' ? 'border-slate-900 bg-slate-50 shadow-sm' : 'border-slate-200 hover:border-slate-300 bg-white'
                  }`}
                >
                  <Globe className="w-5 h-5 text-blue-600" />
                  <div className="text-sm font-bold text-slate-900">Dominio propio</div>
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Tu web normal (<code className="font-mono">miweb.com</code> o <code className="font-mono">app.miweb.com</code>).
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setKind('wildcard')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer space-y-1.5 ${
                    kind === 'wildcard' ? 'border-slate-900 bg-slate-50 shadow-sm' : 'border-slate-200 hover:border-slate-300 bg-white'
                  }`}
                >
                  <ShieldCheck className="w-5 h-5 text-amber-600" />
                  <div className="text-sm font-bold text-slate-900">Comodín Wildcard</div>
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Cubre TODOS tus subdominios (<code className="font-mono">*.miweb.com</code>) vía Cloudflare DNS-01.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setKind('sslip')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer space-y-1.5 ${
                    kind === 'sslip' ? 'border-slate-900 bg-slate-50 shadow-sm' : 'border-slate-200 hover:border-slate-300 bg-white'
                  }`}
                >
                  <Zap className="w-5 h-5 text-emerald-600" />
                  <div className="text-sm font-bold text-slate-900">URL gratis al instante</div>
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Sin comprar dominio: genera <code className="font-mono">app.IP.sslip.io</code> en 1 clic.
                  </p>
                </button>
              </div>

              {kind === 'sslip' ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1.5">Nombre del subdominio</label>
                    <input
                      type="text"
                      value={hostnameInput}
                      onChange={(e) => setHostnameInput(e.target.value)}
                      placeholder="mi-app"
                      className="w-full px-3 py-2 bg-white border border-slate-300 rounded-xl text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1.5">IP pública de tu servidor</label>
                    <input
                      type="text"
                      value={serverIp}
                      onChange={(e) => setServerIp(e.target.value)}
                      placeholder="Ej. 203.0.113.10"
                      className="w-full px-3 py-2 bg-white border border-slate-300 rounded-xl text-sm font-mono"
                    />
                  </div>
                  {finalHostname && (
                    <div className="sm:col-span-2 p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                      Tu dirección gratis quedará lista en: <strong className="font-mono">https://{finalHostname}</strong> (no necesitas configurar DNS).
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    {kind === 'wildcard' ? 'Tu dominio raíz (sin *. delante)' : 'Escribe tu dominio'}
                  </label>
                  <div className="flex items-center">
                    {kind === 'wildcard' && (
                      <span className="px-3 py-2 bg-slate-100 border border-r-0 border-slate-300 rounded-l-xl text-sm font-mono text-slate-600">
                        *.
                      </span>
                    )}
                    <input
                      type="text"
                      value={hostnameInput}
                      onChange={(e) => setHostnameInput(e.target.value)}
                      placeholder={kind === 'wildcard' ? 'miempresa.com' : 'app.miempresa.com'}
                      className={`w-full px-3 py-2 bg-white border border-slate-300 text-sm font-mono ${kind === 'wildcard' ? 'rounded-r-xl' : 'rounded-xl'}`}
                    />
                  </div>
                </div>
              )}

              {!fixedProjectId && projects.length > 0 && (
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    ¿A qué proyecto quieres conectar este dominio?
                  </label>
                  <select
                    value={selectedProjectId}
                    onChange={(e) => setSelectedProjectId(e.target.value)}
                    className="w-full px-3 py-2 bg-white border border-slate-300 rounded-xl text-sm text-slate-800"
                  >
                    <option value="">Solo registrar en Caddy (sin proyecto asignado aún)</option>
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          )}

          {/* STEP 2 */}
          {step === 2 && (
            <div className="space-y-4">
              {kind === 'sslip' ? (
                <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 space-y-1.5">
                  <div className="font-bold flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    No necesitas tocar ningún registro DNS
                  </div>
                  <p>
                    <strong className="font-mono">{finalHostname}</strong> resuelve automáticamente a tu IP{' '}
                    <strong className="font-mono">{serverIp}</strong>. Pulsa «Activar HTTPS ahora» para publicarlo.
                  </p>
                </div>
              ) : (
                <>
                  {/* Cloudflare automatic path */}
                  <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/70 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <Cloud className="w-4 h-4 text-orange-500" />
                        <span className="text-xs font-bold text-slate-900">
                          {cfConfigured ? 'Cloudflare conectado: configuración automática en 1 clic' : '¿Usas Cloudflare? Conéctalo aquí para hacerlo en 1 clic'}
                        </span>
                      </div>
                      {!cfConfigured && (
                        <button
                          type="button"
                          onClick={() => setShowCfSetup((prev) => !prev)}
                          className="text-xs font-semibold text-blue-600 hover:underline cursor-pointer"
                        >
                          {showCfSetup ? 'Ocultar' : 'Conectar token ahora'}
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
                          <span>Crear automáticamente el registro DNS A apuntando a <strong className="font-mono">{serverIp || 'este servidor'}</strong></span>
                        </label>
                        <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={cfProxied}
                            onChange={(e) => setCfProxied(e.target.checked)}
                            className="rounded border-slate-300"
                          />
                          <span>Activar protección proxy de Cloudflare (nube naranja)</span>
                        </label>
                      </div>
                    ) : showCfSetup ? (
                      <form onSubmit={handleInlineCfSave} className="space-y-2.5 pt-2 border-t border-slate-200">
                        <p className="text-[11px] text-slate-600">
                          Crea un API Token en Cloudflare con permiso <strong>Zone → DNS → Edit</strong> y pégalo aquí:
                        </p>
                        <div className="flex gap-2">
                          <div className="relative flex-1">
                            <KeyRound className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                            <input
                              type="password"
                              value={cfTokenInput}
                              onChange={(e) => setCfTokenInput(e.target.value)}
                              placeholder="Pega tu Cloudflare API Token"
                              className="w-full pl-8 pr-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
                            />
                          </div>
                          <button
                            type="submit"
                            disabled={cfSaving || !cfTokenInput.trim()}
                            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                          >
                            {cfSaving ? 'Verificando…' : 'Conectar'}
                          </button>
                        </div>
                        {cfError && <p className="text-xs text-rose-700">{cfError}</p>}
                      </form>
                    ) : null}
                  </div>

                  {/* Manual DNS guide by provider */}
                  <div className="space-y-3">
                    <div className="text-xs font-semibold text-slate-700">
                      O configúralo manualmente en tu proveedor de dominios:
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

                      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-200 text-xs">
                        <div className="bg-white border border-slate-200 rounded-lg p-2.5">
                          <div className="text-[10px] text-slate-400">Tipo</div>
                          <div className="font-mono font-bold text-slate-900 mt-0.5">A</div>
                        </div>
                        <div className="bg-white border border-slate-200 rounded-lg p-2.5 flex items-center justify-between gap-1">
                          <div className="min-w-0">
                            <div className="text-[10px] text-slate-400">Nombre / Host</div>
                            <div className="font-mono font-bold text-slate-900 truncate mt-0.5">{dnsRecordName}</div>
                          </div>
                          <button type="button" onClick={() => copyValue(dnsRecordName, 'host')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer">
                            {copiedKey === 'host' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        <div className="bg-white border border-slate-200 rounded-lg p-2.5 flex items-center justify-between gap-1">
                          <div className="min-w-0">
                            <div className="text-[10px] text-slate-400">Valor (IP servidor)</div>
                            <div className="font-mono font-bold text-slate-900 truncate mt-0.5">{serverIp || 'Tu IP pública'}</div>
                          </div>
                          {serverIp && (
                            <button type="button" onClick={() => copyValue(serverIp, 'ip')} className="p-1 text-slate-400 hover:text-slate-900 cursor-pointer">
                              {copiedKey === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center justify-between gap-2 pt-1">
                        <button
                          type="button"
                          onClick={handleCheckDns}
                          disabled={checkingDns}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-xs font-semibold text-slate-700 cursor-pointer"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${checkingDns ? 'animate-spin' : ''}`} />
                          <span>{checkingDns ? 'Comprobando…' : 'Comprobar DNS ahora'}</span>
                        </button>
                        {dnsCheck && (
                          <span className={`text-xs font-medium ${dnsCheck.resolvedIps?.length ? 'text-emerald-700' : 'text-amber-700'}`}>
                            {dnsCheck.resolvedIps?.length
                              ? `Apunta a: ${dnsCheck.resolvedIps.join(', ')}`
                              : dnsCheck.error || 'Aún no resuelve (puede tardar 1-5 min)'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* STEP 3 */}
          {step === 3 && activationResult && (
            <div className="space-y-4 text-center py-2">
              <div className={`w-14 h-14 rounded-2xl mx-auto flex items-center justify-center border ${
                activationResult.httpsReady
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-600'
                  : 'bg-blue-50 border-blue-200 text-blue-600'
              }`}>
                <Lock className="w-7 h-7" />
              </div>

              <div>
                <h4 className="text-lg font-bold text-slate-900">
                  {activationResult.httpsReady ? '¡Candado HTTPS verificado y activo!' : `Dominio ${activationResult.hostname} guardado`}
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
                  Caddy emitirá tu certificado HTTPS automáticamente en la primera visita en cuanto el DNS apunte a este servidor. Puedes comprobar el candado en cualquier momento desde la tabla de dominios.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 border-t border-slate-200 flex items-center justify-between gap-2">
          {step === 1 && (
            <>
              <button type="button" onClick={onClose} className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:bg-slate-200/70 cursor-pointer">
                Cancelar
              </button>
              <button
                type="button"
                disabled={!canProceedStep1}
                onClick={() => setStep(2)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                <span>Siguiente: Configurar DNS</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          {step === 2 && (
            <>
              <button
                type="button"
                onClick={() => setStep(1)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:bg-slate-200/70 cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Atrás</span>
              </button>
              <button
                type="button"
                disabled={activating}
                onClick={handleActivate}
                className="inline-flex items-center gap-1.5 px-5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                {activating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                <span>{activating ? 'Activando HTTPS…' : 'Activar HTTPS ahora'}</span>
              </button>
            </>
          )}

          {step === 3 && (
            <button
              type="button"
              onClick={onClose}
              className="ml-auto px-5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer"
            >
              Listo, volver a Dominios
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
