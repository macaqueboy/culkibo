import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Cloud,
  Plus,
  Zap,
  Trash2,
  CheckCircle2,
  RefreshCw,
  Server,
  Lock,
  Search,
  ArrowRightLeft,
  AlertTriangle,
  Link2,
  X
} from 'lucide-react';
import type { DomainItem, SslCertificate, IngressStatus, TlsProbe } from '../lib/api';
import { api } from '../lib/api';

/** Fecha corta en castellano para las caducidades de certificado. */
const formatDate = (iso?: string | null) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' });
};

interface DomainManagerProps {
  onNotify?: (msg: string) => void;
  liveSslProgress?: { stage: string; progress: number; message: string; domain?: string } | null;
  projectId?: string;
  projectDomains?: string[];
  onDomainAddedToProject?: (domain: string) => void;
  onDomainRemovedFromProject?: (domain: string) => void;
}

export const DomainManager: React.FC<DomainManagerProps> = ({ onNotify, liveSslProgress, projectId, projectDomains, onDomainAddedToProject, onDomainRemovedFromProject }) => {
  const [domains, setDomains] = useState<DomainItem[]>([]);
  const [certs, setCerts] = useState<SslCertificate[]>([]);
  const [ingress, setIngress] = useState<IngressStatus | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [domainTypeFilter, setDomainTypeFilter] = useState<'all' | 'wildcard' | 'custom' | 'sslip'>('all');
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [showWildcardModal, setShowWildcardModal] = useState(false);
  const [showSslipModal, setShowSslipModal] = useState(false);
  const [showDnsVerifyModal, setShowDnsVerifyModal] = useState(false);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<any>(null);
  const [verifyingDns, setVerifyingDns] = useState(false);

  // Ingress Route Test Modal
  const [showIngressModal, setShowIngressModal] = useState(false);
  const [ingressResult, setIngressResult] = useState<any>(null);
  const [testingIngress, setTestingIngress] = useState(false);

  // New Domain Form
  const [newHostname, setNewHostname] = useState('');
  const [newTargetEntorno, setNewTargetEntorno] = useState<'forge' | 'citadel'>('forge');
  const [newTargetPort, setNewTargetPort] = useState(3001);
  const [newProxied, setNewProxied] = useState(true);
  const [autoCreateCfRecord, setAutoCreateCfRecord] = useState(true);

  // Link Existing Domain
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [selectedLinkDomain, setSelectedLinkDomain] = useState('');

  // sslip.io Form
  const [sslipIp, setSslipIp] = useState('127.0.0.1');
  const [issuingSslip, setIssuingSslip] = useState(false);

  // Progreso SSL por WebSocket (ajuste derivado al cambiar la prop sin cascada de efecto).
  const [prevSslProgressMsg, setPrevSslProgressMsg] = useState<string | undefined>(undefined);
  if (liveSslProgress?.message !== prevSslProgressMsg) {
    setPrevSslProgressMsg(liveSslProgress?.message);
    if (liveSslProgress?.message) {
      setErrorBanner(liveSslProgress.message);
    }
  }

  const loadData = async () => {
    try {
      setLoading(true);
      // El estado del ingress se pide en paralelo y nunca tumba la vista: sin
      // plano de datos el resto de la pantalla tiene que seguir funcionando.
      const [domRes, certRes, ingRes] = await Promise.all([
        api.getDomains(),
        api.getCertificates(),
        api.getIngressStatus().catch(() => null)
      ]);
      setDomains(domRes.domains || []);
      setCerts(certRes.certificates || []);
      setIngress(ingRes);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getDomains(),
      api.getCertificates(),
      api.getIngressStatus().catch(() => null)
    ])
      .then(([domRes, certRes, ingRes]) => {
        if (!active) return;
        setDomains(domRes.domains || []);
        setCerts(certRes.certificates || []);
        setIngress(ingRes);
      })
      .catch((e) => console.error(e))
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  /** Handshake TLS real de este dominio, si ya se ha sondeado. */
  const tlsFor = (hostname: string): TlsProbe | null =>
    (ingress?.tls || []).find(t => t.hostname === hostname) || null;

  /** Ruta viva en Caddy que sirve este hostname. */
  const routeFor = (hostname: string) =>
    (ingress?.routes || []).find(r => r.hosts.includes(hostname)) || null;

  /** Motivo por el que un dominio no tiene ruta publicada. */
  const skippedReasonFor = (hostname: string) =>
    (ingress?.skipped || []).find(s => s.hostnames.includes(hostname))?.reason || null;

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const res = await api.reconcileIngress();
      await loadData();
      if (onNotify) {
        onNotify(res.applied ? 'Rutas de ingress reconciliadas con Caddy' : (res.message || 'No se pudo reconciliar el ingress'));
      }
    } catch (err: any) {
      setErrorBanner(`Error al reconciliar el ingress: ${err.message}`);
    } finally {
      setReconciling(false);
    }
  };

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    const hostname = newHostname.trim();
    if (!hostname) return;

    try {
      if (projectId) {
        // Una sola acción: crea el registro, lo vincula al proyecto y publica
        // la ruta en Caddy. Antes eran tres pasos y el tercero no existía.
        const res = await api.attachDomainToProject(projectId, {
          hostname,
          targetPod: newTargetEntorno,
          targetPort: newTargetPort,
          cloudflareProxied: newProxied,
          autoCreateDns: autoCreateCfRecord
        });
        if (onDomainAddedToProject) onDomainAddedToProject(hostname);
        if (onNotify) {
          onNotify(res.ingress?.applied
            ? `${hostname} vinculado y enrutado hacia ${(res.ingress.upstreams || []).join(', ')}`
            : `${hostname} vinculado. Ingress sin aplicar: ${res.ingress?.message || 'sin detalle'}`);
        }
      } else {
        const res = await api.addDomain({
          hostname,
          targetPod: newTargetEntorno,
          targetPort: newTargetPort,
          cloudflareProxied: newProxied,
          autoCreateDns: autoCreateCfRecord
        });
        const outcome = (res as any).ingress;
        if (onNotify) {
          onNotify(outcome?.applied
            ? `Dominio ${hostname} añadido y enrutado en Caddy`
            : `Dominio ${hostname} añadido. Ingress sin aplicar: ${outcome?.message || 'sin detalle'}`);
        }
      }

      setShowAddModal(false);
      setNewHostname('');
      loadData();
    } catch (err: any) {
      setErrorBanner(`Error al añadir dominio: ${err.message}`);
    }
  };

  const handleLinkDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedLinkDomain || !projectId) return;
    try {
      const res = await api.attachDomainToProject(projectId, { hostname: selectedLinkDomain });
      if (onDomainAddedToProject) onDomainAddedToProject(selectedLinkDomain);
      setShowLinkModal(false);
      setSelectedLinkDomain('');
      loadData();
      if (onNotify) {
        onNotify(res.ingress?.applied
          ? `${selectedLinkDomain} vinculado y enrutado hacia ${(res.ingress.upstreams || []).join(', ')}`
          : `${selectedLinkDomain} vinculado. Ingress sin aplicar: ${res.ingress?.message || 'sin detalle'}`);
      }
    } catch (err: any) {
      setErrorBanner(`Error al vincular el dominio: ${err.message}`);
    }
  };

  const handleToggleProxy = async (id: string, hostname: string) => {
    try {
      const updated = await api.toggleDomainProxy(id);
      setDomains(prev => prev.map(d => d.id === id ? { ...d, cloudflareProxied: updated.cloudflareProxied } : d));
      if (onNotify) {
        onNotify(updated.cloudflareProxied ? `Proxy Cloudflare activado para ${hostname}` : `Proxy Cloudflare desactivado para ${hostname}`);
      }
    } catch (err: any) {
      setErrorBanner(`Fallo al alternar el proxy de Cloudflare: ${err.message}`);
    }
  };

  const handleToggleEntorno = async (id: string, currentPod: 'forge' | 'citadel', hostname: string) => {
    const nextPod: 'forge' | 'citadel' = currentPod === 'forge' ? 'citadel' : 'forge';
    const nextPort = nextPod === 'forge' ? 3001 : 8080;
    try {
      const updated = await api.updateDomain(id, { targetPod: nextPod, targetPort: nextPort });
      setDomains(prev => prev.map(d => d.id === id ? { ...d, targetPod: updated.targetPod, targetPort: updated.targetPort } : d));
      if (onNotify) {
        onNotify(`Tráfico de ${hostname} redirigido a ${nextPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)'}`);
      }
    } catch (err: any) {
      setErrorBanner(`Fallo al cambiar el entorno de destino: ${err.message}`);
    }
  };

  const handleDeleteDomain = async (id: string, name: string) => {
    // Desvincular y eliminar la ruta son la misma acción: dejar el registro sin
    // ruta, o la ruta sin registro, es exactamente la divergencia que se quiere
    // evitar.
    if (projectId) {
      if (!confirm(`¿Confirmas desvincular ${name} del proyecto y retirar su ruta del ingress?`)) return;
      try {
        await api.detachDomainFromProject(projectId, id);
        if (onDomainRemovedFromProject) onDomainRemovedFromProject(name);
        loadData();
        if (onNotify) onNotify(`Dominio ${name} desvinculado y ruta retirada`);
      } catch (err: any) {
        setErrorBanner(`Error al desvincular el dominio: ${err.message}`);
      }
      return;
    }

    if (!confirm(`¿Confirmas eliminar el dominio ${name} permanentemente?`)) return;
    try {
      await api.deleteDomain(id);
      loadData();
      if (onNotify) onNotify(`Dominio ${name} eliminado y ruta retirada`);
    } catch (err: any) {
      setErrorBanner(`Error al eliminar dominio: ${err.message}`);
    }
  };

  const handleVerifyDns = async (hostname: string) => {
    setVerifyingDns(true);
    setShowDnsVerifyModal(true);
    setDnsVerifyResult(null);
    try {
      const res = await api.verifyDns(hostname);
      setDnsVerifyResult(res);
    } catch (err: any) {
      setDnsVerifyResult({ error: err.message });
    } finally {
      setVerifyingDns(false);
    }
  };

  const handleTestIngress = async (hostname: string) => {
    setTestingIngress(true);
    setShowIngressModal(true);
    setIngressResult(null);
    try {
      const res = await api.getIngressResolution(hostname);
      setIngressResult(res);
    } catch (err: any) {
      setIngressResult({ error: err.message });
    } finally {
      setTestingIngress(false);
    }
  };

  const handleIssueSslip = async () => {
    setIssuingSslip(true);
    try {
      const res = await api.issueOnDemandSslip(sslipIp, 'sslip.io');
      if (res.success) {
        setShowSslipModal(false);
        loadData();
        // «Registrado», no «emitido»: aquí no se emite nada. Caddy emitirá el
        // certificado en la primera conexión HTTPS a ese host.
        if (onNotify) onNotify(`Host ${res.cert.rootDomain} registrado. Caddy emitirá su certificado en el primer acceso HTTPS.`);
      } else {
        setErrorBanner(`Error de sslip: ${res.error}`);
      }
    } catch (err: any) {
      setErrorBanner(`Error de sslip: ${err.message}`);
    } finally {
      setIssuingSslip(false);
    }
  };

  const filteredDomains = domains.filter(d => {
    if (projectDomains && !projectDomains.includes(d.hostname)) return false;
    const matchesSearch = d.hostname.toLowerCase().includes(searchFilter.toLowerCase());
    if (!matchesSearch) return false;
    if (domainTypeFilter === 'wildcard') return d.isWildcard;
    if (domainTypeFilter === 'sslip') return d.hostname.includes('.sslip.io') || d.hostname.includes('.nip.io');
    if (domainTypeFilter === 'custom') return !d.isWildcard && !d.hostname.includes('.sslip.io') && !d.hostname.includes('.nip.io');
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Error / Alert Banner */}
      {errorBanner && (
        <div className="flex items-center justify-between p-4 rounded-2xl bg-red-50 border border-red-200 text-red-700 text-xs font-medium animate-fade-in shadow-sm">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorBanner}</span>
          </div>
          <button
            onClick={() => setErrorBanner(null)}
            className="text-red-500 hover:text-red-800 p-1 rounded-lg hover:bg-red-100 cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Estado real del plano de datos.
          Sin Caddy no hay ingress, y el panel tiene que decirlo en vez de
          dibujar dominios «activos» que nadie sirve. */}
      {ingress && (
        <div className={`p-4 rounded-2xl border text-xs shadow-sm ${
          ingress.available
            ? (ingress.inSync ? 'bg-white border-slate-200' : 'bg-amber-50 border-amber-200')
            : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div className={`w-8 h-8 rounded-xl border flex items-center justify-center shrink-0 ${
                ingress.available ? 'bg-emerald-50 border-emerald-200 text-emerald-600' : 'bg-slate-100 border-slate-200 text-slate-500'
              }`}>
                {ingress.available ? <Zap className="w-4 h-4" /> : <ShieldOff className="w-4 h-4" />}
              </div>
              <div>
                <div className="font-semibold text-slate-900">
                  {ingress.available
                    ? `Plano de datos: Caddy en ${ingress.adminUrl}`
                    : 'Plano de datos no disponible'}
                </div>
                <p className="text-slate-600 mt-0.5 max-w-2xl leading-relaxed">{ingress.message}</p>
                {ingress.available && (
                  <p className="text-slate-500 mt-1">
                    {ingress.routesManaged} ruta(s) publicadas
                    {ingress.inSync
                      ? ' · sin divergencia con el estado esperado'
                      : ` · ${ingress.drift.missing.length} sin publicar, ${ingress.drift.unexpected.length} sobrantes`}
                    {ingress.lastReconcile && ` · última reconciliación: ${new Date(ingress.lastReconcile.at).toLocaleTimeString('es-ES')}`}
                  </p>
                )}
                {ingress.skipped.length > 0 && (
                  <ul className="mt-2 space-y-0.5 text-slate-500">
                    {ingress.skipped.map(s => (
                      <li key={s.hostnames.join(',')}>
                        <span className="font-mono text-slate-700">{s.hostnames.join(', ')}</span>: {s.reason}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleReconcile}
                disabled={reconciling || !ingress.available}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                title="Volver a aplicar en Caddy el estado que Culkibo espera"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${reconciling ? 'animate-spin' : ''}`} />
                <span>Reconciliar rutas</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Top Header & Actions Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-white border border-slate-200 shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-600">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Dominios y certificados SSL
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Conecta tus dominios, activa certificados Wildcard (*.tudominio.com) y enruta tráfico a tus aplicaciones.
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {projectId && (
            <button
              onClick={() => setShowLinkModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-semibold transition-all shadow-sm cursor-pointer active:scale-95"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Vincular existente</span>
            </button>
          )}

          {/* Add Domain */}
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition-all shadow-sm cursor-pointer active:scale-95"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Añadir dominio</span>
          </button>

          {/* Comodines: explica que no se emiten, en vez de fingir que sí */}
          <button
            onClick={() => setShowWildcardModal(true)}
            title="Culkibo no emite certificados comodín"
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs font-medium transition-all cursor-pointer"
          >
            <ShieldOff className="w-3.5 h-3.5 text-slate-500" />
            <span>SSL wildcard</span>
          </button>

          {/* Zero Config sslip.io */}
          <button
            onClick={() => setShowSslipModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs font-medium transition-all cursor-pointer"
          >
            <Server className="w-3.5 h-3.5 text-blue-600" />
            <span>Wildcard rápido (sslip.io)</span>
          </button>

          {/* Reload Data */}
          <button
            onClick={loadData}
            className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-600 hover:text-slate-900 transition-all cursor-pointer"
            title="Recargar dominios y certificados"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100/80 border border-slate-200 rounded-xl text-xs">
          <button
            onClick={() => setDomainTypeFilter('all')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
              domainTypeFilter === 'all'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Todos ({domains.length})
          </button>
          <button
            onClick={() => setDomainTypeFilter('wildcard')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
              domainTypeFilter === 'wildcard'
                ? 'bg-amber-100/80 text-amber-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Wildcards ({domains.filter(d => d.isWildcard).length})
          </button>
          <button
            onClick={() => setDomainTypeFilter('custom')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
              domainTypeFilter === 'custom'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Personalizados ({domains.filter(d => !d.isWildcard && !d.hostname.includes('.sslip.io')).length})
          </button>
          <button
            onClick={() => setDomainTypeFilter('sslip')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
              domainTypeFilter === 'sslip'
                ? 'bg-blue-100/80 text-blue-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Zero-Config sslip ({domains.filter(d => d.hostname.includes('.sslip.io') || d.hostname.includes('.nip.io')).length})
          </button>
        </div>

        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Buscar por nombre de dominio..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-white border border-slate-300 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-amber-500 focus:ring-2 focus:ring-amber-500/10 transition-all"
          />
        </div>
      </div>

      {/* Domains Table */}
      <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
 <tr className="border-b border-slate-200 bg-slate-50/80 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4">Dominio</th>
                <th className="py-3 px-4">Entorno destino</th>
                <th className="py-3 px-4">Ruta en Caddy</th>
                <th className="py-3 px-4">Proxy Cloudflare</th>
                <th className="py-3 px-4">TLS servido (verificado)</th>
                <th className="py-3 px-4">Comprobación</th>
                <th className="py-3 px-4 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredDomains.map((domain) => {
                const isForge = domain.targetPod === 'forge';
                const probe = tlsFor(domain.hostname);
                const liveRoute = routeFor(domain.hostname);
                const skippedReason = skippedReasonFor(domain.hostname);

                return (
                  <tr key={domain.id} className="hover:bg-slate-50/70 transition-colors">
                    {/* Hostname */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-900">
                          {domain.hostname}
                        </span>
                        {domain.isWildcard && (
                          <span className="px-1.5 py-0.5 rounded-lg text-[10px] font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                            Comodín
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] text-slate-400">
                        ID: {domain.id}
                      </span>
                    </td>

                    {/* Target Entorno Switcher */}
                    <td className="py-3.5 px-4">
                      <button
                        onClick={() => handleToggleEntorno(domain.id, domain.targetPod, domain.hostname)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border cursor-pointer transition-all hover:scale-105 active:scale-95 ${
                          isForge
                            ? 'bg-amber-50 border-amber-200 text-amber-800 hover:bg-amber-100'
                            : 'bg-blue-50 border-blue-200 text-blue-800 hover:bg-blue-100'
                        }`}
                        title={`Clic para cambiar el destino a ${isForge ? 'Producción (:8080)' : 'Desarrollo en vivo (:3001)'}`}
                      >
                        <span>{isForge ? 'Desarrollo' : 'Producción'}</span>
                        <span className="text-slate-500">:{domain.targetPort}</span>
                        <ArrowRightLeft className="w-3 h-3 ml-0.5 opacity-60" />
                      </button>
                    </td>

                    {/* Ruta real publicada en Caddy, no la intención guardada */}
                    <td className="py-3.5 px-4">
                      {liveRoute ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-emerald-700 font-semibold">
                            <Link2 className="w-3.5 h-3.5 text-emerald-600" />
                            <span>Publicada</span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            {liveRoute.upstreams.join(', ')}
                            {liveRoute.weights && ` · pesos ${liveRoute.weights.join('/')}`}
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-slate-500 font-medium">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>Sin ruta</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[220px]">
                            {skippedReason || (ingress && !ingress.available ? 'No hay plano de datos' : 'Todavía no publicada')}
                          </div>
                        </div>
                      )}
                    </td>

                    {/* Cloudflare Edge Proxy Toggle Button */}
                    <td className="py-3.5 px-4">
                      <button
                        onClick={() => handleToggleProxy(domain.id, domain.hostname)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs cursor-pointer border transition-all hover:scale-105 active:scale-95 font-medium ${
                          domain.cloudflareProxied
                            ? 'bg-orange-50 border-orange-200 text-orange-700 hover:bg-orange-100'
                            : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                        }`}
                        title={domain.cloudflareProxied ? 'Proxy Cloudflare activo (clic para pasar a Solo DNS)' : 'Solo DNS (clic para activar el proxy Cloudflare)'}
                      >
                        <Cloud className={`w-3.5 h-3.5 ${domain.cloudflareProxied ? 'fill-orange-400 text-orange-500' : 'text-slate-400'}`} />
                        <span>{domain.cloudflareProxied ? 'Proxy activo (nube ☁️)' : 'Solo DNS (gris ☁️)'}</span>
                      </button>
                    </td>

                    {/* TLS realmente servido.
                        Esta columna mostraba `sslStatus === 'active'` leído de
                        nuestro propio JSON, y unos «días restantes» calculados
                        sobre una caducidad que nos inventábamos al «emitir».
                        Ahora sale de un handshake TLS contra el dominio. */}
                    <td className="py-3.5 px-4">
                      {!probe ? (
                        <span className="text-[11px] text-slate-400">Sin comprobar todavía</span>
                      ) : probe.reachable && probe.notAfter ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5">
                            {probe.trusted && !probe.expired ? (
                              <ShieldCheck className="w-4 h-4 text-emerald-600" />
                            ) : (
                              <ShieldAlert className="w-4 h-4 text-amber-600" />
                            )}
                            <span className={`font-semibold ${probe.trusted && !probe.expired ? 'text-emerald-700' : 'text-amber-700'}`}>
                              {probe.issuer || probe.issuerCN || 'Emisor desconocido'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Caduca el {formatDate(probe.notAfter)}
                            {typeof probe.daysRemaining === 'number' && ` · ${probe.daysRemaining} días`}
                          </div>
                          {!probe.trusted && (
                            <div className="text-[11px] text-amber-700">
                              Cadena no validada: {probe.trustError || 'motivo desconocido'}
                            </div>
                          )}
                          {probe.wildcard && (
                            <div className="text-[11px] text-slate-400">Sondeado en {probe.probed}</div>
                          )}
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-slate-500 font-medium">
                            <ShieldOff className="w-4 h-4 text-slate-400" />
                            <span>Sin handshake TLS</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[220px]">
                            {probe.error || 'El servidor no presentó ningún certificado'}
                          </div>
                          {domain.certClaim && (
                            <div className="text-[11px] text-slate-400">
                              {domain.certClaim.managedBy
                                ? 'El registro interno sólo anota que el TLS lo emite Caddy bajo demanda'
                                : `El registro interno afirma ${domain.certClaim.issuer ?? 'un emisor desconocido'}, sin verificar`}
                            </div>
                          )}
                        </div>
                      )}
                    </td>

                    {/* DNS Verification & Ingress Test */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleVerifyDns(domain.hostname)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer transition-colors"
                          title="Comprobar resolución DNS"
                        >
                          <Search className="w-3 h-3 text-slate-500" />
                          <span>DNS</span>
                        </button>
                        <button
                          onClick={() => handleTestIngress(domain.hostname)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-800 text-xs font-medium cursor-pointer transition-colors"
                          title="Simular enrutamiento"
                        >
                          <Zap className="w-3 h-3 text-amber-600" />
                          <span>Ruta</span>
                        </button>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDeleteDomain(domain.id, domain.hostname)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                        title="Eliminar dominio"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}

              {filteredDomains.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No se encontraron dominios con ese criterio de búsqueda.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Registro interno de certificados.
          Es lo que Culkibo anotó al emitir, no lo que un navegador recibe: lo
          verificado está arriba, en la columna «TLS servido». Se etiqueta como
          tal para que nadie vuelva a leerlo como una comprobación. */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-slate-500" />
            <h3 className="text-sm font-bold text-slate-900">
              Registro interno de certificados
            </h3>
          </div>
          <span className="text-xs font-medium text-slate-500">
            Sólo certificados que existen. Lo verificado está en el handshake
          </span>
        </div>

        {certs.length === 0 && (
          <p className="text-xs text-slate-500 leading-relaxed">
            El registro está vacío. No es un error: Culkibo no guarda copia de los
            certificados que emite Caddy bajo demanda. El estado real de cada dominio
            sale del handshake TLS de la tabla de arriba.
          </p>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {certs.map((cert) => {
            const delegated = cert.status === 'delegated';
            return (
            <div
              key={cert.id}
              className="p-4 rounded-xl bg-slate-50/70 border border-slate-200 flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">
                      {cert.domain}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      {delegated ? 'Emisor: lo decide Caddy al emitir' : `Emisor: ${cert.issuer ?? 'desconocido'}`}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-200 shrink-0">
                    {delegated
                      ? 'Bajo demanda'
                      : cert.daysRemaining === null
                        ? 'Sin caducidad legible'
                        : `${cert.daysRemaining} días (leído del X.509)`}
                  </span>
                </div>

                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  {delegated ? (
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      {cert.message ?? 'Culkibo no almacena ni la clave ni la caducidad de este certificado.'}
                    </p>
                  ) : (
                    <>
                      <div>Algoritmo: <span className="font-semibold text-slate-800">{cert.keyType ?? 'desconocido'}</span></div>
                      <div className="truncate font-mono text-[11px]">Huella: <span className="text-slate-500">{cert.fingerprint ?? '—'}</span></div>
                    </>
                  )}
                  <div>SANs: <span className="font-semibold text-amber-700">{cert.sans?.join(', ')}</span></div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200 flex items-center justify-between gap-2 text-[11px] text-slate-500">
                <span>{delegated ? 'Almacenamiento: volumen de Caddy' : `Almacenamiento: ./data/certs/${cert.rootDomain}`}</span>
                {(() => {
                  const verified = (ingress?.tls || []).find(t => t.probed === cert.rootDomain && t.reachable && t.notAfter);
                  return verified ? (
                    <span className="text-emerald-700 font-medium flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      Servido de verdad: caduca el {formatDate(verified.notAfter)}
                    </span>
                  ) : (
                    <span className="text-slate-500 font-medium">Sin confirmar en el servidor</span>
                  );
                })()}
              </div>
            </div>
            );
          })}
        </div>
      </div>

      {/* --- MODAL: LINK EXISTING DOMAIN --- */}
      {showLinkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <h3 className="text-base font-bold text-slate-900">
              Vincular dominio existente
            </h3>
            <form onSubmit={handleLinkDomain} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Seleccionar dominio
                </label>
                <select
                  value={selectedLinkDomain}
                  onChange={(e) => setSelectedLinkDomain(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-indigo-500"
                  required
                >
                  <option value="" disabled>-- Selecciona un dominio --</option>
                  {domains.filter(d => !projectDomains?.includes(d.hostname)).map(d => (
                    <option key={d.id} value={d.hostname}>{d.hostname}</option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  Solo se muestran los dominios que aún no están vinculados a este proyecto.
                </p>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowLinkModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={!selectedLinkDomain}
                  className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-sm cursor-pointer active:scale-95 transition-all disabled:opacity-50"
                >
                  Vincular al proyecto
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: ADD DOMAIN --- */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <h3 className="text-base font-bold text-slate-900">
              Añadir nuevo dominio
            </h3>

            <form onSubmit={handleAddDomain} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Nombre de dominio o wildcard
                </label>
                <input
                  type="text"
                  placeholder="ej. *.miempresa.com o app.miempresa.com"
                  value={newHostname}
                  onChange={(e) => setNewHostname(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-amber-500 focus:ring-2 focus:ring-amber-500/10 transition-all font-mono"
                  required
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Usa <code>*.</code> para abarcar todos los subdominios (ej. <code>*.culkibo.dev</code>)
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">Entorno destino</label>
                  <select
                    value={newTargetEntorno}
                    onChange={(e) => {
                      const val = e.target.value as 'forge' | 'citadel';
                      setNewTargetEntorno(val);
                      setNewTargetPort(val === 'forge' ? 3001 : 8080);
                    }}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-amber-500"
                  >
                    <option value="forge">Desarrollo (puerto 3001)</option>
                    <option value="citadel">Producción (puerto 8080)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">Puerto interno</label>
                  <input
                    type="number"
                    value={newTargetPort}
                    onChange={(e) => setNewTargetPort(parseInt(e.target.value, 10))}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-amber-500"
                  />
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-100">
                <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newProxied}
                    onChange={(e) => setNewProxied(e.target.checked)}
                    className="rounded-lg border-slate-300 text-amber-600 focus:ring-0"
                  />
                  <span>Activar Proxy Cloudflare (Nube Naranja ☁️ CDN/WAF)</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={autoCreateCfRecord}
                    onChange={(e) => setAutoCreateCfRecord(e.target.checked)}
                    className="rounded-lg border-slate-300 text-amber-600 focus:ring-0"
                  />
                  <span>Crear automáticamente registro A/CNAME en Cloudflare</span>
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-sm cursor-pointer active:scale-95 transition-all"
                >
                  Guardar y enrutar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: WILDCARD DNS-01 — NO IMPLEMENTADO --- */}
      {/*
        Antes este modal tenía una barra de progreso con seis etapas ACME. Las
        etapas eran `setTimeout`, el certificado un PEM inventado y la caducidad
        un `Date.now() + 90 días` escrito a mano. Se ha sustituido por lo que es
        cierto: Culkibo no emite comodines, y el TLS por host ya funciona solo.
      */}
      {showWildcardModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <div className="flex items-center gap-2 text-slate-600">
              <ShieldOff className="w-5 h-5" />
              <h3 className="text-base font-bold text-slate-900">
                Certificados comodín (*.tudominio.com)
              </h3>
            </div>

            <div className="p-3.5 rounded-xl bg-amber-50/70 border border-amber-200">
              <p className="text-xs text-amber-900 leading-relaxed">
                <span className="font-semibold">Culkibo no emite certificados comodín.</span>{' '}
                El desafío ACME DNS-01 no está implementado. Hasta la v1.0.0 esta
                pantalla simulaba la emisión y guardaba un certificado inventado en{' '}
                <code>data/certs/</code>: se ha eliminado.
              </p>
            </div>

            <div className="space-y-2 text-xs text-slate-600 leading-relaxed">
              <p>
                <span className="font-semibold text-slate-800">Lo que sí funciona:</span>{' '}
                Caddy emite un certificado por host en la primera conexión HTTPS
                (TLS bajo demanda). Añade el dominio, apunta su DNS a este servidor
                y el certificado aparece solo en el primer acceso. No hay nada que
                pulsar aquí.
              </p>
              <p>
                <span className="font-semibold text-slate-800">Si necesitas un comodín de verdad:</span>{' '}
                hay que compilar Caddy con el módulo <code>caddy-dns/cloudflare</code>{' '}
                (xcaddy) y darle un token de Cloudflare. La imagen estándar{' '}
                <code>caddy:2-alpine</code> no lo incluye.
              </p>
              <p>
                El estado real de cada dominio —emisor y caducidad tal como los
                presenta el servidor— sale del handshake TLS de la tabla, no de
                ninguna anotación interna.
              </p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowWildcardModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-sm cursor-pointer active:scale-95 transition-all"
              >
                Entendido
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- MODAL: ZERO CONFIG SSLIP.IO --- */}
      {showSslipModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <div className="flex items-center gap-2 text-blue-600">
              <Server className="w-5 h-5" />
              <h3 className="text-base font-bold text-slate-900">
                Wildcard rápido con sslip.io
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Registra un subdominio instantáneo sin configurar DNS propios, ideal para
              pruebas locales. Culkibo no emite ni almacena el certificado: lo emite Caddy
              en la primera conexión HTTPS al host, y su estado real aparece en el
              handshake TLS de la tabla.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Dirección IP destino
                </label>
                <input
                  type="text"
                  value={sslipIp}
                  onChange={(e) => setSslipIp(e.target.value)}
                  placeholder="127.0.0.1 o la IP de tu VPS"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 font-mono focus:outline-none focus:bg-white focus:border-blue-500"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Resolverá automáticamente a: <code>*.{sslipIp.replace(/\./g, '-')}.sslip.io</code>
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowSslipModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer transition-colors"
              >
                Cancelar
              </button>
              <button
                onClick={handleIssueSslip}
                disabled={issuingSslip}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm cursor-pointer active:scale-95 transition-all disabled:opacity-50"
              >
                {issuingSslip ? 'Registrando host...' : 'Registrar host'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- MODAL: DNS VERIFICATION INSPECTOR --- */}
      {showDnsVerifyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Search className="w-4 h-4 text-amber-600" />
              Comprobador de resolución DNS en vivo
            </h3>

            {verifyingDns ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin text-amber-600" />
                <span className="text-xs font-medium">Consultando servidores DNS con autoridad...</span>
              </div>
            ) : dnsVerifyResult ? (
              <div className="space-y-3">
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono space-y-2">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Dominio consultado:</span>
                    <span className="text-slate-900 font-bold">{dnsVerifyResult.hostname}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Tiempo de respuesta:</span>
                    <span className="text-emerald-600 font-bold">{dnsVerifyResult.lookupDurationMs}ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Red Cloudflare:</span>
                    <span className={dnsVerifyResult.isCloudflareEdge ? 'text-orange-600 font-bold' : 'text-slate-600 font-medium'}>
                      {dnsVerifyResult.isCloudflareEdge ? 'Sí (proxy Cloudflare activo ☁️)' : 'No (DNS directo)'}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-xs font-semibold text-slate-700 block mb-1">
                    Direcciones IP (registros A):
                  </span>
                  <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200 font-mono text-xs text-slate-900">
                    {dnsVerifyResult.resolvedIps?.length ? (
                      dnsVerifyResult.resolvedIps.map((ip: string) => <div key={ip}>{ip}</div>)
                    ) : (
                      <span className="text-slate-400">Sin registros A encontrados</span>
                    )}
                  </div>
                </div>

                {dnsVerifyResult.cnames?.length > 0 && (
                  <div>
                    <span className="text-xs font-semibold text-slate-700 block mb-1">
                      Registros CNAME:
                    </span>
                    <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200 font-mono text-xs text-blue-700">
                      {dnsVerifyResult.cnames.map((cname: string) => <div key={cname}>{cname}</div>)}
                    </div>
                  </div>
                )}
              </div>
            ) : null}

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                onClick={() => setShowDnsVerifyModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer transition-colors"
              >
                Cerrar comprobador
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- MODAL: INGRESS ROUTE INSPECTOR --- */}
      {showIngressModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-600" />
              Diagnóstico de enrutamiento
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              Compara la regla que Culkibo tiene configurada con la ruta que Caddy está sirviendo de verdad para esta cabecera Host.
            </p>

            {testingIngress ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-slate-500 text-xs font-medium">
                <RefreshCw className="w-6 h-6 animate-spin text-amber-600" />
                <span>Consultando la configuración viva de Caddy...</span>
              </div>
            ) : ingressResult ? (
              <div className="space-y-3">
                {ingressResult.found ? (
                  <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono space-y-2.5">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Host de entrada:</span>
                      <span className="text-slate-900 font-bold">{ingressResult.hostname}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Regla coincidente:</span>
                      <span className="text-amber-700 font-bold">{ingressResult.matchedRoute}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Tipo de regla:</span>
                      <span className="text-slate-700">{ingressResult.isWildcard ? 'Comodín wildcard (*.)' : 'Dominio exacto'}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Entorno configurado:</span>
                      <span className={`px-2 py-0.5 rounded-lg text-[11px] font-bold ${ingressResult.configuredPod === 'forge' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'}`}>
                        {ingressResult.configuredPod === 'forge' ? 'Desarrollo' : 'Producción'} :{ingressResult.configuredPort}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Servido por Caddy:</span>
                      <span className={ingressResult.servedByCaddy ? 'text-emerald-700 font-bold' : 'text-slate-600 font-medium'}>
                        {ingressResult.servedByCaddy ? 'Sí' : 'No'}
                      </span>
                    </div>
                    {ingressResult.liveRoute && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Destino real:</span>
                        <span className="text-slate-900">{(ingressResult.liveRoute.upstreams || []).join(', ')}</span>
                      </div>
                    )}
                    {!ingressResult.servedByCaddy && ingressResult.notServedReason && (
                      <div className="pt-2 border-t border-slate-200 text-amber-700 font-sans">
                        {ingressResult.notServedReason}
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-slate-500">Proxy Cloudflare:</span>
                      <span className={ingressResult.cloudflareProxied ? 'text-orange-600 font-medium' : 'text-slate-600'}>
                        {ingressResult.cloudflareProxied ? 'Proxy activo (nube naranja ☁️)' : 'Solo DNS (nube gris ☁️)'}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs font-medium text-red-700">
                    {ingressResult.message || 'No hay ninguna regla configurada para ese dominio.'}
                  </div>
                )}
              </div>
            ) : null}

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                onClick={() => setShowIngressModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer transition-colors"
              >
                Cerrar diagnóstico
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
