import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Cloud,
  Plus,
  Zap,
  Trash2,
  RefreshCw,
  Server,
  Lock,
  Search,
  ArrowRightLeft,
  AlertTriangle,
  Link2,
  X,
  Play,
  Loader2
} from 'lucide-react';
import type { DomainItem, SslCertificate, IngressStatus, TlsProbe } from '../lib/api';
import { api } from '../lib/api';
import { DomainWizardModal } from './DomainWizardModal';

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
  autoOpenWizard?: boolean;
}

export const DomainManager: React.FC<DomainManagerProps> = ({
  onNotify,
  liveSslProgress,
  projectId,
  projectDomains,
  onDomainAddedToProject,
  onDomainRemovedFromProject,
  autoOpenWizard = false
}) => {
  const [domains, setDomains] = useState<DomainItem[]>([]);
  const [certs, setCerts] = useState<SslCertificate[]>([]);
  const [ingress, setIngress] = useState<IngressStatus | null>(null);
  const [probingTls, setProbingTls] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [domainTypeFilter, setDomainTypeFilter] = useState<'all' | 'wildcard' | 'custom' | 'sslip'>('all');
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  // Modals
  const [showWizard, setShowWizard] = useState(autoOpenWizard);
  const [wizardKind, setWizardKind] = useState<'custom' | 'wildcard' | 'sslip'>('custom');
  const [showDnsVerifyModal, setShowDnsVerifyModal] = useState(false);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<any>(null);
  const [verifyingDns, setVerifyingDns] = useState(false);

  const [showIngressModal, setShowIngressModal] = useState(false);
  const [ingressResult, setIngressResult] = useState<any>(null);
  const [testingIngress, setTestingIngress] = useState(false);

  const [showLinkModal, setShowLinkModal] = useState(false);
  const [selectedLinkDomain, setSelectedLinkDomain] = useState('');

  const [prevSslProgressMsg, setPrevSslProgressMsg] = useState<string | undefined>(undefined);
  if (liveSslProgress?.message !== prevSslProgressMsg) {
    setPrevSslProgressMsg(liveSslProgress?.message);
    if (liveSslProgress?.message) {
      setErrorBanner(liveSslProgress.message);
    }
  }

  /**
   * Carga progresiva en 2 fases (<50 ms):
   * 1. Dominios, certificados y rutas Caddy sin bloquear en TLS handshakes (`probe: false`).
   * 2. Handshakes TLS reales en segundo plano (`probe: true`).
   */
  const loadData = useCallback(async (withTlsProbe = true) => {
    try {
      setLoading(true);
      const [domRes, certRes, fastIng] = await Promise.all([
        api.getDomains(),
        api.getCertificates(),
        api.getIngressStatus({ probe: false }).catch(() => null)
      ]);
      setDomains(domRes.domains || []);
      setCerts(certRes.certificates || []);
      setIngress(fastIng);
      setLoading(false);

      if (withTlsProbe && (domRes.domains || []).length > 0) {
        setProbingTls(true);
        const probedIng = await api.getIngressStatus({ probe: true }).catch(() => null);
        if (probedIng) setIngress(probedIng);
        setProbingTls(false);
      }
    } catch (e) {
      console.error(e);
      setLoading(false);
      setProbingTls(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getDomains(),
      api.getCertificates(),
      api.getIngressStatus({ probe: false }).catch(() => null)
    ])
      .then(([domRes, certRes, fastIng]) => {
        if (!active) return;
        const list = domRes.domains || [];
        setDomains(list);
        setCerts(certRes.certificates || []);
        setIngress(fastIng);
        setLoading(false);
        if (list.length > 0) {
          setProbingTls(true);
          api.getIngressStatus({ probe: true })
            .then((probedIng) => { if (active && probedIng) setIngress(probedIng); })
            .catch(() => {})
            .finally(() => { if (active) setProbingTls(false); });
        }
      })
      .catch((e) => {
        console.error(e);
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  const tlsFor = (hostname: string): TlsProbe | null =>
    (ingress?.tls || []).find((t) => t.hostname === hostname) || null;

  const routeFor = (hostname: string) =>
    (ingress?.routes || []).find((r) => r.hosts.includes(hostname)) || null;

  const skippedReasonFor = (hostname: string) =>
    (ingress?.skipped || []).find((s) => s.hostnames.includes(hostname))?.reason || null;

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    setErrorBanner(null);
    try {
      const res = await api.startIngress();
      await loadData(true);
      onNotify?.(res.message || 'Caddy activado y rutas sincronizadas');
    } catch (err: any) {
      setErrorBanner(`No se pudo activar Caddy: ${err.message}`);
    } finally {
      setStartingCaddy(false);
    }
  };

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const res = await api.reconcileIngress();
      await loadData(true);
      onNotify?.(res.applied ? 'Rutas de ingress reconciliadas con Caddy' : (res.message || 'No se pudo reconciliar el ingress'));
    } catch (err: any) {
      setErrorBanner(`Error al reconciliar el ingress: ${err.message}`);
    } finally {
      setReconciling(false);
    }
  };

  const handleLinkDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedLinkDomain || !projectId) return;
    try {
      const res = await api.attachDomainToProject(projectId, { hostname: selectedLinkDomain });
      onDomainAddedToProject?.(selectedLinkDomain);
      setShowLinkModal(false);
      setSelectedLinkDomain('');
      void loadData(true);
      onNotify?.(res.ingress?.applied
        ? `${selectedLinkDomain} vinculado y enrutado en Caddy`
        : `${selectedLinkDomain} vinculado. ${res.ingress?.message || ''}`);
    } catch (err: any) {
      setErrorBanner(`Error al vincular el dominio: ${err.message}`);
    }
  };

  const handleToggleProxy = async (id: string, hostname: string) => {
    try {
      const updated = await api.toggleDomainProxy(id);
      setDomains((prev) => prev.map((d) => (d.id === id ? { ...d, cloudflareProxied: updated.cloudflareProxied } : d)));
      onNotify?.(updated.cloudflareProxied ? `Proxy Cloudflare activado para ${hostname}` : `Proxy Cloudflare desactivado para ${hostname}`);
    } catch (err: any) {
      setErrorBanner(`Fallo al alternar el proxy de Cloudflare: ${err.message}`);
    }
  };

  const handleToggleEntorno = async (id: string, currentPod: 'forge' | 'citadel', hostname: string) => {
    const nextPod: 'forge' | 'citadel' = currentPod === 'forge' ? 'citadel' : 'forge';
    const nextPort = nextPod === 'forge' ? 3001 : 8080;
    try {
      const updated = await api.updateDomain(id, { targetPod: nextPod, targetPort: nextPort });
      setDomains((prev) => prev.map((d) => (d.id === id ? { ...d, targetPod: updated.targetPod, targetPort: updated.targetPort } : d)));
      onNotify?.(`Tráfico de ${hostname} dirigido a ${nextPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)'}`);
    } catch (err: any) {
      setErrorBanner(`Fallo al cambiar el entorno destino: ${err.message}`);
    }
  };

  const handleConfirmDelete = async (id: string, name: string) => {
    setConfirmDeleteId(null);
    try {
      if (projectId) {
        await api.detachDomainFromProject(projectId, id);
        onDomainRemovedFromProject?.(name);
        onNotify?.(`Dominio ${name} desvinculado y ruta retirada`);
      } else {
        await api.deleteDomain(id);
        onNotify?.(`Dominio ${name} eliminado y ruta retirada`);
      }
      void loadData(false);
    } catch (err: any) {
      setErrorBanner(`Error al eliminar dominio: ${err.message}`);
    }
  };

  const handleVerifyDns = async (hostname: string) => {
    setVerifyingDns(true);
    setShowDnsVerifyModal(true);
    setDnsVerifyResult(null);
    try {
      setDnsVerifyResult(await api.verifyDns(hostname));
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
      setIngressResult(await api.getIngressResolution(hostname));
    } catch (err: any) {
      setIngressResult({ error: err.message });
    } finally {
      setTestingIngress(false);
    }
  };

  const openWizard = (kind: 'custom' | 'wildcard' | 'sslip') => {
    setWizardKind(kind);
    setShowWizard(true);
  };

  const filteredDomains = domains.filter((d) => {
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
      {errorBanner && (
        <div className="flex items-center justify-between p-4 rounded-2xl bg-red-50 border border-red-200 text-red-700 text-xs font-medium shadow-sm">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorBanner}</span>
          </div>
          <button type="button" onClick={() => setErrorBanner(null)} className="text-red-500 hover:text-red-800 p-1 rounded-lg cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Estado real del plano de datos Caddy */}
      {ingress && (
        <div className={`p-4 rounded-2xl border text-xs shadow-sm ${
          ingress.available
            ? (ingress.inSync ? 'bg-white border-slate-200' : 'bg-amber-50 border-amber-200')
            : 'bg-amber-50/70 border-amber-200'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div className={`w-8 h-8 rounded-xl border flex items-center justify-center shrink-0 ${
                ingress.available ? 'bg-emerald-50 border-emerald-200 text-emerald-600' : 'bg-amber-100 border-amber-200 text-amber-700'
              }`}>
                {ingress.available ? <Zap className="w-4 h-4" /> : <ShieldOff className="w-4 h-4" />}
              </div>
              <div>
                <div className="font-semibold text-slate-900">
                  {ingress.available
                    ? `Enrutador HTTPS activo (Caddy en ${ingress.adminUrl})`
                    : 'Caddy HTTPS está detenido'}
                </div>
                <p className="text-slate-600 mt-0.5 max-w-2xl leading-relaxed">{ingress.message}</p>
                {ingress.available && (
                  <p className="text-slate-500 mt-1">
                    {ingress.routesManaged} ruta(s) publicadas
                    {ingress.inSync ? ' · todo sincronizado' : ` · ${ingress.drift.missing.length} sin publicar, ${ingress.drift.unexpected.length} sobrantes`}
                    {probingTls ? ' · comprobando candados TLS…' : ''}
                  </p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {!ingress.available ? (
                <button
                  type="button"
                  onClick={handleStartCaddy}
                  disabled={startingCaddy}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {startingCaddy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{startingCaddy ? 'Activando Caddy…' : 'Activar Caddy ahora'}</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleReconcile}
                  disabled={reconciling}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${reconciling ? 'animate-spin' : ''}`} />
                  <span>Reconciliar rutas</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Header & Guided Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-white border border-slate-200 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shrink-0">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900">Dominios y certificados HTTPS</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Conecta dominios propios, certificados comodín (*.tudominio.com) o direcciones gratis sslip.io en 3 pasos.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {projectId && (
            <button
              type="button"
              onClick={() => setShowLinkModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-semibold cursor-pointer"
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>Vincular existente</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => openWizard('custom')}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-sm cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Conectar dominio o Wildcard</span>
          </button>

          <button
            type="button"
            onClick={() => openWizard('wildcard')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-xs font-semibold cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Wildcard *.dominio</span>
          </button>

          <button
            type="button"
            onClick={() => openWizard('sslip')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs font-medium cursor-pointer"
          >
            <Server className="w-3.5 h-3.5 text-blue-600" />
            <span>Gratis sslip.io</span>
          </button>

          <button
            type="button"
            onClick={() => void loadData(true)}
            className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-600 cursor-pointer"
            title="Recargar y volver a comprobar TLS"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading || probingTls ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100/80 border border-slate-200 rounded-xl text-xs">
          {([
            { id: 'all', label: `Todos (${domains.length})` },
            { id: 'wildcard', label: `Wildcards (${domains.filter((d) => d.isWildcard).length})` },
            { id: 'custom', label: `Propios (${domains.filter((d) => !d.isWildcard && !d.hostname.includes('.sslip.io')).length})` },
            { id: 'sslip', label: `sslip.io (${domains.filter((d) => d.hostname.includes('.sslip.io') || d.hostname.includes('.nip.io')).length})` }
          ] as const).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setDomainTypeFilter(tab.id)}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
                domainTypeFilter === tab.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Buscar dominio…"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-white border border-slate-300 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none"
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
                <th className="py-3 px-4">Destino</th>
                <th className="py-3 px-4">Ruta en Caddy</th>
                <th className="py-3 px-4">Cloudflare</th>
                <th className="py-3 px-4">Certificado HTTPS (verificado)</th>
                <th className="py-3 px-4">Diagnóstico</th>
                <th className="py-3 px-4 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredDomains.map((domain) => {
                const isForge = domain.targetPod === 'forge';
                const probe = tlsFor(domain.hostname);
                const liveRoute = routeFor(domain.hostname);
                const skippedReason = skippedReasonFor(domain.hostname);
                const confirming = confirmDeleteId === domain.id;

                return (
                  <tr key={domain.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-900 font-mono">{domain.hostname}</span>
                        {domain.isWildcard && (
                          <span className="px-1.5 py-0.5 rounded-lg text-[10px] font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                            Comodín
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <button
                        type="button"
                        onClick={() => handleToggleEntorno(domain.id, domain.targetPod, domain.hostname)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border cursor-pointer ${
                          isForge
                            ? 'bg-amber-50 border-amber-200 text-amber-800 hover:bg-amber-100'
                            : 'bg-blue-50 border-blue-200 text-blue-800 hover:bg-blue-100'
                        }`}
                      >
                        <span>{isForge ? 'Desarrollo' : 'Producción'}</span>
                        <span className="text-slate-500">:{domain.targetPort}</span>
                        <ArrowRightLeft className="w-3 h-3 opacity-60" />
                      </button>
                    </td>

                    <td className="py-3.5 px-4">
                      {liveRoute ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-emerald-700 font-semibold">
                            <Link2 className="w-3.5 h-3.5 text-emerald-600" />
                            <span>Publicada</span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">{liveRoute.upstreams.join(', ')}</div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-slate-500 font-medium">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>Sin ruta</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[200px]">
                            {skippedReason || (ingress && !ingress.available ? 'Caddy detenido' : 'Pendiente')}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <button
                        type="button"
                        onClick={() => handleToggleProxy(domain.id, domain.hostname)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs cursor-pointer border font-medium ${
                          domain.cloudflareProxied
                            ? 'bg-orange-50 border-orange-200 text-orange-700 hover:bg-orange-100'
                            : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                        }`}
                      >
                        <Cloud className={`w-3.5 h-3.5 ${domain.cloudflareProxied ? 'fill-orange-400 text-orange-500' : 'text-slate-400'}`} />
                        <span>{domain.cloudflareProxied ? 'Proxy activo' : 'Solo DNS'}</span>
                      </button>
                    </td>

                    <td className="py-3.5 px-4">
                      {!probe ? (
                        <span className="text-[11px] text-slate-400">
                          {probingTls ? 'Comprobando…' : 'Sin sondear'}
                        </span>
                      ) : probe.reachable && probe.notAfter ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5">
                            {probe.trusted && !probe.expired ? (
                              <ShieldCheck className="w-4 h-4 text-emerald-600" />
                            ) : (
                              <ShieldAlert className="w-4 h-4 text-amber-600" />
                            )}
                            <span className={`font-semibold ${probe.trusted && !probe.expired ? 'text-emerald-700' : 'text-amber-700'}`}>
                              {probe.issuer || probe.issuerCN || 'Certificado detectado'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Caduca {formatDate(probe.notAfter)}
                            {typeof probe.daysRemaining === 'number' && ` · ${probe.daysRemaining} d`}
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 text-slate-500 font-medium">
                            <ShieldOff className="w-4 h-4 text-slate-400" />
                            <span>Pendiente de HTTPS</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[200px] truncate" title={probe.error}>
                            {probe.error || 'Apunta el DNS para emitirlo'}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => handleVerifyDns(domain.hostname)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer"
                        >
                          <Search className="w-3 h-3 text-slate-500" />
                          <span>DNS</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleTestIngress(domain.hostname)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-800 text-xs font-medium cursor-pointer"
                        >
                          <Zap className="w-3 h-3 text-amber-600" />
                          <span>Ruta</span>
                        </button>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      {confirming ? (
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => void handleConfirmDelete(domain.id, domain.hostname)}
                            className="px-2 py-1 rounded-lg bg-rose-600 text-white text-[11px] font-semibold cursor-pointer"
                          >
                            Confirmar
                          </button>
                          <button
                            type="button"
                            onClick={() => setConfirmDeleteId(null)}
                            className="px-2 py-1 rounded-lg bg-slate-100 text-slate-600 text-[11px] font-medium cursor-pointer"
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(domain.id)}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                          title={projectId ? 'Desvincular dominio' : 'Eliminar dominio'}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}

              {filteredDomains.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500">
                    <div className="space-y-2">
                      <p>No hay dominios configurados todavía.</p>
                      <button
                        type="button"
                        onClick={() => openWizard('custom')}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 text-white text-xs font-semibold cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>Conectar tu primer dominio</span>
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Registro interno de certificados */}
      {certs.length > 0 && (
        <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-slate-500" />
              <h3 className="text-sm font-bold text-slate-900">Certificados registrados</h3>
            </div>
            <span className="text-xs text-slate-500">Verificados en vivo arriba por handshake TLS</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {certs.map((cert) => {
              const delegated = cert.status === 'delegated';
              return (
                <div key={cert.id} className="p-4 rounded-xl bg-slate-50/70 border border-slate-200 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="text-xs font-bold text-slate-900 block font-mono">{cert.domain}</span>
                      <span className="text-[11px] text-slate-500">
                        {delegated ? 'Gestionado por Caddy bajo demanda' : `Emisor: ${cert.issuer ?? 'desconocido'}`}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded-lg text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                      {delegated ? 'Automático' : cert.daysRemaining !== null ? `${cert.daysRemaining} días` : 'X.509'}
                    </span>
                  </div>
                  {cert.sans?.length > 0 && (
                    <div className="text-[11px] text-slate-600">
                      SANs: <span className="font-mono text-slate-800">{cert.sans.join(', ')}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Asistente 3 pasos */}
      <DomainWizardModal
        isOpen={showWizard}
        onClose={() => setShowWizard(false)}
        onComplete={() => {
          void loadData(true);
          onDomainAddedToProject?.('');
        }}
        onNotify={onNotify}
        projectId={projectId}
        initialKind={wizardKind}
      />

      {/* Modal: Vincular existente */}
      {showLinkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-[2px] p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-base font-bold text-slate-900">Vincular dominio existente</h3>
            <form onSubmit={handleLinkDomain} className="space-y-4">
              <select
                value={selectedLinkDomain}
                onChange={(e) => setSelectedLinkDomain(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900"
                required
              >
                <option value="" disabled>-- Elige un dominio --</option>
                {domains.filter((d) => !projectDomains?.includes(d.hostname)).map((d) => (
                  <option key={d.id} value={d.hostname}>{d.hostname}</option>
                ))}
              </select>
              <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                <button type="button" onClick={() => setShowLinkModal(false)} className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:bg-slate-100 cursor-pointer">
                  Cancelar
                </button>
                <button type="submit" disabled={!selectedLinkDomain} className="px-4 py-2 rounded-xl bg-slate-900 text-white font-semibold text-xs cursor-pointer disabled:opacity-50">
                  Vincular
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: DNS Check */}
      {showDnsVerifyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-[2px] p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Search className="w-4 h-4 text-blue-600" />
              Comprobador DNS en vivo
            </h3>
            {verifyingDns ? (
              <div className="flex flex-col items-center py-8 gap-2 text-slate-500 text-xs">
                <RefreshCw className="w-5 h-5 animate-spin text-blue-600" />
                <span>Consultando registros DNS…</span>
              </div>
            ) : dnsVerifyResult ? (
              <div className="space-y-3 text-xs">
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 font-mono space-y-2">
                  <div className="flex justify-between"><span className="text-slate-500">Dominio:</span><span className="font-bold">{dnsVerifyResult.hostname}</span></div>
                  <div className="flex justify-between"><span className="text-slate-500">Respuesta:</span><span className="text-emerald-700 font-bold">{dnsVerifyResult.lookupDurationMs} ms</span></div>
                  <div className="flex justify-between"><span className="text-slate-500">IPs (A):</span><span>{dnsVerifyResult.resolvedIps?.join(', ') || 'Sin registros A'}</span></div>
                </div>
              </div>
            ) : null}
            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button type="button" onClick={() => setShowDnsVerifyModal(false)} className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer">
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Ingress Route Check */}
      {showIngressModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-[2px] p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-600" />
              Diagnóstico de enrutamiento Caddy
            </h3>
            {testingIngress ? (
              <div className="flex flex-col items-center py-8 gap-2 text-slate-500 text-xs">
                <RefreshCw className="w-5 h-5 animate-spin text-amber-600" />
                <span>Consultando Caddy…</span>
              </div>
            ) : ingressResult ? (
              <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono space-y-2">
                <div className="flex justify-between"><span className="text-slate-500">Host:</span><span className="font-bold">{ingressResult.hostname}</span></div>
                <div className="flex justify-between"><span className="text-slate-500">Servido por Caddy:</span><span className={ingressResult.servedByCaddy ? 'text-emerald-700 font-bold' : 'text-amber-700 font-bold'}>{ingressResult.servedByCaddy ? 'Sí' : 'No'}</span></div>
                {ingressResult.liveRoute && (
                  <div className="flex justify-between"><span className="text-slate-500">Destino real:</span><span>{(ingressResult.liveRoute.upstreams || []).join(', ')}</span></div>
                )}
                {!ingressResult.servedByCaddy && ingressResult.notServedReason && (
                  <div className="text-amber-700 font-sans pt-1">{ingressResult.notServedReason}</div>
                )}
              </div>
            ) : null}
            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button type="button" onClick={() => setShowIngressModal(false)} className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer">
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
