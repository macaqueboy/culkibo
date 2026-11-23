import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Cloud,
  Plus,
  Zap,
  Trash2,
  RefreshCw,
  Lock,
  Search,
  ArrowRightLeft,
  AlertTriangle,
  Link2,
  X,
  Play,
  Loader2,
} from 'lucide-react';
import type { DomainItem, SslCertificate, IngressStatus, TlsProbe } from '../lib/api';
import { api } from '../lib/api';
import { DomainWizardModal } from './DomainWizardModal';
import { Modal } from './Modal';

const formatDate = (iso?: string | null) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' });
};

interface DomainManagerProps {
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  liveSslProgress?: { stage: string; progress: number; message: string; domain?: string } | null;
  projectId?: string;
  projectDomains?: string[];
  onDomainAddedToProject?: (domain: string) => void;
  onDomainRemovedFromProject?: (domain: string) => void;
  wizardTrigger?: number;
}

export const DomainManager: React.FC<DomainManagerProps> = ({
  onNotify,
  liveSslProgress,
  projectId,
  projectDomains,
  onDomainAddedToProject,
  onDomainRemovedFromProject,
  wizardTrigger = 0,
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

  const [showWizard, setShowWizard] = useState(wizardTrigger > 0);
  const [wizardKind, setWizardKind] = useState<'custom' | 'wildcard' | 'sslip'>('custom');
  const [showDnsVerifyModal, setShowDnsVerifyModal] = useState(false);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<any>(null);
  const [verifyingDns, setVerifyingDns] = useState(false);

  const [showIngressModal, setShowIngressModal] = useState(false);
  const [ingressResult, setIngressResult] = useState<any>(null);
  const [testingIngress, setTestingIngress] = useState(false);

  const [showLinkModal, setShowLinkModal] = useState(false);
  const [selectedLinkDomain, setSelectedLinkDomain] = useState('');

  const [prevWizardTrigger, setPrevWizardTrigger] = useState(wizardTrigger);
  if (wizardTrigger !== prevWizardTrigger) {
    setPrevWizardTrigger(wizardTrigger);
    if (wizardTrigger > 0) {
      setWizardKind('custom');
      setShowWizard(true);
    }
  }

  const [prevSslProgressMsg, setPrevSslProgressMsg] = useState<string | undefined>(undefined);
  if (liveSslProgress?.message !== prevSslProgressMsg) {
    setPrevSslProgressMsg(liveSslProgress?.message);
    if (liveSslProgress?.message) {
      setErrorBanner(liveSslProgress.message);
    }
  }

  const loadData = useCallback(async (withTlsProbe = true) => {
    try {
      setLoading(true);
      const [domRes, certRes, fastIng] = await Promise.all([
        api.getDomains(),
        api.getCertificates(),
        api.getIngressStatus({ probe: false }).catch(() => null),
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
      api.getIngressStatus({ probe: false }).catch(() => null),
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
      onNotify?.(res.message || 'Caddy activado y rutas sincronizadas', 'success');
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
      onNotify?.(
        res.applied ? 'Rutas sincronizadas con Caddy' : (res.message || 'No se pudo sincronizar Caddy'),
        res.applied ? 'success' : 'error'
      );
    } catch (err: any) {
      setErrorBanner(`Error al reconciliar rutas: ${err.message}`);
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
      onNotify?.(
        res.ingress?.applied
          ? `${selectedLinkDomain} vinculado y publicado en Caddy`
          : `${selectedLinkDomain} vinculado. ${res.ingress?.message || ''}`,
        'success'
      );
    } catch (err: any) {
      setErrorBanner(`Error al vincular el dominio: ${err.message}`);
    }
  };

  const handleToggleProxy = async (id: string, hostname: string) => {
    try {
      const updated = await api.toggleDomainProxy(id);
      setDomains((prev) => prev.map((d) => (d.id === id ? { ...d, cloudflareProxied: updated.cloudflareProxied } : d)));
      onNotify?.(
        updated.cloudflareProxied ? `Proxy Cloudflare activado para ${hostname}` : `Proxy Cloudflare desactivado para ${hostname}`,
        'info'
      );
    } catch (err: any) {
      setErrorBanner(`Fallo al alternar proxy de Cloudflare: ${err.message}`);
    }
  };

  const handleToggleEntorno = async (id: string, currentPod: 'forge' | 'citadel', hostname: string) => {
    const nextPod: 'forge' | 'citadel' = currentPod === 'forge' ? 'citadel' : 'forge';
    const nextPort = nextPod === 'forge' ? 3001 : 8080;
    try {
      const updated = await api.updateDomain(id, { targetPod: nextPod, targetPort: nextPort });
      setDomains((prev) => prev.map((d) => (d.id === id ? { ...d, targetPod: updated.targetPod, targetPort: updated.targetPort } : d)));
      onNotify?.(`Tráfico de ${hostname} dirigido a ${nextPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)'}`, 'info');
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
        onNotify?.(`Dominio ${name} desvinculado y ruta retirada`, 'info');
      } else {
        await api.deleteDomain(id);
        onNotify?.(`Dominio ${name} eliminado y ruta retirada`, 'info');
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

  const scopedDomains = projectDomains
    ? domains.filter((d) => projectDomains.includes(d.hostname))
    : domains;

  const filteredDomains = scopedDomains.filter((d) => {
    if (searchFilter && !d.hostname.toLowerCase().includes(searchFilter.toLowerCase())) return false;
    if (domainTypeFilter === 'wildcard') return d.isWildcard;
    if (domainTypeFilter === 'sslip') return d.hostname.includes('.sslip.io') || d.hostname.includes('.nip.io');
    if (domainTypeFilter === 'custom') return !d.isWildcard && !d.hostname.includes('.sslip.io') && !d.hostname.includes('.nip.io');
    return true;
  });

  const wildcardCount = scopedDomains.filter((d) => d.isWildcard).length;
  const sslipCount = scopedDomains.filter((d) => d.hostname.includes('.sslip.io') || d.hostname.includes('.nip.io')).length;
  const customCount = scopedDomains.length - wildcardCount - sslipCount;

  return (
    <div className="space-y-5">
      {/* Cabecera fuera de tarjeta */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          {projectId ? (
            <h2 className="text-base font-semibold text-slate-900">Dominios y certificados HTTPS</h2>
          ) : (
            <h1 className="text-xl font-semibold text-slate-900 tracking-tight">Dominios y HTTPS</h1>
          )}
          <p className="text-sm text-slate-500 mt-1">
            Conecta dominios propios, comodines <code className="font-mono text-xs">*.tudominio.com</code> o direcciones <code className="font-mono text-xs">sslip.io</code> gestionadas por Caddy.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {projectId && (
            <button
              type="button"
              onClick={() => setShowLinkModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium cursor-pointer"
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>Vincular existente</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => { setWizardKind('custom'); setShowWizard(true); }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Conectar dominio</span>
          </button>

          <button
            type="button"
            aria-label="Actualizar dominios y certificados"
            onClick={() => void loadData(true)}
            className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
            title="Recargar y comprobar TLS"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading || probingTls ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {errorBanner && (
        <div role="alert" className="flex items-center justify-between p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs font-medium">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorBanner}</span>
          </div>
          <button type="button" aria-label="Cerrar aviso" onClick={() => setErrorBanner(null)} className="text-red-500 hover:text-red-800 p-1 rounded cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Estado de Caddy */}
      {ingress && (
        <div
          className={`p-4 rounded-xl border text-xs ${
            ingress.available
              ? (ingress.inSync ? 'bg-white border-slate-200' : 'bg-amber-50 border-amber-200')
              : 'bg-amber-50/80 border-amber-200'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${
                ingress.available ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-amber-100 border-amber-200 text-amber-800'
              }`}>
                {ingress.available ? <Zap className="w-4 h-4" /> : <ShieldOff className="w-4 h-4" />}
              </div>
              <div>
                <div className="font-semibold text-slate-900">
                  {ingress.available ? `Caddy activo (${ingress.adminUrl})` : 'Caddy está detenido'}
                </div>
                <p className="text-slate-600 mt-0.5 max-w-2xl leading-relaxed">{ingress.message}</p>
                {ingress.available && (
                  <p className="text-slate-500 mt-1 tabular-nums">
                    {ingress.routesManaged} {ingress.routesManaged === 1 ? 'ruta publicada' : 'rutas publicadas'}
                    {ingress.inSync
                      ? ' · sincronizado'
                      : ` · ${ingress.drift.missing.length} sin publicar, ${ingress.drift.unexpected.length} sobrantes`}
                    {probingTls ? ' · comprobando TLS…' : ''}
                  </p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {!ingress.available ? (
                <button
                  type="button"
                  onClick={() => void handleStartCaddy()}
                  disabled={startingCaddy}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {startingCaddy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{startingCaddy ? 'Activando…' : 'Activar Caddy'}</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => void handleReconcile()}
                  disabled={reconciling}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${reconciling ? 'animate-spin' : ''}`} />
                  <span>Reconciliar rutas</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filtros */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1 p-0.5 bg-slate-100 border border-slate-200 rounded-lg text-xs">
          {([
            { id: 'all', label: `Todos (${scopedDomains.length})` },
            { id: 'custom', label: `Propios (${customCount})` },
            { id: 'wildcard', label: `Comodines (${wildcardCount})` },
            { id: 'sslip', label: `sslip.io (${sslipCount})` },
          ] as const).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setDomainTypeFilter(tab.id)}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer font-medium tabular-nums ${
                domainTypeFilter === tab.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filtrar dominio…"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400"
          />
        </div>
      </div>

      {/* Tabla de dominios */}
      <div className="rounded-xl bg-white border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium text-slate-500">
                <th className="py-2.5 px-4">Dominio</th>
                <th className="py-2.5 px-4">Destino</th>
                <th className="py-2.5 px-4">Ruta Caddy</th>
                <th className="py-2.5 px-4">Cloudflare</th>
                <th className="py-2.5 px-4">Certificado TLS</th>
                <th className="py-2.5 px-4">Comprobar</th>
                <th className="py-2.5 px-4 text-right">Acciones</th>
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
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-slate-900 font-mono">{domain.hostname}</span>
                        {domain.isWildcard && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                            Comodín
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <button
                        type="button"
                        onClick={() => void handleToggleEntorno(domain.id, domain.targetPod, domain.hostname)}
                        title="Pulsa para alternar entre Producción y Desarrollo"
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 cursor-pointer tabular-nums"
                      >
                        <span>{isForge ? 'Desarrollo' : 'Producción'}</span>
                        <span className="text-slate-400 font-mono">:{domain.targetPort}</span>
                        <ArrowRightLeft className="w-3 h-3 text-slate-400" />
                      </button>
                    </td>

                    <td className="py-3 px-4">
                      {liveRoute ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-emerald-700 font-medium">
                            <Link2 className="w-3.5 h-3.5" />
                            <span>Publicada</span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">{liveRoute.upstreams.join(', ')}</div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-slate-500">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>Sin ruta</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[180px] truncate">
                            {skippedReason || (ingress && !ingress.available ? 'Caddy detenido' : 'Pendiente')}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <button
                        type="button"
                        onClick={() => void handleToggleProxy(domain.id, domain.hostname)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs cursor-pointer border font-medium ${
                          domain.cloudflareProxied
                            ? 'bg-amber-50 border-amber-200 text-amber-800 hover:bg-amber-100'
                            : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                        }`}
                      >
                        <Cloud className="w-3.5 h-3.5" />
                        <span>{domain.cloudflareProxied ? 'Proxy' : 'Solo DNS'}</span>
                      </button>
                    </td>

                    <td className="py-3 px-4">
                      {!probe ? (
                        <span className="text-[11px] text-slate-400">
                          {probingTls ? 'Comprobando…' : 'Sin sondear'}
                        </span>
                      ) : probe.reachable && probe.notAfter ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5">
                            {probe.trusted && !probe.expired ? (
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                            ) : (
                              <ShieldAlert className="w-3.5 h-3.5 text-amber-600" />
                            )}
                            <span className={`font-medium ${probe.trusted && !probe.expired ? 'text-emerald-700' : 'text-amber-700'}`}>
                              {probe.issuer || probe.issuerCN || 'Certificado detectado'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 tabular-nums">
                            Caduca {formatDate(probe.notAfter)}
                            {typeof probe.daysRemaining === 'number' && ` · ${probe.daysRemaining} d`}
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-slate-500">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>Pendiente</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[180px] truncate" title={probe.error}>
                            {probe.error || 'Apunta el DNS para emitirlo'}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => void handleVerifyDns(domain.hostname)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer"
                        >
                          <Search className="w-3 h-3 text-slate-500" /> DNS
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleTestIngress(domain.hostname)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer"
                        >
                          <Zap className="w-3 h-3 text-slate-500" /> Ruta
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      {confirming ? (
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => void handleConfirmDelete(domain.id, domain.hostname)}
                            className="px-2 py-1 rounded-md bg-red-600 text-white text-[11px] font-medium cursor-pointer"
                          >
                            Confirmar
                          </button>
                          <button
                            type="button"
                            onClick={() => setConfirmDeleteId(null)}
                            className="px-2 py-1 rounded-md bg-slate-100 text-slate-600 text-[11px] font-medium cursor-pointer"
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          aria-label={projectId ? `Desvincular ${domain.hostname}` : `Eliminar ${domain.hostname}`}
                          onClick={() => setConfirmDeleteId(domain.id)}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                          title={projectId ? 'Desvincular dominio' : 'Eliminar dominio'}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}

              {filteredDomains.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500">
                    <div className="space-y-2.5">
                      <p className="text-xs">No hay dominios configurados en esta vista.</p>
                      <button
                        type="button"
                        onClick={() => { setWizardKind('custom'); setShowWizard(true); }}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>Conectar primer dominio</span>
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
      {certs.length > 0 && !projectId && (
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3.5">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-slate-900">Certificados registrados</h2>
            </div>
            <span className="text-xs text-slate-500">Verificados en directo por handshake TLS en la tabla superior</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {certs.map((cert) => {
              const delegated = cert.status === 'delegated';
              return (
                <div key={cert.id} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <span className="text-xs font-semibold text-slate-900 block font-mono truncate">{cert.domain}</span>
                      <span className="text-[11px] text-slate-500">
                        {delegated ? 'Emitido por Caddy bajo demanda' : `Emisor: ${cert.issuer ?? 'desconocido'}`}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-white text-slate-600 border border-slate-200 shrink-0 tabular-nums">
                      {delegated ? 'Automático' : cert.daysRemaining !== null ? `${cert.daysRemaining} d` : 'X.509'}
                    </span>
                  </div>
                  {cert.sans?.length > 0 && (
                    <div className="text-[11px] text-slate-500 truncate">
                      SANs: <span className="font-mono text-slate-700">{cert.sans.join(', ')}</span>
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
      <Modal
        open={showLinkModal}
        onClose={() => setShowLinkModal(false)}
        title="Vincular dominio existente"
        maxWidthClass="max-w-md"
      >
        <form onSubmit={handleLinkDomain} className="p-5 space-y-4">
          <select
            value={selectedLinkDomain}
            onChange={(e) => setSelectedLinkDomain(e.target.value)}
            className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs text-slate-900"
            required
          >
            <option value="" disabled>Selecciona un dominio…</option>
            {domains.filter((d) => !projectDomains?.includes(d.hostname)).map((d) => (
              <option key={d.id} value={d.hostname}>{d.hostname}</option>
            ))}
          </select>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setShowLinkModal(false)} className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button type="submit" disabled={!selectedLinkDomain} className="px-4 py-2 rounded-lg bg-slate-900 text-white font-medium text-xs cursor-pointer disabled:opacity-50">
              Vincular
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Comprobador DNS */}
      <Modal
        open={showDnsVerifyModal}
        onClose={() => setShowDnsVerifyModal(false)}
        title="Comprobador DNS en vivo"
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4">
          {verifyingDns ? (
            <div className="flex flex-col items-center py-6 gap-2 text-slate-500 text-xs">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Consultando registros DNS…</span>
            </div>
          ) : dnsVerifyResult?.error ? (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800">
              {dnsVerifyResult.error}
            </div>
          ) : dnsVerifyResult ? (
            <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 font-mono text-xs space-y-2 tabular-nums">
              <div className="flex justify-between gap-2">
                <span className="text-slate-500">Dominio:</span>
                <span className="font-semibold text-slate-900 truncate">{dnsVerifyResult.hostname}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-500">Respuesta:</span>
                <span className="text-emerald-700 font-semibold">{dnsVerifyResult.lookupDurationMs ?? '—'} ms</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-500">IPs (A):</span>
                <span className="text-slate-800 text-right">{dnsVerifyResult.resolvedIps?.join(', ') || 'Sin registros A'}</span>
              </div>
            </div>
          ) : null}
          <div className="flex justify-end">
            <button type="button" onClick={() => setShowDnsVerifyModal(false)} className="px-3.5 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium cursor-pointer">
              Cerrar
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Diagnóstico de ruta Caddy */}
      <Modal
        open={showIngressModal}
        onClose={() => setShowIngressModal(false)}
        title="Diagnóstico de ruta en Caddy"
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4">
          {testingIngress ? (
            <div className="flex flex-col items-center py-6 gap-2 text-slate-500 text-xs">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Consultando Caddy…</span>
            </div>
          ) : ingressResult?.error ? (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800">
              {ingressResult.error}
            </div>
          ) : ingressResult ? (
            <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono space-y-2">
              <div className="flex justify-between gap-2">
                <span className="text-slate-500">Host:</span>
                <span className="font-semibold text-slate-900 truncate">{ingressResult.hostname}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-500">Servido por Caddy:</span>
                <span className={ingressResult.servedByCaddy ? 'text-emerald-700 font-semibold' : 'text-amber-700 font-semibold'}>
                  {ingressResult.servedByCaddy ? 'Sí' : 'No'}
                </span>
              </div>
              {ingressResult.liveRoute && (
                <div className="flex justify-between gap-2">
                  <span className="text-slate-500">Destino real:</span>
                  <span className="text-slate-800">{(ingressResult.liveRoute.upstreams || []).join(', ')}</span>
                </div>
              )}
              {!ingressResult.servedByCaddy && ingressResult.notServedReason && (
                <div className="text-amber-800 font-sans pt-1">{ingressResult.notServedReason}</div>
              )}
            </div>
          ) : null}
          <div className="flex justify-end">
            <button type="button" onClick={() => setShowIngressModal(false)} className="px-3.5 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium cursor-pointer">
              Cerrar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
