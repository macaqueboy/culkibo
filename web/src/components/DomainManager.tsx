import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
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
  X
} from 'lucide-react';
import type { DomainItem, SslCertificate } from '../lib/api';
import { api } from '../lib/api';

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

  // Wildcard ACME Issuance State
  const [wildcardDomain, setWildcardDomain] = useState('*.culkibo.dev');
  const [wildcardProvider, setWildcardProvider] = useState('lets_encrypt');
  const [issuingWildcard, setIssuingWildcard] = useState(false);
  const [wildcardProgress, setWildcardProgress] = useState<{ stage: string; progress: number; message: string } | null>(null);

  // sslip.io Form
  const [sslipIp, setSslipIp] = useState('127.0.0.1');
  const [issuingSslip, setIssuingSslip] = useState(false);

  // Sync real-time WebSocket SSL progress
  useEffect(() => {
    if (liveSslProgress) {
      setWildcardProgress(liveSslProgress);
      if (liveSslProgress.stage === 'installed') {
        setTimeout(() => {
          setShowWildcardModal(false);
          setIssuingWildcard(false);
          setWildcardProgress(null);
          loadData();
        }, 1500);
      } else if (liveSslProgress.stage === 'error') {
        setIssuingWildcard(false);
      }
    }
  }, [liveSslProgress]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [domRes, certRes] = await Promise.all([
        api.getDomains(),
        api.getCertificates()
      ]);
      setDomains(domRes.domains || []);
      setCerts(certRes.certificates || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHostname.trim()) return;

    try {
      await api.addDomain({
        hostname: newHostname.trim(),
        targetPod: newTargetEntorno,
        targetPort: newTargetPort,
        cloudflareProxied: newProxied,
        autoCreateDns: autoCreateCfRecord
      });
      setShowAddModal(false);
      
      if (projectId && onDomainAddedToProject) {
        onDomainAddedToProject(newHostname.trim());
      }
      
      setNewHostname('');
      loadData();
      if (onNotify) onNotify(`Dominio ${newHostname} añadido con éxito`);
    } catch (err: any) {
      setErrorBanner(`Error al añadir dominio: ${err.message}`);
    }
  };

  const handleLinkDomain = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedLinkDomain || !onDomainAddedToProject) return;
    onDomainAddedToProject(selectedLinkDomain);
    setShowLinkModal(false);
    setSelectedLinkDomain('');
    if (onNotify) onNotify(`Dominio ${selectedLinkDomain} vinculado al proyecto`);
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
    if (projectId && onDomainRemovedFromProject) {
      if (!confirm(`¿Confirmas desvincular el dominio ${name} del proyecto?`)) return;
      onDomainRemovedFromProject(name);
      if (onNotify) onNotify(`Dominio ${name} desvinculado`);
      return;
    }

    if (!confirm(`¿Confirmas eliminar el dominio ${name} permanentemente?`)) return;
    try {
      await api.deleteDomain(id);
      loadData();
      if (onNotify) onNotify(`Dominio ${name} eliminado`);
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

  const handleIssueWildcard = async () => {
    setIssuingWildcard(true);
    setWildcardProgress({ stage: 'submitting', progress: 10, message: 'Iniciando verificación de dominio con Cloudflare...' });

    try {
      const res = await api.issueWildcardSsl(wildcardDomain, undefined, wildcardProvider);
      if (res.success) {
        setWildcardProgress({ stage: 'installed', progress: 100, message: `¡Certificado Wildcard emitido para ${wildcardDomain}!` });
        setTimeout(() => {
          setShowWildcardModal(false);
          setIssuingWildcard(false);
          setWildcardProgress(null);
          loadData();
          if (onNotify) onNotify(`SSL Wildcard emitido para ${wildcardDomain}`);
        }, 1200);
      } else {
        setErrorBanner(`Error de emisión SSL: ${res.error}`);
        setWildcardProgress({ stage: 'error', progress: 100, message: `Error de emisión: ${res.error}` });
        setIssuingWildcard(false);
      }
    } catch (err: any) {
      setErrorBanner(`ACME DNS-01 error: ${err.message}`);
      setWildcardProgress({ stage: 'error', progress: 100, message: `Error de ACME: ${err.message}` });
      setIssuingWildcard(false);
    }
  };

  const handleIssueSslip = async () => {
    setIssuingSslip(true);
    try {
      const res = await api.issueOnDemandSslip(sslipIp, 'sslip.io');
      if (res.success) {
        setShowSslipModal(false);
        loadData();
        if (onNotify) onNotify(`Certificado automático emitido para ${res.cert.domain}`);
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

      {/* Top Header & Actions Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-white border border-slate-200 shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-600">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Dominios y Certificados SSL
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
              <span>Vincular Existente</span>
            </button>
          )}

          {/* Add Domain */}
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition-all shadow-sm cursor-pointer active:scale-95"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Añadir Dominio</span>
          </button>

          {/* Issue Wildcard ACME DNS-01 */}
          <button
            onClick={() => setShowWildcardModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-white text-xs font-semibold transition-all shadow-sm cursor-pointer active:scale-95"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Emitir Wildcard SSL</span>
          </button>

          {/* Zero Config sslip.io */}
          <button
            onClick={() => setShowSslipModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs font-medium transition-all cursor-pointer"
          >
            <Server className="w-3.5 h-3.5 text-blue-600" />
            <span>Wildcard Rápido (sslip.io)</span>
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
                <th className="py-3 px-4">Entorno Destino</th>
                <th className="py-3 px-4">Proxy Cloudflare</th>
                <th className="py-3 px-4">Certificado SSL</th>
                <th className="py-3 px-4">Comprobación</th>
                <th className="py-3 px-4 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredDomains.map((domain) => {
                const hasSsl = domain.sslStatus === 'active';
                const isForge = domain.targetPod === 'forge';

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
                            WILDCARD (*.)
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
                        title={`Clic para cambiar destino a ${isForge ? 'Producción (:8080)' : 'Desarrollo en vivo (:3001)'}`}
                      >
                        <span>{isForge ? 'Desarrollo' : 'Producción'}</span>
                        <span className="text-slate-500">:{domain.targetPort}</span>
                        <ArrowRightLeft className="w-3 h-3 ml-0.5 opacity-60" />
                      </button>
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
                        title={domain.cloudflareProxied ? 'Proxy Cloudflare activo (Clic para pasar a Solo DNS)' : 'Solo DNS (Clic para activar Proxy Cloudflare)'}
                      >
                        <Cloud className={`w-3.5 h-3.5 ${domain.cloudflareProxied ? 'fill-orange-400 text-orange-500' : 'text-slate-400'}`} />
                        <span>{domain.cloudflareProxied ? 'Proxy Activo (Nube ☁️)' : 'Solo DNS (Gris ☁️)'}</span>
                      </button>
                    </td>

                    {/* SSL Status */}
                    <td className="py-3.5 px-4">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-1.5">
                          {hasSsl ? (
                            <ShieldCheck className="w-4 h-4 text-emerald-600" />
                          ) : (
                            <ShieldAlert className="w-4 h-4 text-amber-600" />
                          )}
                          <span className={`font-semibold ${hasSsl ? 'text-emerald-700' : 'text-amber-700'}`}>
                            {hasSsl ? 'Seguro & Activo' : 'Pendiente SSL'}
                          </span>
                        </div>
                        {domain.certInfo && (
                          <div className="text-[11px] text-slate-500">
                            {domain.certInfo.daysRemaining} días restantes • {domain.certInfo.issuer.split(' ')[0]}
                          </div>
                        )}
                      </div>
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
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No se encontraron dominios con ese criterio de búsqueda.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* SSL Certificates Registry Section */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Bóveda de Certificados SSL
            </h3>
          </div>
          <span className="text-xs font-medium text-slate-500">
            Renovación automática habilitada (&lt;30 días)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {certs.map((cert) => (
            <div
              key={cert.id}
              className="p-4 rounded-xl bg-slate-50/70 border border-slate-200 flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">
                      {cert.domain}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      Emisor: {cert.issuer}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {cert.daysRemaining} DÍAS RESTANTES
                  </span>
                </div>

                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div>Algoritmo: <span className="font-semibold text-slate-800">{cert.keyType}</span></div>
                  <div className="truncate font-mono text-[11px]">Huella: <span className="text-slate-500">{cert.fingerprint}</span></div>
                  <div>SANs: <span className="font-semibold text-amber-700">{cert.sans?.join(', ')}</span></div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
                <span>Almacenamiento: ./data/certs/{cert.rootDomain}</span>
                <span className="text-emerald-700 font-medium flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Auto-renovable
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* --- MODAL: LINK EXISTING DOMAIN --- */}
      {showLinkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <h3 className="text-base font-bold text-slate-900">
              Vincular Dominio Existente
            </h3>
            <form onSubmit={handleLinkDomain} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Seleccionar Dominio
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
                  Vincular al Proyecto
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
              Añadir Nuevo Dominio
            </h3>

            <form onSubmit={handleAddDomain} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Nombre de Dominio o Wildcard
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
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">Entorno Destino</label>
                  <select
                    value={newTargetEntorno}
                    onChange={(e) => {
                      const val = e.target.value as 'forge' | 'citadel';
                      setNewTargetEntorno(val);
                      setNewTargetPort(val === 'forge' ? 3001 : 8080);
                    }}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-amber-500"
                  >
                    <option value="forge">Desarrollo (Puerto 3001)</option>
                    <option value="citadel">Producción (Puerto 8080)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">Puerto Interno</label>
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
                  Guardar y Enrutar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: WILDCARD ACME DNS-01 ISSUER --- */}
      {showWildcardModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
            <div className="flex items-center gap-2 text-amber-600">
              <Zap className="w-5 h-5" />
              <h3 className="text-base font-bold text-slate-900">
                Emitir Certificado Wildcard SSL (*.tudominio.com)
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Culkibo gestiona el desafío RFC 8555 ACME DNS-01 inyectando el registro TXT necesario en tu zona de Cloudflare y emitiendo un certificado SSL wildcard válido para <code>*.tudominio.com</code>.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Dominio Wildcard
                </label>
                <input
                  type="text"
                  value={wildcardDomain}
                  onChange={(e) => setWildcardDomain(e.target.value)}
                  disabled={issuingWildcard}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 font-mono focus:outline-none focus:bg-white focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Autoridad de Certificación (CA)
                </label>
                <select
                  value={wildcardProvider}
                  onChange={(e) => setWildcardProvider(e.target.value)}
                  disabled={issuingWildcard}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-amber-500"
                >
                  <option value="lets_encrypt">Let's Encrypt (ECDSA P-256 / ACME v2)</option>
                  <option value="zerossl">ZeroSSL (ECC CA)</option>
                </select>
              </div>

              {/* Progress Bar & Stage Indicator */}
              {wildcardProgress && (
                <div className="p-3.5 rounded-xl bg-amber-50/70 border border-amber-200 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-amber-800 font-medium">{wildcardProgress.message}</span>
                    <span className="text-amber-900 font-bold">{wildcardProgress.progress}%</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-amber-100 overflow-hidden">
                    <div
                      style={{ width: `${wildcardProgress.progress}%` }}
                      className="h-full bg-amber-500 transition-all duration-300"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowWildcardModal(false)}
                disabled={issuingWildcard}
                className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer transition-colors"
              >
                Cerrar
              </button>
              <button
                onClick={handleIssueWildcard}
                disabled={issuingWildcard}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-white font-semibold text-xs shadow-sm cursor-pointer active:scale-95 transition-all disabled:opacity-50"
              >
                <Zap className={`w-4 h-4 ${issuingWildcard ? 'animate-spin' : ''}`} />
                <span>{issuingWildcard ? 'Emitiendo Wildcard...' : 'Iniciar Emisión SSL'}</span>
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
                Wildcard Rápido con sslip.io
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Genera un subdominio comodín instantáneo sin necesidad de configurar DNS propios. Ideal para pruebas locales y previsualización inmediata.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Dirección IP Destino
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
                {issuingSslip ? 'Generando TLS...' : 'Generar Certificado Rápido'}
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
              Comprobador de Resolución DNS en Vivo
            </h3>

            {verifyingDns ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin text-amber-600" />
                <span className="text-xs font-medium">Consultando servidores DNS con autorización...</span>
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
                      {dnsVerifyResult.isCloudflareEdge ? 'SÍ (Proxy Cloudflare Activo ☁️)' : 'NO (DNS Directo)'}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-xs font-semibold text-slate-700 block mb-1">
                    Direcciones IP (Registros A):
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
                Cerrar Comprobador
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
              Simulador de Enrutamiento en el Borde
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              Muestra exactamente hacia qué entorno y puerto enviará el proxy inverso el tráfico que llegue con esta cabecera Host.
            </p>

            {testingIngress ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-slate-500 text-xs font-medium">
                <RefreshCw className="w-6 h-6 animate-spin text-amber-600" />
                <span>Simulando resolución de paquetes en el enrutador...</span>
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
                      <span className="text-slate-700">{ingressResult.isWildcard ? 'Comodín Wildcard (*.)' : 'Dominio Exacto'}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Entorno destino:</span>
                      <span className={`px-2 py-0.5 rounded-lg text-[11px] font-bold ${ingressResult.effectiveEntorno === 'forge' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'}`}>
                        {ingressResult.effectiveEntorno === 'forge' ? 'DESARROLLO (Puerto 3001)' : 'PRODUCCIÓN (Puerto 8080)'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Proxy Cloudflare:</span>
                      <span className={ingressResult.cloudflareProxied ? 'text-orange-600 font-medium' : 'text-slate-600'}>
                        {ingressResult.cloudflareProxied ? 'Proxy Activo (Nube Naranja ☁️)' : 'Solo DNS (Nube Gris ☁️)'}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs font-medium text-red-700">
                    {ingressResult.message || 'No se encontró una regla de enrutamiento válida.'}
                  </div>
                )}
              </div>
            ) : null}

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                onClick={() => setShowIngressModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer transition-colors"
              >
                Cerrar Simulador
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
