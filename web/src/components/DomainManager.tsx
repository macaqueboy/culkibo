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
  Stethoscope,
  SlidersHorizontal,
  Upload,
  CheckCircle2,
  Copy,
  Check,
  Radio,
  Terminal,
} from 'lucide-react';
import type {
  DomainItem,
  SslCertificate,
  IngressStatus,
  TlsProbe,
  DomainWizardPreset,
  IngressCapabilities,
  DomainDiagnosisReport,
  Project,
  EdgeTunnelStatusResult,
  EdgeTunnelCreateResult,
  EdgeShieldStatusResult,
  EdgeShieldChallengeResult,
  EdgeExperimentRecord,
  RateLimitPolicyRecord,
  RateLimitSimulateResult,
  StreamGuardEvalResult,
  DnsCutoverPreflightResult,
  DnsCutoverPlanResult,
  EdgeCacheCoalesceResult,
  EdgeCachePurgeResult,
} from '../lib/api';
import { api } from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { useTheme } from '../lib/theme';
import { DomainWizardModal } from './DomainWizardModal';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

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
  wizardPreset?: DomainWizardPreset | null;
  onClearWizardPreset?: () => void;
}

export const DomainManager: React.FC<DomainManagerProps> = ({
  onNotify,
  liveSslProgress,
  projectId,
  projectDomains,
  onDomainAddedToProject,
  onDomainRemovedFromProject,
  wizardTrigger = 0,
  wizardPreset = null,
  onClearWizardPreset,
}) => {
  const { t, locale } = useI18n();
  const { isDark } = useTheme();
  const [domains, setDomains] = useState<DomainItem[]>([]);
  const [certs, setCerts] = useState<SslCertificate[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [ingress, setIngress] = useState<IngressStatus | null>(null);
  const [capabilities, setCapabilities] = useState<IngressCapabilities | null>(null);

  // Sovereign EdgeTunnel (CGNAT) state
  const [tunnelStatus, setTunnelStatus] = useState<EdgeTunnelStatusResult | null>(null);
  // Edge Bot-Shield & Hashcash PoW Gate state
  const [shieldStatus, setShieldStatus] = useState<EdgeShieldStatusResult | null>(null);
  const [shieldChallenge, setShieldChallenge] = useState<EdgeShieldChallengeResult | null>(null);
  const [shieldLoading, setShieldLoading] = useState(false);
  const [shieldError, setShieldError] = useState<string | null>(null);
  // Cycle-11 Multi-Region Edge Geo-Routing (CF-IPCountry) & Sticky A/B Experiments state
  const [experiments, setExperiments] = useState<EdgeExperimentRecord[]>([]);
  const [expBusyId, setExpBusyId] = useState<string | null>(null);
  const [expError, setExpError] = useState<string | null>(null);
  const [expPreviewId, setExpPreviewId] = useState<string | null>(null);
  // Cycle-15 Edge API Rate-Limit & AI Wallet-Drain Shield (RPM + TPM)
  const [rlPolicies, setRlPolicies] = useState<RateLimitPolicyRecord[]>([]);
  const [rlSelectedTier, setRlSelectedTier] = useState<'free' | 'pro' | 'enterprise'>('pro');
  const [rlSimResult, setRlSimResult] = useState<RateLimitSimulateResult | null>(null);
  const [rlBusy, setRlBusy] = useState(false);
  const [rlError, setRlError] = useState<string | null>(null);
  // Cycle-16 Edge WS/SSE Flood & 101 Hop-by-Hop Guard + Zero-Downtime DNS Cutover Verifier
  const [streamGuardResult, setStreamGuardResult] = useState<StreamGuardEvalResult | null>(null);
  const [streamGuardBusy, setStreamGuardBusy] = useState(false);
  const [streamGuardError, setStreamGuardError] = useState<string | null>(null);
  const [dnsCutDomain, setDnsCutDomain] = useState('app.acme-demo.dev');
  const [dnsPreflightResult, setDnsPreflightResult] = useState<DnsCutoverPreflightResult | null>(null);
  const [dnsPlanResult, setDnsPlanResult] = useState<DnsCutoverPlanResult | null>(null);
  const [dnsCutBusy, setDnsCutBusy] = useState<'cf' | 'plan' | null>(null);
  const [dnsCutError, setDnsCutError] = useState<string | null>(null);
  // Cycle-17 Surrogate-Key Edge Cache & Stampede Coalescer (souin#884 / #850)
  const [cacheCoalesceResult, setCacheCoalesceResult] = useState<EdgeCacheCoalesceResult | null>(null);
  const [cachePurgeResult, setCachePurgeResult] = useState<EdgeCachePurgeResult | null>(null);
  const [cacheBusy, setCacheBusy] = useState(false);
  const [cacheError, setCacheError] = useState<string | null>(null);
  const [tunnelName, setTunnelName] = useState('');
  const [tunnelHost, setTunnelHost] = useState('127.0.0.1');
  const [tunnelPort, setTunnelPort] = useState('3000');
  const [tunnelHostname, setTunnelHostname] = useState('');
  const [creatingTunnel, setCreatingTunnel] = useState(false);
  const [revokingTunnelId, setRevokingTunnelId] = useState<string | null>(null);
  const [createdTunnelSecret, setCreatedTunnelSecret] = useState<EdgeTunnelCreateResult | null>(null);
  const [copiedTunnelCmd, setCopiedTunnelCmd] = useState(false);
  const [tunnelError, setTunnelError] = useState<string | null>(null);
  const [probingTls, setProbingTls] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [domainTypeFilter, setDomainTypeFilter] = useState<'all' | 'wildcard' | 'custom' | 'sslip'>('all');
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const [showWizard, setShowWizard] = useState(wizardTrigger > 0 || Boolean(wizardPreset));
  const [wizardKind, setWizardKind] = useState<'custom' | 'wildcard' | 'sslip'>('custom');

  // Diagnóstico 4 capas
  const [showDiagnoseModal, setShowDiagnoseModal] = useState(false);
  const [diagnosingId, setDiagnosingId] = useState<string | null>(null);
  const [diagnoseLoading, setDiagnoseLoading] = useState(false);
  const [diagnoseReport, setDiagnoseReport] = useState<DomainDiagnosisReport | null>(null);
  const [diagnoseError, setDiagnoseError] = useState<string | null>(null);

  // Editar dominio
  const [editingDomain, setEditingDomain] = useState<DomainItem | null>(null);
  const [editProjectId, setEditProjectId] = useState<string>('');
  const [editPod, setEditPod] = useState<'forge' | 'citadel' | 'service'>('citadel');
  const [editPort, setEditPort] = useState<number>(8080);
  const [editRedirect, setEditRedirect] = useState<'none' | 'www_to_apex' | 'apex_to_www'>('none');
  const [editSecHeaders, setEditSecHeaders] = useState<boolean>(true);
  const [editFramePolicy, setEditFramePolicy] = useState<'SAMEORIGIN' | 'DENY' | 'ALLOW'>('SAMEORIGIN');
  const [editMaxBodyMb, setEditMaxBodyMb] = useState<string>('');
  const [editIpAllowlist, setEditIpAllowlist] = useState<string>('');
  const [editCustomHeaders, setEditCustomHeaders] = useState<string>('');
  const [editBasicAuthEnabled, setEditBasicAuthEnabled] = useState<boolean>(false);
  const [editBasicAuthUser, setEditBasicAuthUser] = useState<string>('');
  const [editBasicAuthPass, setEditBasicAuthPass] = useState<string>('');
  const [savingEdit, setSavingEdit] = useState(false);

  // Auditoría TLS
  const [auditingTls, setAuditingTls] = useState(false);
  const [tlsAuditSummary, setTlsAuditSummary] = useState<{ ok: number; expiring: number; expired: number; errors: number } | null>(null);

  // Wildcard DNS-01 & ACME email
  const [newWildcardRoot, setNewWildcardRoot] = useState('');
  const [addingWildcard, setAddingWildcard] = useState(false);
  const [removingWildcard, setRemovingWildcard] = useState<string | null>(null);
  const [acmeEmailInput, setAcmeEmailInput] = useState('');
  const [savingAcme, setSavingAcme] = useState(false);
  const [copiedCaddyCmd, setCopiedCaddyCmd] = useState(false);

  // Subir PEM / Cloudflare Origin CA
  const [showUploadCertModal, setShowUploadCertModal] = useState(false);
  const [uploadDomain, setUploadDomain] = useState('');
  const [uploadProvider, setUploadProvider] = useState<'cloudflare_origin_ca' | 'custom_pem'>('cloudflare_origin_ca');
  const [uploadCertPem, setUploadCertPem] = useState('');
  const [uploadKeyPem, setUploadKeyPem] = useState('');
  const [uploadingCert, setUploadingCert] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

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

  const [prevPreset, setPrevPreset] = useState<DomainWizardPreset | null>(wizardPreset);
  if (wizardPreset !== prevPreset) {
    setPrevPreset(wizardPreset);
    if (wizardPreset) {
      setWizardKind(wizardPreset.suggestedHostname?.startsWith('*.') ? 'wildcard' : 'custom');
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
      const [domRes, certRes, fastIng, capsRes, projList] = await Promise.all([
        api.getDomains(),
        api.getCertificates(),
        api.getIngressStatus({ probe: false }).catch(() => null),
        projectId ? Promise.resolve(null) : api.getIngressCapabilities().catch(() => null),
        projectId ? Promise.resolve([]) : api.getProjects().catch(() => []),
      ]);
      setDomains(domRes.domains || []);
      setCerts(certRes.certificates || []);
      setIngress(fastIng);
      if (capsRes) {
        setCapabilities(capsRes);
        setAcmeEmailInput(capsRes.acmeEmail || '');
      }
      if (Array.isArray(projList)) setProjects(projList);
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
  }, [projectId]);

  const handleSimulateAiBurst = async (overrideTier?: 'free' | 'pro' | 'enterprise') => {
    const tier = overrideTier || rlSelectedTier;
    if (overrideTier) setRlSelectedTier(overrideTier);
    setRlBusy(true);
    setRlError(null);
    try {
      let pol = rlPolicies.find((p) => p.planTier === tier) || rlPolicies[0];
      if (!pol) {
        const created = await api.saveEdgeRateLimit({
          name: `${tier.toUpperCase()} AI API Shield`,
          planTier: tier,
          rpmLimit: tier === 'free' ? 30 : tier === 'pro' ? 120 : 600,
          tpmLimit: tier === 'free' ? 15000 : tier === 'pro' ? 60000 : 300000,
          burstMultiplier: 1.5,
          windowSec: 60,
        });
        pol = created?.policy;
        if (pol) setRlPolicies((prev) => [pol, ...prev]);
      }
      const res = await api.simulateEdgeRateLimit({
        policyId: pol?.id || `rl_${tier}`,
        requestsCount: 20,
        tokensPerRequest: tier === 'enterprise' ? 25000 : 5000,
        intervalMs: 50,
        clientKey: 'tenant_burst_demo',
      });
      setRlSimResult(res);
      onNotify?.(
        `AI Burst Shield (${tier}): ${res.throttledCount}/${res.totalRequests} throttled (HTTP 429 · $${Number(res.estimatedWalletSavedUsd ?? 0).toFixed(2)} saved)`,
        'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Rate-limit simulation failed';
      setRlError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setRlBusy(false);
    }
  };

  const handleSimulateStreamGuard = async () => {
    setStreamGuardBusy(true);
    setStreamGuardError(null);
    try {
      const res = await api.evaluateStreamGuard({
        projectId: projectId || 'proj_acme_web',
        clientIp: '198.51.100.88',
        protocol: 'ws',
        activePerIp: 25,
        activeProject: 140,
        headerElapsedMs: 120,
        bytesPerSec: 1024,
        bufferedBytes: 65536,
        upgradeHeaders: {
          Connection: 'Upgrade, Keep-Alive',
          Upgrade: 'websocket',
          'Sec-WebSocket-Accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
          'Proxy-Authenticate': 'Basic realm="leak"',
          'Alt-Svc': 'h3=":443"',
          'Keep-Alive': 'timeout=5',
        },
      });
      setStreamGuardResult(res);
      onNotify?.(
        `WS/SSE Flood Guard: HTTP ${res.httpStatus ?? 429} / WS ${res.wsCloseCode ?? 1013} · ${(Array.isArray(res.strippedHeaders) ? res.strippedHeaders.length : 3)} hop headers scrubbed`,
        'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Stream flood guard evaluation failed';
      setStreamGuardError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setStreamGuardBusy(false);
    }
  };

  const handleTestCloudflareCutover = async () => {
    const dom = dnsCutDomain.trim() || 'app.acme-demo.dev';
    setDnsCutBusy('cf');
    setDnsCutError(null);
    try {
      const res = await api.preflightDnsCutover({
        domain: dom,
        targetIpv4: '91.107.194.22',
        challengeMode: 'http-01',
        recordsSnapshot: { aRecords: ['104.21.10.5'], txtAcmeRecords: [] },
      });
      setDnsPreflightResult(res);
      onNotify?.(`DNS Cutover Check: ${res.code} (Cloudflare Anycast proxy detected — NOT false DNS mismatch)`, 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'DNS cutover preflight failed';
      setDnsCutError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setDnsCutBusy(null);
    }
  };

  const handleBuildDnsCutoverPlan = async () => {
    const dom = dnsCutDomain.trim() || 'app.acme-demo.dev';
    setDnsCutBusy('plan');
    setDnsCutError(null);
    try {
      const res = await api.buildDnsCutoverPlan({
        domain: dom,
        currentTtlSec: 3600,
        targetTtlSec: 60,
        targetIp: '91.107.194.22',
        acmeMode: 'dns-01',
        soaRefreshSec: 3600,
        nameserverSerials: [2026112801, 2026112801],
      });
      setDnsPlanResult(res);
      onNotify?.(`5-Phase Zero-Downtime DNS Cutover Plan ready (minPreCutoverWaitSec: ${res.minPreCutoverWaitSec ?? 3600}s)`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'DNS cutover plan failed';
      setDnsCutError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setDnsCutBusy(null);
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getDomains(),
      api.getCertificates(),
      api.getIngressStatus({ probe: false }).catch(() => null),
      projectId ? Promise.resolve(null) : api.getIngressCapabilities().catch(() => null),
      projectId ? Promise.resolve([]) : api.getProjects().catch(() => []),
      projectId ? Promise.resolve(null) : api.getEdgeTunnelStatus().catch(() => null),
      projectId ? Promise.resolve(null) : api.getEdgeShieldStatus().catch(() => null),
      api.listEdgeExperiments(projectId).catch(() => ({ experiments: [] })),
      projectId ? Promise.resolve({ policies: [] }) : api.listEdgeRateLimits().catch(() => ({ policies: [] })),
    ])
      .then(([domRes, certRes, fastIng, capsRes, projList, tunRes, shRes, expRes, rlRes]) => {
        if (!active) return;
        const list = domRes.domains || [];
        setDomains(list);
        setCerts(certRes.certificates || []);
        setIngress(fastIng);
        if (capsRes) {
          setCapabilities(capsRes);
          setAcmeEmailInput(capsRes.acmeEmail || '');
        }
        if (Array.isArray(projList)) setProjects(projList);
        if (tunRes) setTunnelStatus(tunRes);
        if (shRes) setShieldStatus(shRes);
        if (expRes && Array.isArray(expRes.experiments)) setExperiments(expRes.experiments);
        if (rlRes && Array.isArray(rlRes.policies)) setRlPolicies(rlRes.policies);
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
  }, [projectId]);

  const handlePreviewShieldChallenge = async () => {
    setShieldLoading(true);
    setShieldError(null);
    try {
      const res = await api.getEdgeShieldChallenge(domains[0]?.hostname);
      setShieldChallenge(res);
    } catch (err: unknown) {
      setShieldError(err instanceof Error ? err.message : 'Edge Shield challenge unavailable');
    } finally {
      setShieldLoading(false);
    }
  };

  const handleCreateDemoExperiment = async (kind: 'ab' | 'geo') => {
    setExpBusyId(`create-${kind}`);
    setExpError(null);
    try {
      const host = domains[0]?.hostname || 'app.acme-demo.dev';
      const targetProj = projectId || projects[0]?.id || undefined;
      const payload = kind === 'geo'
        ? {
            projectId: targetProj,
            name: 'EU / US Regional Geo-Router',
            hostname: host,
            headerName: 'CF-IPCountry',
            regions: [
              { countries: ['DE', 'FR', 'ES'], upstream: '10.88.0.2:3000', label: 'eu-central' },
              { countries: ['US', 'CA'], upstream: '10.88.0.3:3000', label: 'us-east' },
            ],
            defaultUpstream: '127.0.0.1:3000',
          }
        : {
            projectId: targetProj,
            name: 'Sticky Cookie 50/50 A/B Split',
            hostname: host,
            stickyMode: 'cookie' as const,
            cookieName: `ckb_ab_${Date.now().toString(36).slice(-4)}`,
            variants: [
              { name: 'control', upstream: '127.0.0.1:3000', weight: 50 },
              { name: 'variant-b', upstream: '127.0.0.1:3001', weight: 50 },
            ],
          };
      const created = await api.upsertEdgeExperiment(payload);
      setExperiments((prev) => [created, ...prev.filter((e) => e.id !== created.id)]);
      setExpPreviewId(created.id);
      onNotify?.(`Compiled native Caddy v2.11 ${kind === 'geo' ? 'Geo-IP' : 'Sticky A/B'} route for ${host}`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not compile edge experiment';
      setExpError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setExpBusyId(null);
    }
  };

  const handleKillExperiment = async (expId: string) => {
    setExpBusyId(`kill-${expId}`);
    setExpError(null);
    try {
      const updated = await api.killEdgeExperiment(expId, 'operator_kill_switch');
      setExperiments((prev) => prev.map((e) => (e.id === expId ? updated : e)));
      onNotify?.('Kill-Switch engaged — traffic reverted instantly to 100% control upstream', 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not trigger kill-switch';
      setExpError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setExpBusyId(null);
    }
  };

  const tlsFor = (hostname: string): TlsProbe | null =>
    (Array.isArray(ingress?.tls) ? ingress.tls : []).find((t) => t?.hostname === hostname) || null;

  const routeFor = (hostname: string) =>
    (Array.isArray(ingress?.routes) ? ingress.routes : []).find((r) => Array.isArray(r?.hosts) && r.hosts.includes(hostname)) || null;

  const skippedReasonFor = (hostname: string) =>
    (Array.isArray(ingress?.skipped) ? ingress.skipped : []).find((s) => Array.isArray(s?.hostnames) && s.hostnames.includes(hostname))?.reason || null;

  const handleTestEdgeCache = async () => {
    setCacheBusy(true);
    setCacheError(null);
    try {
      const [coalRes, purgeRes] = await Promise.all([
        api.evaluateEdgeCacheCoalesce({
          cacheKey: '/api/v1/account/billing',
          inFlightCount: 12,
          backendTimeoutMs: 5000,
          cacheControl: 'private, no-store',
        }),
        api.purgeEdgeCacheByTags({
          tags: ['product:42', 'pricing'],
          providers: ['caddy', 'cloudflare', 'fastly'],
          dryRun: true,
        }),
      ]);
      setCacheCoalesceResult(coalRes);
      setCachePurgeResult(purgeRes);
      onNotify?.(`Edge Cache Guard: ${coalRes.reason} · Multi-edge dry-run purge planned across ${(purgeRes.providers || []).length || 3} providers`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Edge cache guard evaluation failed';
      setCacheError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setCacheBusy(false);
    }
  };

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

  const handleToggleEntorno = async (id: string, currentPod: 'forge' | 'citadel' | 'service', hostname: string) => {
    if (currentPod === 'service') return;
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

  const handleDiagnose = async (domainId: string) => {
    setDiagnosingId(domainId);
    setShowDiagnoseModal(true);
    setDiagnoseLoading(true);
    setDiagnoseReport(null);
    setDiagnoseError(null);
    try {
      const report = await api.diagnoseDomain(domainId);
      setDiagnoseReport(report);
    } catch (err: any) {
      setDiagnoseError(err?.message || 'Error ejecutando el diagnóstico');
    } finally {
      setDiagnoseLoading(false);
    }
  };

  const openEditDomain = (dom: DomainItem) => {
    setEditingDomain(dom);
    setEditProjectId(dom.projectId || '');
    setEditPod(dom.targetPod);
    setEditPort(dom.targetPort || 8080);
    setEditRedirect(dom.canonicalRedirect || 'none');
    setEditSecHeaders(dom.securityHeaders !== false);
    setEditFramePolicy(dom.framePolicy || 'SAMEORIGIN');
    setEditMaxBodyMb(dom.maxBodySizeMb ? String(dom.maxBodySizeMb) : '');
    setEditIpAllowlist(Array.isArray(dom.ipAllowlist) ? dom.ipAllowlist.join(', ') : '');
    setEditCustomHeaders(
      dom.customHeaders
        ? Object.entries(dom.customHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
        : ''
    );
    setEditBasicAuthEnabled(Boolean(dom.basicAuth?.enabled));
    setEditBasicAuthUser(dom.basicAuth?.username || '');
    setEditBasicAuthPass('');
  };

  const handleSaveEditDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingDomain) return;
    setSavingEdit(true);
    try {
      const parsedIps = editIpAllowlist
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const parsedHeaders: Record<string, string> = {};
      for (const rawLine of editCustomHeaders.split(/\r?\n/)) {
        const idx = rawLine.indexOf(':');
        if (idx <= 0) continue;
        const k = rawLine.slice(0, idx).trim();
        const v = rawLine.slice(idx + 1).trim();
        if (k && v) parsedHeaders[k] = v;
      }
      const maxMbNum = editMaxBodyMb.trim() ? Number(editMaxBodyMb.trim()) : null;
      const basicAuthPayload = editBasicAuthEnabled
        ? {
            enabled: true,
            username: editBasicAuthUser.trim() || 'admin',
            ...(editBasicAuthPass ? { password: editBasicAuthPass } : {}),
          }
        : { enabled: false };

      await api.updateDomain(editingDomain.id, {
        projectId: editProjectId || null,
        targetPod: editPod,
        targetPort: Number(editPort) || editingDomain.targetPort,
        canonicalRedirect: editRedirect,
        securityHeaders: editSecHeaders,
        framePolicy: editFramePolicy,
        maxBodySizeMb: maxMbNum && Number.isFinite(maxMbNum) && maxMbNum > 0 ? maxMbNum : null,
        ipAllowlist: parsedIps,
        customHeaders: parsedHeaders,
        basicAuth: basicAuthPayload,
      });
      onNotify?.(`Configuración de ${editingDomain.hostname} actualizada en Caddy`, 'success');
      setEditingDomain(null);
      void loadData(true);
    } catch (err: any) {
      setErrorBanner(`No se pudo actualizar ${editingDomain.hostname}: ${err.message}`);
    } finally {
      setSavingEdit(false);
    }
  };

  const handleRunTlsAudit = async () => {
    setAuditingTls(true);
    try {
      const res = await api.runTlsAudit({ warnDays: 14, probeLive: true });
      const summary = {
        ok: (res.ok || []).length,
        expiring: (res.expiring || []).length,
        expired: (res.expired || []).length,
        errors: (res.errors || []).length,
      };
      setTlsAuditSummary(summary);
      onNotify?.(
        summary.expired > 0 || summary.expiring > 0
          ? `Auditoría TLS: ${summary.expired} caducados, ${summary.expiring} próximos a caducar, ${summary.ok} vigentes`
          : `Auditoría TLS completada: ${summary.ok} certificados vigentes`,
        summary.expired > 0 ? 'error' : summary.expiring > 0 ? 'info' : 'success'
      );
      void loadData(false);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo auditar la caducidad TLS', 'error');
    } finally {
      setAuditingTls(false);
    }
  };

  const handleAddWildcardPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanRoot = newWildcardRoot.trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot || !cleanRoot.includes('.')) return;
    setAddingWildcard(true);
    try {
      const res = await api.configureWildcardDns01(cleanRoot);
      setNewWildcardRoot('');
      if (res && res.applied === false) {
        onNotify?.(
          res.message || `Política *.${cleanRoot} guardada, pero pendiente de aplicar en Caddy`,
          'info'
        );
      } else {
        onNotify?.(`Política Wildcard DNS-01 aplicada para *.${cleanRoot}`, 'success');
      }
      void loadData(false);
    } catch (err: any) {
      setErrorBanner(err?.message || 'No se pudo añadir la política Wildcard');
    } finally {
      setAddingWildcard(false);
    }
  };

  const handleRemoveWildcardPolicy = async (rootDomain: string) => {
    setRemovingWildcard(rootDomain);
    try {
      await api.removeWildcardPolicy(rootDomain);
      onNotify?.(`Política Wildcard *.${rootDomain} eliminada`, 'info');
      void loadData(false);
    } catch (err: any) {
      setErrorBanner(err?.message || 'No se pudo eliminar la política Wildcard');
    } finally {
      setRemovingWildcard(null);
    }
  };

  const handleSaveAcmeEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingAcme(true);
    try {
      await api.setAcmeEmail(acmeEmailInput.trim() || null);
      onNotify?.('Correo ACME actualizado para avisos de Let’s Encrypt', 'success');
      void loadData(false);
    } catch (err: any) {
      setErrorBanner(err?.message || 'No se pudo actualizar el correo ACME');
    } finally {
      setSavingAcme(false);
    }
  };

  const handleUploadCert = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploadingCert(true);
    setUploadError(null);
    try {
      await api.uploadCustomCertificate({
        domain: uploadDomain.trim(),
        certPem: uploadCertPem,
        keyPem: uploadKeyPem,
        provider: uploadProvider,
      });
      setShowUploadCertModal(false);
      setUploadDomain('');
      setUploadCertPem('');
      setUploadKeyPem('');
      onNotify?.('Certificado PEM verificado, guardado y sincronizado con Caddy', 'success');
      void loadData(true);
    } catch (err: any) {
      setUploadError(err?.message || 'El certificado o la clave PEM no son válidos');
    } finally {
      setUploadingCert(false);
    }
  };

  const handleDeleteCert = async (certId: string, label: string) => {
    try {
      await api.deleteCertificate(certId);
      onNotify?.(`Certificado ${label} revocado`, 'info');
      void loadData(false);
    } catch (err: any) {
      setErrorBanner(err?.message || 'No se pudo eliminar el certificado');
    }
  };

  const handleCreateEdgeTunnel = async (e: React.FormEvent) => {
    e.preventDefault();
    const portNum = Number(tunnelPort);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return;
    setCreatingTunnel(true);
    setTunnelError(null);
    try {
      const created = await api.createEdgeTunnel({
        name: tunnelName.trim() || `tunnel-${portNum}`,
        targetHost: tunnelHost.trim() || '127.0.0.1',
        targetPort: portNum,
        hostname: tunnelHostname.trim() || undefined,
      });
      setCreatedTunnelSecret(created);
      setTunnelName('');
      setTunnelHostname('');
      onNotify?.(`EdgeTunnel "${created.name}" created`, 'success');
      const status = await api.getEdgeTunnelStatus().catch(() => null);
      if (status) setTunnelStatus(status);
    } catch (err: unknown) {
      setTunnelError(err instanceof Error ? err.message : 'Failed to create EdgeTunnel');
    } finally {
      setCreatingTunnel(false);
    }
  };

  const handleRevokeEdgeTunnel = async (id: string) => {
    setRevokingTunnelId(id);
    setTunnelError(null);
    try {
      await api.revokeEdgeTunnel(id);
      if (createdTunnelSecret?.id === id) setCreatedTunnelSecret(null);
      onNotify?.(`EdgeTunnel ${id} revoked`, 'info');
      const status = await api.getEdgeTunnelStatus().catch(() => null);
      if (status) setTunnelStatus(status);
    } catch (err: unknown) {
      setTunnelError(err instanceof Error ? err.message : 'Failed to revoke EdgeTunnel');
    } finally {
      setRevokingTunnelId(null);
    }
  };

  const buildTunnelAgentCmd = (tun: EdgeTunnelCreateResult): string => {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${window.location.host}/ws/edge-tunnel`;
    return `culkibo tunnel-agent --url ${wsUrl} --id ${tun.id} --token ${tun.token} --target ${tun.targetHost}:${tun.targetPort}`;
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
  const onDiskCerts = certs.filter((c) => c.status === 'on_disk');
  const wildcardPolicies = capabilities?.wildcardPolicies || [];

  return (
    <div className="space-y-5">
      {/* Cabecera fuera de tarjeta */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          {projectId ? (
            <h2 className="text-base font-semibold text-slate-900">{t('domains.projectTitle')}</h2>
          ) : (
            <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('domains.title')}</h1>
          )}
          <p className="text-sm text-slate-500 mt-1">{t('domains.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {projectId && (
            <button
              type="button"
              onClick={() => setShowLinkModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium cursor-pointer"
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>{t('domains.linkExisting')}</span>
            </button>
          )}

          {!projectId && (
            <button
              type="button"
              onClick={() => {
                setUploadError(null);
                setShowUploadCertModal(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{t('domains.uploadPem')}</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => {
              onClearWizardPreset?.();
              setWizardKind('custom');
              setShowWizard(true);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('domains.connect')}</span>
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
              ? (ingress.inSync
                  ? 'bg-white border-slate-200'
                  : 'bg-amber-50 border-amber-200 dark:bg-amber-950/40 dark:border-amber-800/60 dark:text-amber-200')
              : 'bg-amber-50/80 border-amber-200 dark:bg-amber-950/40 dark:border-amber-800/60 dark:text-amber-200'
          }`}
          style={
            isDark && (!ingress.available || !ingress.inSync)
              ? {
                  backgroundColor: 'rgba(69, 26, 3, 0.42)',
                  borderColor: 'rgba(146, 64, 14, 0.65)',
                  color: '#fde68a',
                }
              : undefined
          }
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div
                className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${
                  ingress.available ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-amber-100 border-amber-200 text-amber-800'
                }`}
                style={
                  isDark && !ingress.available
                    ? { backgroundColor: 'rgba(120, 53, 15, 0.55)', borderColor: 'rgba(180, 83, 9, 0.65)', color: '#fcd34d' }
                    : undefined
                }
              >
                {ingress.available ? <Zap className="w-4 h-4" /> : <ShieldOff className="w-4 h-4" />}
              </div>
              <div>
                <div
                  className="font-semibold text-slate-900"
                  style={isDark && (!ingress.available || !ingress.inSync) ? { color: '#fef3c7' } : undefined}
                >
                  {ingress.available
                    ? t('domains.caddyActive', {
                        ver: ingress.version && /^v?\d/i.test(ingress.version) ? ` ${ingress.version}` : '',
                        url: ingress.adminUrl || 'localhost:2019',
                      })
                    : t('domains.caddyStopped')}
                </div>
                <p
                  className="text-slate-600 mt-0.5 max-w-2xl leading-relaxed"
                  style={isDark && (!ingress.available || !ingress.inSync) ? { color: '#fde68a' } : undefined}
                >
                  {(() => {
                    const ingAny = ingress as IngressStatus & { messageEn?: string; code?: string };
                    if (locale === 'en') {
                      if (ingAny.messageEn) return ingAny.messageEn;
                      if (ingAny.code === 'CADDY_ADMIN_FORBIDDEN') return t('domains.caddyAdminForbiddenEn');
                      if (!ingress.available) return t('domains.caddyOfflineEn');
                      return ingress.inSync ? t('domains.caddySyncedEn') : t('domains.caddyDriftEn');
                    }
                    return ingress.message;
                  })()}
                </p>
                {ingress.available && (
                  <p className="text-slate-500 mt-1 tabular-nums">
                    {t('domains.routesPublished', {
                      count: ingress.routesManaged,
                      unit: locale === 'es'
                        ? (ingress.routesManaged === 1 ? 'ruta publicada' : 'rutas publicadas')
                        : (ingress.routesManaged === 1 ? 'route' : 'routes'),
                    })}
                    {ingress.inSync
                      ? ` · ${t('domains.inSync')}`
                      : ` · ${ingress.drift.missing.length} missing, ${ingress.drift.unexpected.length} extra${(ingress.drift.modified?.length || 0) > 0 ? `, ${ingress.drift.modified?.length} outdated` : ''}`}
                    {probingTls ? ` · ${t('domains.tlsChecking')}` : ''}
                    {tlsAuditSummary && ` · TLS: ${tlsAuditSummary.ok} OK${tlsAuditSummary.expiring ? `, ${tlsAuditSummary.expiring} expiring` : ''}${tlsAuditSummary.expired ? `, ${tlsAuditSummary.expired} expired` : ''}`}
                  </p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 flex-wrap">
              {!ingress.available ? (
                <button
                  type="button"
                  onClick={() => void handleStartCaddy()}
                  disabled={startingCaddy}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {startingCaddy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{t('domains.activateCaddy')}</span>
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={() => void handleRunTlsAudit()}
                    disabled={auditingTls}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer disabled:opacity-50"
                  >
                    <ShieldCheck className={`w-3.5 h-3.5 ${auditingTls ? 'animate-pulse' : ''}`} />
                    <span>{t('domains.auditTls')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleReconcile()}
                    disabled={reconciling}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${reconciling ? 'animate-spin' : ''}`} />
                    <span>{t('domains.reconcile')}</span>
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Edge Bot-Shield & Hashcash PoW Gate Pill */}
      {!projectId && (
        <section className="culkibo-surface rounded-xl p-4 text-xs space-y-2.5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-slate-900">{t('domains.shieldTitle')}</span>
                  <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-mono font-semibold tabular-nums">
                    SHA-256 PoW · diff {shieldStatus?.defaultDifficulty ?? 4}
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.shieldDesc')}</p>
                {shieldStatus && (
                  <div className="flex flex-wrap items-center gap-2 mt-1.5 font-mono text-[11px] text-slate-600 tabular-nums">
                    <span>
                      {Array.isArray(shieldStatus.blockedPathRules) ? shieldStatus.blockedPathRules.length : shieldStatus.blockedPathRules} scanner rules
                    </span>
                    <span>·</span>
                    <span>
                      {Array.isArray(shieldStatus.blockedUaPatterns) ? shieldStatus.blockedUaPatterns.length : shieldStatus.blockedUaPatterns} AI-scraper UAs
                    </span>
                    <span>·</span>
                    <span>{shieldStatus.powEnabledCount} PoW gate(s)</span>
                  </div>
                )}
              </div>
            </div>
            <button
              type="button"
              disabled={shieldLoading}
              onClick={() => void handlePreviewShieldChallenge()}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50 self-start md:self-auto"
            >
              {shieldLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
              <span>{shieldLoading ? t('domains.shieldLoading') : t('domains.shieldPreview')}</span>
            </button>
          </div>
          {shieldError && (
            <div className="p-2 rounded-lg bg-red-50 border border-red-200 text-red-700">{shieldError}</div>
          )}
          {shieldChallenge && (
            <div className="p-3 rounded-lg bg-slate-950 text-slate-100 border border-slate-800 font-mono text-[11px] flex flex-col sm:flex-row sm:items-center justify-between gap-2 tabular-nums">
              <div className="truncate">
                <span className="text-emerald-400">{shieldChallenge.algorithm.toUpperCase()}</span>
                {' · '}diff={shieldChallenge.difficulty}
                {' · '}salt={shieldChallenge.salt}
                {shieldChallenge.domain ? ` · ${shieldChallenge.domain}` : ''}
              </div>
              <button
                type="button"
                onClick={() => setShieldChallenge(null)}
                aria-label="Close PoW preview"
                className="text-slate-400 hover:text-white cursor-pointer self-end sm:self-auto"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </section>
      )}

      {/* Filtros */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1 p-0.5 bg-slate-100 border border-slate-200 rounded-lg text-xs">
          {([
            { id: 'all', label: `${t('domains.filterAll')} (${scopedDomains.length})` },
            { id: 'custom', label: `${t('domains.filterCustom')} (${customCount})` },
            { id: 'wildcard', label: `${t('domains.filterWildcard')} (${wildcardCount})` },
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
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder={t('domains.searchPlaceholder')}
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
                <th className="py-2.5 px-4">{t('domains.colDomain')}</th>
                <th className="py-2.5 px-4">{t('domains.colTarget')}</th>
                <th className="py-2.5 px-4">{t('domains.colRoute')}</th>
                <th className="py-2.5 px-4">{t('domains.colCloudflare')}</th>
                <th className="py-2.5 px-4">{t('domains.colTls')}</th>
                <th className="py-2.5 px-4 text-right">{t('domains.colActions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredDomains.map((domain) => {
                const isForge = domain.targetPod === 'forge';
                const isService = domain.targetPod === 'service';
                const probe = tlsFor(domain.hostname);
                const liveRoute = routeFor(domain.hostname);
                const skippedReason = skippedReasonFor(domain.hostname);
                const confirming = confirmDeleteId === domain.id;

                return (
                  <tr key={domain.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-medium text-slate-900 font-mono">{domain.hostname}</span>
                        {domain.isWildcard && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                            {t('domains.badgeWildcard')}
                          </span>
                        )}
                        {domain.canonicalRedirect === 'www_to_apex' && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                            {t('domains.badgeWwwToApex')}
                          </span>
                        )}
                        {domain.canonicalRedirect === 'apex_to_www' && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                            {t('domains.badgeApexToWww')}
                          </span>
                        )}
                        {domain.basicAuth?.enabled && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-900 text-white" title="HTTP Basic Auth">
                            Basic Auth
                          </span>
                        )}
                        {Array.isArray(domain.ipAllowlist) && domain.ipAllowlist.length > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-700 border border-slate-200" title={domain.ipAllowlist.join(', ')}>
                            {domain.ipAllowlist.length} IPs
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      {isService ? (
                        <span
                          title={`:${domain.targetPort}`}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-200 bg-slate-50 text-slate-700 tabular-nums"
                        >
                          <span>{domain.serviceName || 'Service'}</span>
                          <span className="text-slate-400 font-mono">:{domain.targetPort}</span>
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => void handleToggleEntorno(domain.id, domain.targetPod, domain.hostname)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 cursor-pointer tabular-nums"
                        >
                          <span>{isForge ? t('domains.envDev') : t('domains.envProd')}</span>
                          <span className="text-slate-400 font-mono">:{domain.targetPort}</span>
                          <ArrowRightLeft className="w-3 h-3 text-slate-400" />
                        </button>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      {liveRoute ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-emerald-700 font-medium">
                            <Link2 className="w-3.5 h-3.5" />
                            <span>{t('domains.routePublished')}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">{liveRoute.upstreams.join(', ')}</div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-slate-500">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>{t('domains.routeNone')}</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[180px] truncate">
                            {skippedReason || (ingress && !ingress.available ? t('domains.caddyStopped') : t('domains.routePending'))}
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
                        <span>{domain.cloudflareProxied ? t('domains.cfProxy') : t('domains.cfDnsOnly')}</span>
                      </button>
                    </td>

                    <td className="py-3 px-4">
                      {!probe ? (
                        <span className="text-[11px] text-slate-400">
                          {probingTls ? t('domains.tlsChecking') : t('domains.tlsNotProbed')}
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
                              {probe.issuer || probe.issuerCN || t('domains.tlsDetected')}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 tabular-nums">
                            {t('domains.tlsExpires')} {formatDate(probe.notAfter)}
                            {typeof probe.daysRemaining === 'number' && ` · ${probe.daysRemaining} d`}
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1 text-slate-500">
                            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
                            <span>{t('domains.routePending')}</span>
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-[180px] truncate" title={probe.error}>
                            {probe.error || t('domains.tlsPointDns')}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right">
                      {confirming ? (
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => void handleConfirmDelete(domain.id, domain.hostname)}
                            className="px-2 py-1 rounded-md bg-red-600 text-white text-[11px] font-medium cursor-pointer"
                          >
                            {t('domains.confirm')}
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
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            onClick={() => void handleDiagnose(domain.id)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer"
                          >
                            <Stethoscope className="w-3 h-3 text-slate-500" />
                            <span>{t('domains.diagnose')}</span>
                          </button>
                          <button
                            type="button"
                            aria-label={`Editar ${domain.hostname}`}
                            title="Editar destino, redirección www y cabeceras"
                            onClick={() => openEditDomain(domain)}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
                          >
                            <SlidersHorizontal className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            aria-label={projectId ? `Desvincular ${domain.hostname}` : `Eliminar ${domain.hostname}`}
                            onClick={() => setConfirmDeleteId(domain.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                            title={projectId ? 'Desvincular dominio' : 'Eliminar dominio'}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}

              {filteredDomains.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500">
                    <div className="space-y-2.5">
                      <p className="text-xs">{t('domains.empty')}</p>
                      <button
                        type="button"
                        onClick={() => {
                          onClearWizardPreset?.();
                          setWizardKind('custom');
                          setShowWizard(true);
                        }}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>{t('domains.connectFirst')}</span>
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Panel Multi-Wildcard DNS-01 y correo ACME (solo en vista global de Dominios) */}
      {!projectId && (
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">{t('domains.wildcardTitle')}</h2>
              <p className="text-xs text-slate-500 mt-0.5">{t('domains.wildcardDesc')}</p>
            </div>
            {capabilities && (
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border self-start sm:self-auto ${
                capabilities.hasCloudflareDnsPlugin === true
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-amber-50 text-amber-800 border-amber-200'
              }`}>
                {capabilities.hasCloudflareDnsPlugin === true ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{t('domains.cfPluginActive')}</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>{t('domains.cfPluginMissing')}</span>
                  </>
                )}
              </span>
            )}
          </div>

          {capabilities && capabilities.hasCloudflareDnsPlugin === false && (
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span>{t('domains.cfPluginHint')}</span>
              <button
                type="button"
                onClick={async () => {
                  const ok = await copyToClipboard('docker build -f Dockerfile.caddy -t culkibo-caddy:cloudflare .');
                  if (!ok) return;
                  setCopiedCaddyCmd(true);
                  window.setTimeout(() => setCopiedCaddyCmd(false), 1800);
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 text-[11px] font-mono shrink-0 cursor-pointer"
              >
                {copiedCaddyCmd ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{t('domains.copyCaddyBuild')}</span>
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-1">
            {/* Añadir / listar políticas wildcard */}
            <div className="space-y-2.5">
              <form onSubmit={handleAddWildcardPolicy} className="flex gap-2">
                <input
                  type="text"
                  value={newWildcardRoot}
                  onChange={(e) => setNewWildcardRoot(e.target.value)}
                  placeholder={t('domains.wildcardPlaceholder')}
                  className="flex-1 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
                <button
                  type="submit"
                  disabled={addingWildcard || !newWildcardRoot.trim().includes('.')}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50 shrink-0"
                >
                  {addingWildcard ? t('domains.adding') : t('domains.addWildcard')}
                </button>
              </form>

              {wildcardPolicies.length > 0 ? (
                <div className="space-y-1.5">
                  {wildcardPolicies.map((pol) => (
                    <div key={pol.rootDomain} className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs">
                      <div className="min-w-0">
                        <span className="font-mono font-semibold text-slate-900">*.{pol.rootDomain}</span>
                        {pol.includeApex && <span className="text-slate-500 ml-1.5 font-mono">+ {pol.rootDomain}</span>}
                      </div>
                      <button
                        type="button"
                        disabled={removingWildcard === pol.rootDomain}
                        onClick={() => void handleRemoveWildcardPolicy(pol.rootDomain)}
                        className="text-slate-400 hover:text-red-600 p-1 rounded cursor-pointer"
                        title={`Remove *.${pol.rootDomain}`}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-400">{t('domains.noWildcards')}</p>
              )}
            </div>

            {/* Correo ACME para avisos de Let's Encrypt */}
            <form onSubmit={handleSaveAcmeEmail} className="space-y-2">
              <label className="block text-xs font-medium text-slate-700">{t('domains.acmeEmailLabel')}</label>
              <div className="flex gap-2">
                <input
                  type="email"
                  value={acmeEmailInput}
                  onChange={(e) => setAcmeEmailInput(e.target.value)}
                  placeholder={t('domains.acmeEmailPlaceholder')}
                  className="flex-1 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs"
                />
                <button
                  type="submit"
                  disabled={savingAcme}
                  className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium cursor-pointer disabled:opacity-50 shrink-0"
                >
                  {savingAcme ? t('domains.saving') : t('domains.save')}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">{t('domains.acmeEmailHint')}</p>
            </form>
          </div>
        </div>
      )}

      {/* Sovereign EdgeTunnel (CGNAT · Zero Cloudflare Lock-in) */}
      {!projectId && (
        <section className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <Radio className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('domains.tunnelTitle')}</h2>
                <p className="text-xs text-slate-500 mt-0.5">{t('domains.tunnelDesc')}</p>
              </div>
            </div>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-[11px] font-mono text-slate-700 tabular-nums self-start sm:self-auto">
              <span className={`w-1.5 h-1.5 rounded-full ${(tunnelStatus?.connectedTunnels ?? 0) > 0 ? 'bg-emerald-500' : 'bg-slate-400'}`} />
              {t('domains.tunnelActiveLabel', {
                connected: tunnelStatus?.connectedTunnels ?? tunnelStatus?.connectedAgents ?? 0,
                active: tunnelStatus?.activeTunnels ?? 0,
              })}
            </span>
          </div>

          <form onSubmit={(e) => void handleCreateEdgeTunnel(e)} className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 items-end text-xs">
            <label className="sm:col-span-3 block">
              <span className="text-slate-600 font-medium block mb-1">{t('domains.tunnelName')}</span>
              <input
                type="text"
                value={tunnelName}
                onChange={(e) => setTunnelName(e.target.value)}
                placeholder="home-lab-api"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-900"
              />
            </label>
            <label className="sm:col-span-3 block">
              <span className="text-slate-600 font-medium block mb-1">{t('domains.tunnelHost')}</span>
              <input
                type="text"
                required
                value={tunnelHost}
                onChange={(e) => setTunnelHost(e.target.value)}
                placeholder="127.0.0.1"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="sm:col-span-2 block">
              <span className="text-slate-600 font-medium block mb-1">{t('domains.tunnelPort')}</span>
              <input
                type="number"
                min={1}
                max={65535}
                required
                value={tunnelPort}
                onChange={(e) => setTunnelPort(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
              />
            </label>
            <label className="sm:col-span-2 block">
              <span className="text-slate-600 font-medium block mb-1">{t('domains.tunnelHostname')}</span>
              <input
                type="text"
                value={tunnelHostname}
                onChange={(e) => setTunnelHostname(e.target.value)}
                placeholder="app.example.com"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={creatingTunnel}
                className="culkibo-press w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {creatingTunnel ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>{creatingTunnel ? t('domains.tunnelCreating') : t('domains.tunnelCreate')}</span>
              </button>
            </div>
          </form>

          {tunnelError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700">{tunnelError}</div>
          )}

          {createdTunnelSecret && (
            <div className="p-3.5 rounded-xl bg-slate-950 text-slate-100 border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-emerald-300">
                  <Terminal className="w-3.5 h-3.5" />
                  {t('domains.tunnelTokenOnce')}
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={async () => {
                      const ok = await copyToClipboard(buildTunnelAgentCmd(createdTunnelSecret));
                      if (!ok) return;
                      setCopiedTunnelCmd(true);
                      window.setTimeout(() => setCopiedTunnelCmd(false), 1800);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 text-[11px] font-medium cursor-pointer"
                  >
                    {copiedTunnelCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{t('domains.tunnelCopyCmd')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setCreatedTunnelSecret(null)}
                    className="p-1 text-slate-400 hover:text-white cursor-pointer"
                    aria-label="Close token banner"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
              <code className="block font-mono text-[11px] text-slate-200 break-all">
                {buildTunnelAgentCmd(createdTunnelSecret)}
              </code>
            </div>
          )}

          {tunnelStatus && Array.isArray(tunnelStatus.tunnels) && tunnelStatus.tunnels.filter((tun) => !tun.revoked).length > 0 ? (
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden text-xs">
              {tunnelStatus.tunnels
                .filter((tun) => !tun.revoked)
                .map((tun) => (
                  <div key={tun.id} className="px-3.5 py-2.5 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{tun.name}</span>
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                          tun.connected
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${tun.connected ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                          {tun.connected ? 'connected' : 'waiting agent'}
                        </span>
                        {tun.hostname && (
                          <span className="font-mono text-[11px] text-slate-600">{tun.hostname}</span>
                        )}
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 mt-0.5 tabular-nums">
                        {tun.id} → {tun.targetHost}:{tun.targetPort}
                        {tun.tokenPreview ? ` · ${tun.tokenPreview}` : ''}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={revokingTunnelId === tun.id}
                      onClick={() => void handleRevokeEdgeTunnel(tun.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-red-50 hover:border-red-200 text-slate-600 hover:text-red-700 font-medium cursor-pointer shrink-0 disabled:opacity-50"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>{t('domains.tunnelRevoke')}</span>
                    </button>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400">{t('domains.tunnelEmpty')}</p>
          )}
        </section>
      )}

      {/* Cycle-11: Multi-Region Edge Geo-Routing (CF-IPCountry) & Sticky A/B Experiments */}
      {!projectId && (
        <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <ArrowRightLeft className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('domains.expTitle')}</h2>
                  <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                    CF-IPCountry · Caddy v2.11 Native
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.expDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap shrink-0">
              <button
                type="button"
                disabled={expBusyId !== null}
                onClick={() => void handleCreateDemoExperiment('geo')}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
              >
                {expBusyId === 'create-geo' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>+ Geo-IP</span>
              </button>
              <button
                type="button"
                disabled={expBusyId !== null}
                onClick={() => void handleCreateDemoExperiment('ab')}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {expBusyId === 'create-ab' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>{expBusyId === 'create-ab' ? t('domains.expCreating') : t('domains.expCreateDemo')}</span>
              </button>
            </div>
          </div>

          {expError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{expError}</span>
            </div>
          )}

          {experiments.length === 0 ? (
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-500 text-center">
              {t('domains.expEmpty')}
            </div>
          ) : (
            <div className="space-y-3">
              {experiments.map((exp) => {
                const regions = Array.isArray(exp.regions) ? exp.regions : [];
                const variants = Array.isArray(exp.variants) ? exp.variants : [];
                const caddyJson = exp.compiledCaddy || exp.compiledRoute || exp.caddyRoute;
                const isPreviewOpen = expPreviewId === exp.id;
                return (
                  <div key={exp.id} className="p-4 rounded-xl bg-white border border-slate-200 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap min-w-0">
                        <span className="font-semibold text-slate-900">{exp.name || exp.id}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                          {exp.hostname}
                        </span>
                        <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                          exp.killed
                            ? 'bg-red-50 text-red-700 border-red-200'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        }`}>
                          {exp.killed ? t('domains.expKilledBadge') : t('domains.expActiveBadge')}
                        </span>
                        {exp.stickyMode && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 font-mono text-[10px] text-slate-600">
                            sticky: {exp.stickyMode === 'cookie' ? (exp.cookieName || 'ckb_ab') : (exp.headerField || 'X-AB-Group')}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                        {caddyJson && (
                          <button
                            type="button"
                            onClick={() => setExpPreviewId(isPreviewOpen ? null : exp.id)}
                            className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 font-mono text-[10px] text-slate-700 cursor-pointer"
                          >
                            {isPreviewOpen ? 'Hide JSON' : t('domains.expCaddyPreview')}
                          </button>
                        )}
                        {!exp.killed && (
                          <button
                            type="button"
                            disabled={expBusyId !== null}
                            onClick={() => void handleKillExperiment(exp.id)}
                            className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium text-[11px] cursor-pointer disabled:opacity-50"
                          >
                            {expBusyId === `kill-${exp.id}` ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldOff className="w-3 h-3" />}
                            <span>{expBusyId === `kill-${exp.id}` ? t('domains.expKilling') : t('domains.expKillSwitch')}</span>
                          </button>
                        )}
                      </div>
                    </div>

                    {/* ISO Country Geo-Routing Pills */}
                    {regions.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-[10px] text-slate-500 uppercase">{exp.headerName || 'CF-IPCountry'}:</span>
                        {regions.map((r, rIdx) => (
                          <span
                            key={rIdx}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[11px] text-slate-800"
                          >
                            <span className="font-semibold">{(Array.isArray(r.countries) ? r.countries : []).join(', ')}</span>
                            <span className="text-slate-400">→</span>
                            <span className="text-emerald-700">{r.label || r.upstream}</span>
                          </span>
                        ))}
                        {exp.defaultUpstream && (
                          <span className="px-2 py-1 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[10px] text-slate-500">
                            default → {exp.defaultUpstream}
                          </span>
                        )}
                      </div>
                    )}

                    {/* Sticky A/B Traffic Split Bar */}
                    {variants.length > 0 && (
                      <div className="space-y-1.5 tabular-nums">
                        <div className="flex items-center justify-between text-[11px] font-mono text-slate-600">
                          {variants.map((v, vIdx) => (
                            <span key={vIdx}>
                              {v.name}: <strong>{exp.killed ? (vIdx === 0 ? 100 : 0) : v.weight}%</strong> ({v.upstream})
                            </span>
                          ))}
                        </div>
                        <div className="h-2 rounded-full bg-slate-200 overflow-hidden flex">
                          {variants.map((v, vIdx) => {
                            const w = exp.killed ? (vIdx === 0 ? 100 : 0) : Math.max(0, Math.min(100, Number(v.weight) || 0));
                            return (
                              <div
                                key={vIdx}
                                className={vIdx === 0 ? 'bg-slate-900' : 'bg-emerald-500'}
                                style={{ width: `${w}%` }}
                              />
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {isPreviewOpen && caddyJson && (
                      <pre className="p-3 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[10px] overflow-x-auto max-h-52">
                        {JSON.stringify(caddyJson, null, 2)}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      )}

      {/* Cycle-15: Edge API Rate-Limit & AI Wallet-Drain Shield (RPM + TPM) */}
      {!projectId && (
        <section className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4 text-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <Zap className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('domains.rlTitle')}</h2>
                  <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                    IETF RateLimit · 429 Retry-After
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.rlDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap shrink-0">
              <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[10px] font-mono">
                {(['free', 'pro', 'enterprise'] as const).map((tier) => (
                  <button
                    key={tier}
                    type="button"
                    onClick={() => setRlSelectedTier(tier)}
                    className={`px-2 py-1 rounded-md uppercase cursor-pointer ${
                      rlSelectedTier === tier ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {tier}
                  </button>
                ))}
              </div>
              <button
                type="button"
                disabled={rlBusy}
                onClick={() => void handleSimulateAiBurst()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {rlBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{rlBusy ? t('domains.rlSimulating') : t('domains.rlSimBtn')}</span>
              </button>
            </div>
          </div>

          {rlPolicies.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 font-mono text-[11px] tabular-nums">
              {rlPolicies.slice(0, 3).map((pol) => (
                <div
                  key={pol.id}
                  className={`p-3 rounded-xl border space-y-1 ${
                    rlSelectedTier === pol.planTier ? 'bg-white border-slate-900' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900 uppercase">{pol.planTier}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-[10px]">
                      {pol.rpmLimit} RPM
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500">
                    TPM cap: {Number(pol.tpmLimit).toLocaleString()} tok/min · burst {pol.burstMultiplier ?? 1.5}×
                  </div>
                </div>
              ))}
            </div>
          )}

          {rlError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{rlError}</div>
          )}

          {rlSimResult && (
            <div className="space-y-2.5 tabular-nums font-mono text-[11px]">
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-700 text-[10px] font-semibold">
                    HTTP 429 · Retry-After: {rlSimResult.sample429Headers?.['Retry-After'] || '60'}s
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                    allowed: {rlSimResult.allowedCount} · throttled: {rlSimResult.throttledCount}/{rlSimResult.totalRequests}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                    Wallet Saved: ${Number(rlSimResult.estimatedWalletSavedUsd ?? 0).toFixed(2)}
                  </span>
                  {rlSimResult.throttleReason && (
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                      {rlSimResult.throttleReason}
                    </span>
                  )}
                </div>
                {rlSimResult.sample429Headers && (
                  <div className="text-[10px] space-y-0.5">
                    {rlSimResult.sample429Headers.RateLimit && <div>RateLimit: {rlSimResult.sample429Headers.RateLimit}</div>}
                    {rlSimResult.sample429Headers['RateLimit-Policy'] && <div>RateLimit-Policy: {rlSimResult.sample429Headers['RateLimit-Policy']}</div>}
                  </div>
                )}
              </div>
              {rlSimResult.caddyConfig && (
                <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-44 border border-slate-800">
                  {JSON.stringify(rlSimResult.caddyConfig, null, 2)}
                </pre>
              )}
            </div>
          )}
        </section>
      )}

      {/* Cycle-16: Edge WS/SSE Flood & 101 Hop-by-Hop Guard (CVE-2026-55458) */}
      {!projectId && (
        <section className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4 text-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('domains.streamTitle')}</h2>
                  <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                    RFC 7230 §6.1 · stream_close_delay
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.streamDesc')}</p>
              </div>
            </div>
            <button
              type="button"
              disabled={streamGuardBusy}
              onClick={() => void handleSimulateStreamGuard()}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
            >
              {streamGuardBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{streamGuardBusy ? t('domains.streamSimulating') : t('domains.streamSimBtn')}</span>
            </button>
          </div>

          {streamGuardError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{streamGuardError}</div>
          )}

          {streamGuardResult && (() => {
            const stripped = Array.isArray(streamGuardResult.strippedHeaders) ? streamGuardResult.strippedHeaders : [];
            const preserved = Array.isArray(streamGuardResult.preservedHeaders) ? streamGuardResult.preservedHeaders : [];
            return (
              <div className="space-y-2.5 tabular-nums font-mono text-[11px]">
                <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-700 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      {streamGuardResult.code || 'PER_IP_FLOOD_CAPPED'} · HTTP {streamGuardResult.httpStatus ?? 429} / WS {streamGuardResult.wsCloseCode ?? 1013}
                    </span>
                    {streamGuardResult.retryAfterSec != null && (
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                        Retry-After: {streamGuardResult.retryAfterSec}s
                      </span>
                    )}
                    {stripped.map((h) => (
                      <span key={h} className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-semibold">
                        stripped: {h}
                      </span>
                    ))}
                    {preserved.map((h) => (
                      <span key={h} className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                        kept: {h}
                      </span>
                    ))}
                  </div>
                </div>
                {streamGuardResult.caddyStreamBlock && (
                  <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-44 border border-slate-800">
                    {streamGuardResult.caddyStreamBlock}
                  </pre>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {/* Cycle-16: Zero-Downtime DNS Cutover & Cloudflare Proxy Verifier (coolify#6271) */}
      {!projectId && (
        <section className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4 text-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <ArrowRightLeft className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('domains.dnsCutTitle')}</h2>
                  <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                    coolify#6271 · 5-Phase TTL Plan
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.dnsCutDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap shrink-0">
              <input
                type="text"
                value={dnsCutDomain}
                onChange={(e) => setDnsCutDomain(e.target.value)}
                aria-label="Domain for DNS cutover verifier"
                placeholder="app.acme-demo.dev"
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 w-40"
              />
              <button
                type="button"
                disabled={dnsCutBusy !== null}
                onClick={() => void handleTestCloudflareCutover()}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-slate-100 text-amber-800 font-medium cursor-pointer disabled:opacity-50"
              >
                {dnsCutBusy === 'cf' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Cloud className="w-3.5 h-3.5" />}
                <span>{t('domains.dnsCutTestCf')}</span>
              </button>
              <button
                type="button"
                disabled={dnsCutBusy !== null}
                onClick={() => void handleBuildDnsCutoverPlan()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {dnsCutBusy === 'plan' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                <span>{dnsCutBusy === 'plan' ? t('domains.dnsCutWorking') : t('domains.dnsCutPlanBtn')}</span>
              </button>
            </div>
          </div>

          {dnsCutError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{dnsCutError}</div>
          )}

          {dnsPreflightResult && (
            <div className={`p-3 rounded-xl border font-mono text-[11px] space-y-1.5 ${
              dnsPreflightResult.ready
                ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                : 'bg-amber-50 border-amber-200 text-amber-800'
            }`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                  {dnsPreflightResult.code}
                </span>
                {dnsPreflightResult.isProxied && (
                  <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-semibold">
                    Cloudflare Anycast Proxy (104.21.10.5) · Use DNS-01 or Grey-Cloud
                  </span>
                )}
              </div>
              {dnsPreflightResult.message && <div>{dnsPreflightResult.message}</div>}
            </div>
          )}

          {dnsPlanResult && (() => {
            const phases = Array.isArray(dnsPlanResult.phases) ? dnsPlanResult.phases : [];
            return (
              <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 space-y-2 tabular-nums font-mono text-[11px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                    5-PHASE TTL PLAN READY
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                    minPreCutoverWaitSec: {dnsPlanResult.minPreCutoverWaitSec ?? 3600}s
                  </span>
                </div>
                {phases.length > 0 && (
                  <ol className="list-decimal list-inside space-y-0.5 text-[11px]">
                    {phases.map((ph, idx) => (
                      <li key={idx}>
                        {typeof ph === 'string' ? ph : `[${ph.name || `Phase ${ph.phase ?? idx + 1}`}] ${ph.title || ph.action || 'Execute'}`}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {/* Cycle-17: Surrogate-Key Edge Cache & Stampede Coalescer (souin#884 / #850) */}
      {!projectId && (
        <section className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4 text-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                <Zap className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('domains.cacheTitle')}</h2>
                  <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                    0 Global SURROGATE_ OOM
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('domains.cacheDesc')}</p>
              </div>
            </div>
            <button
              type="button"
              disabled={cacheBusy}
              onClick={() => void handleTestEdgeCache()}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
            >
              {cacheBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{cacheBusy ? t('domains.cacheWorking') : t('domains.cacheTestBtn')}</span>
            </button>
          </div>

          {cacheError && (
            <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{cacheError}</div>
          )}

          {(cacheCoalesceResult || cachePurgeResult) && (() => {
            const plans = Array.isArray(cachePurgeResult?.providerPlans) ? cachePurgeResult.providerPlans : [];
            const tags = Array.isArray(cachePurgeResult?.tags) ? cachePurgeResult.tags : [];
            return (
              <div className="space-y-2.5 tabular-nums font-mono text-[11px]">
                <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      {cacheCoalesceResult?.reason || 'PRIVATE_OR_NO_STORE_BYPASS'}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      coalesced: {String(Boolean(cacheCoalesceResult?.coalesced))} (0 cross-tenant leak)
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      globalSurrogateBucketUsed: {String(Boolean(cachePurgeResult?.globalSurrogateBucketUsed))}
                    </span>
                    {tags.length > 0 && (
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                        tags: {tags.join(', ')} (dryRun: {String(cachePurgeResult?.dryRun !== false)})
                      </span>
                    )}
                  </div>
                  {plans.length > 0 && (
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                      {plans.map((pl, idx) => {
                        const obj = typeof pl === 'string' ? { provider: pl } : pl;
                        return (
                          <div key={idx} className="p-2 rounded-lg bg-white border border-slate-200 text-slate-900 text-[10px] space-y-0.5">
                            <div className="font-semibold uppercase">{obj.provider || `edge-${idx + 1}`}</div>
                            <div className="text-slate-600 truncate">
                              {obj.method || 'PURGE'} · {obj.header || 'Surrogate-Key'}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
        </section>
      )}

      {/* Certificados PEM propios en disco (Origin CA / corporativos): solo se muestra si existen */}
      {onDiskCerts.length > 0 && !projectId && (
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3.5">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-slate-900">Certificados PEM propios / Origin CA</h2>
            </div>
            <span className="text-xs text-slate-500">Cargados en Caddy como certificados TLS personalizados</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {onDiskCerts.map((cert) => (
              <div key={cert.id} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-slate-900 block font-mono truncate">{cert.domain}</span>
                    <span className="text-[11px] text-slate-500">Emisor: {cert.issuer ?? 'X.509 propio'}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-white text-slate-600 border border-slate-200 tabular-nums">
                      {cert.daysRemaining !== null ? `${cert.daysRemaining} d` : 'PEM'}
                    </span>
                    <button
                      type="button"
                      aria-label={`Eliminar certificado ${cert.domain}`}
                      onClick={() => void handleDeleteCert(cert.id, cert.domain)}
                      className="p-1 text-slate-400 hover:text-red-600 rounded cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                {cert.sans?.length > 0 && (
                  <div className="text-[11px] text-slate-500 truncate">
                    SANs: <span className="font-mono text-slate-700">{cert.sans.join(', ')}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Asistente 3 pasos */}
      <DomainWizardModal
        isOpen={showWizard}
        onClose={() => {
          setShowWizard(false);
          onClearWizardPreset?.();
        }}
        onComplete={() => {
          void loadData(true);
          onDomainAddedToProject?.('');
        }}
        onNotify={onNotify}
        projectId={projectId}
        initialKind={wizardKind}
        preset={wizardPreset}
        onOpenOriginCa={(suggested) => {
          setUploadDomain(suggested || '');
          setUploadError(null);
          setShowUploadCertModal(true);
        }}
      />

      {/* Modal: Diagnóstico 4 capas */}
      <Modal
        open={showDiagnoseModal}
        onClose={() => setShowDiagnoseModal(false)}
        title="Diagnóstico completo del dominio"
        subtitle={diagnoseReport ? diagnoseReport.hostname : 'Comprobación en directo de DNS, Caddy, TLS y destino'}
        maxWidthClass="max-w-lg"
      >
        <div className="p-5 space-y-4">
          {diagnoseLoading ? (
            <div className="flex flex-col items-center py-8 gap-2 text-slate-500 text-xs">
              <Loader2 className="w-5 h-5 animate-spin text-slate-700" />
              <span>Comprobando DNS, ruta en Caddy, certificado TLS y puerto destino…</span>
            </div>
          ) : diagnoseError ? (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800">{diagnoseError}</div>
          ) : diagnoseReport ? (
            <div className="space-y-3">
              {diagnoseReport.checks.map((check) => (
                <div
                  key={check.id}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex items-start justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-slate-900">{check.title}</div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">{check.detail}</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border shrink-0 ${
                    check.status === 'ok'
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : check.status === 'warn'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                  }`}>
                    {check.status === 'ok' ? 'Correcto' : check.status === 'warn' ? 'Aviso' : 'Fallo'}
                  </span>
                </div>
              ))}
            </div>
          ) : null}

          <div className="flex items-center justify-between pt-2 border-t border-slate-100">
            {diagnosingId && (
              <button
                type="button"
                disabled={diagnoseLoading}
                onClick={() => void handleDiagnose(diagnosingId)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${diagnoseLoading ? 'animate-spin' : ''}`} />
                <span>Reprobar ahora</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => setShowDiagnoseModal(false)}
              className="ml-auto px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
            >
              Cerrar
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Editar dominio */}
      <Modal
        open={Boolean(editingDomain)}
        onClose={() => setEditingDomain(null)}
        title={editingDomain ? `Configurar ${editingDomain.hostname}` : 'Configurar dominio'}
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleSaveEditDomain} className="p-5 space-y-4 text-xs max-h-[78vh] overflow-y-auto">
          {!projectId && projects.length > 0 && editingDomain?.targetPod !== 'service' && (
            <div>
              <label className="block font-medium text-slate-700 mb-1">Proyecto asignado</label>
              <select
                value={editProjectId}
                onChange={(e) => setEditProjectId(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
              >
                <option value="">Sin proyecto (puerto directo)</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-700 mb-1">Entorno destino</label>
              <select
                value={editPod}
                onChange={(e) => setEditPod(e.target.value as 'forge' | 'citadel' | 'service')}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
              >
                <option value="citadel">Producción</option>
                <option value="forge">Desarrollo</option>
                <option value="service">Servicio catálogo</option>
              </select>
            </div>
            <div>
              <label className="block font-medium text-slate-700 mb-1">Puerto</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={editPort}
                onChange={(e) => setEditPort(Number(e.target.value))}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono tabular-nums"
              />
            </div>
          </div>

          {!editingDomain?.isWildcard && !editingDomain?.hostname?.startsWith('www.') && (
            <div>
              <label className="block font-medium text-slate-700 mb-1">Redirección canónica 301 (www)</label>
              <select
                value={editRedirect}
                onChange={(e) => setEditRedirect(e.target.value as 'none' | 'www_to_apex' | 'apex_to_www')}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
              >
                <option value="none">Ninguna</option>
                <option value="www_to_apex">Redirigir www → dominio raíz (301)</option>
                <option value="apex_to_www">Redirigir dominio raíz → www (301)</option>
              </select>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-700 mb-1">Política de iframes</label>
              <select
                value={editFramePolicy}
                onChange={(e) => setEditFramePolicy(e.target.value as 'SAMEORIGIN' | 'DENY' | 'ALLOW')}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
              >
                <option value="SAMEORIGIN">SAMEORIGIN (recomendado)</option>
                <option value="DENY">DENY (bloquear todos)</option>
                <option value="ALLOW">ALLOW (permitir embebidos)</option>
              </select>
            </div>
            <div>
              <label className="block font-medium text-slate-700 mb-1">Límite de subida (MB)</label>
              <input
                type="number"
                min={1}
                max={10240}
                value={editMaxBodyMb}
                onChange={(e) => setEditMaxBodyMb(e.target.value)}
                placeholder="Sin límite (ej. 50)"
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono tabular-nums"
              />
            </div>
          </div>

          {/* Protección Basic Auth (bcrypt nativo en Caddy) */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 font-medium text-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editBasicAuthEnabled}
                  onChange={(e) => setEditBasicAuthEnabled(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span>Proteger con contraseña (Basic Auth)</span>
              </label>
              <HelpTip title="Basic Auth en Caddy" align="right">
                <p>Pide usuario y contraseña antes de dejar entrar al sitio (ideal para entornos de staging o paneles privados).</p>
                <p>La contraseña se cifra con bcrypt y nunca se guarda en texto claro.</p>
              </HelpTip>
            </div>
            {editBasicAuthEnabled && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                <input
                  type="text"
                  value={editBasicAuthUser}
                  onChange={(e) => setEditBasicAuthUser(e.target.value)}
                  placeholder="Usuario (ej. admin)"
                  className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg font-mono"
                />
                <input
                  type="password"
                  value={editBasicAuthPass}
                  onChange={(e) => setEditBasicAuthPass(e.target.value)}
                  placeholder={editingDomain?.basicAuth?.enabled ? 'Nueva contraseña (opcional)' : 'Contraseña'}
                  required={!editingDomain?.basicAuth?.enabled}
                  className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
            )}
          </div>

          <div>
            <label className="block font-medium text-slate-700 mb-1">
              Lista blanca de IPs / CIDR (opcional)
            </label>
            <input
              type="text"
              value={editIpAllowlist}
              onChange={(e) => setEditIpAllowlist(e.target.value)}
              placeholder="Ej. 203.0.113.5, 10.0.0.0/8 (vacío = abierto a todo el mundo)"
              className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
            />
          </div>

          <div>
            <label className="block font-medium text-slate-700 mb-1">
              Cabeceras HTTP personalizadas (una por línea <code className="font-mono">Nombre: valor</code>)
            </label>
            <textarea
              rows={2}
              value={editCustomHeaders}
              onChange={(e) => setEditCustomHeaders(e.target.value)}
              placeholder="Cache-Control: public, max-age=3600"
              className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono text-[11px]"
            />
          </div>

          <label className="flex items-center gap-2 text-slate-700 cursor-pointer pt-1">
            <input
              type="checkbox"
              checked={editSecHeaders}
              onChange={(e) => setEditSecHeaders(e.target.checked)}
              className="rounded border-slate-300 accent-slate-900"
            />
            <span>Añadir cabeceras de seguridad (HSTS, nosniff, Referrer-Policy)</span>
          </label>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
            <button type="button" onClick={() => setEditingDomain(null)} className="px-3.5 py-2 rounded-lg text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={savingEdit}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {savingEdit ? 'Aplicando en Caddy…' : 'Guardar cambios'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Subir certificado PEM / Cloudflare Origin CA */}
      <Modal
        open={showUploadCertModal}
        onClose={() => setShowUploadCertModal(false)}
        title="Subir certificado SSL (PEM / Origin CA)"
        subtitle="Validación criptográfica X.509 y carga automática en Caddy"
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleUploadCert} className="p-5 space-y-4 text-xs">
          {uploadError && (
            <div role="alert" className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800">
              {uploadError}
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-700 mb-1">Dominio / Comodín</label>
              <input
                type="text"
                value={uploadDomain}
                onChange={(e) => setUploadDomain(e.target.value)}
                placeholder="*.miempresa.com"
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
              />
            </div>
            <div>
              <label className="block font-medium text-slate-700 mb-1">Origen</label>
              <select
                value={uploadProvider}
                onChange={(e) => setUploadProvider(e.target.value as 'cloudflare_origin_ca' | 'custom_pem')}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
              >
                <option value="cloudflare_origin_ca">Cloudflare Origin CA (15 años)</option>
                <option value="custom_pem">Certificado PEM corporativo / propio</option>
              </select>
            </div>
          </div>

          {uploadProvider === 'cloudflare_origin_ca' && (
            <ol className="list-decimal list-inside p-3 rounded-xl bg-slate-50 border border-slate-200 text-[11px] text-slate-600 space-y-1">
              <li>En Cloudflare abre tu dominio → <strong>SSL/TLS → Origin Server → Create Certificate</strong>.</li>
              <li>Deja los hostnames (<code className="font-mono">*.tudominio.com, tudominio.com</code>) y 15 años, y pulsa Create.</li>
              <li>Pega o sube aquí los dos bloques PEM y activa modo <strong>Full (Strict)</strong> en Cloudflare.</li>
            </ol>
          )}

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block font-medium text-slate-700">Certificado (PEM)</label>
              <label className="text-[11px] text-slate-600 hover:text-slate-900 underline cursor-pointer">
                Cargar archivo .pem/.crt
                <input
                  type="file"
                  accept=".pem,.crt,.cer,.txt"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    f.text().then((txt) => setUploadCertPem(txt));
                    e.target.value = '';
                  }}
                />
              </label>
            </div>
            <textarea
              required
              rows={4}
              value={uploadCertPem}
              onChange={(e) => setUploadCertPem(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg font-mono text-[11px] focus:bg-white"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block font-medium text-slate-700">Clave privada (PEM)</label>
              <label className="text-[11px] text-slate-600 hover:text-slate-900 underline cursor-pointer">
                Cargar archivo .key/.pem
                <input
                  type="file"
                  accept=".key,.pem,.txt"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    f.text().then((txt) => setUploadKeyPem(txt));
                    e.target.value = '';
                  }}
                />
              </label>
            </div>
            <textarea
              required
              rows={4}
              value={uploadKeyPem}
              onChange={(e) => setUploadKeyPem(e.target.value)}
              placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
              className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg font-mono text-[11px] focus:bg-white"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setShowUploadCertModal(false)} className="px-3.5 py-2 rounded-lg text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={uploadingCert || !uploadCertPem.trim() || !uploadKeyPem.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {uploadingCert ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{uploadingCert ? 'Verificando par…' : 'Verificar y activar'}</span>
            </button>
          </div>
        </form>
      </Modal>

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
    </div>
  );
};
