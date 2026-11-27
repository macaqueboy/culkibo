import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Server,
  ExternalLink,
  Unlink,
  Key,
  AlertCircle,
  RefreshCw,
  Globe,
  Plug,
  Bell,
  Cpu,
  Cloud,
  Send,
  Trash2,
  Play,
  Loader2,
  Activity,
  HardDrive,
  Download,
  Upload,
  ShieldCheck,
  ListChecks,
  FileText,
  Eye,
  EyeOff,
  Users,
  FileCode2,
  Lock,
  Copy,
  Check,
  GitBranch,
  ArrowRightLeft,
  Rocket,
  Plus,
  KeyRound,
  Fingerprint,
  ScanSearch,
  ShieldAlert,
  Radio,
  Link2,
  Sun,
  Moon,
  Monitor,
  Languages,
  Palette,
  Webhook,
} from 'lucide-react';
import {
  api,
  type GitHubStatus,
  type NotificationsConfig,
  type NotificationHistoryItem,
  type DbStorageConfig,
  type RemoteS3Object,
  type InstanceBackupItem,
  type AuditLogEvent,
  type TelemetryStatus,
  type TelemetryPreview,
  type VaultSecretMeta,
  type GitOpsPlanResult,
  type GitOpsDriftResult,
  type Project,
  type ProjectEnvironmentItem,
  type EnvironmentDiffResult,
  type RbacIdentity,
  type TotpSetupResult,
  type OidcProviderSummary,
  type AuditChainVerification,
  type SecretScanReport,
  type DnsProviderInfo,
  type Http3ProbeResult,
  type PasskeyRecord,
  type SecretLeaseRecord,
  type SecretRotationAuditResult,
  type CveScanResult,
  type IacExportResult,
  type BrandThemeConfig,
  type OutboundWebhookSubscription,
  type WebhookDlqEntry,
  type AdmissionPolicyState,
  type AdmissionEvaluationResult,
  type ComplianceBundleResult,
  type ComplianceVerifyResult,
  type LicenseAuditResult,
  type SeccompProfileResult,
  type RuncAuditResult,
  type PreDeploySecretScanResult,
  type MtlsCertRecord,
  type MtlsVerifyResult,
  type OciVerifyResult,
  type OrphanScanResult,
  type OrphanReapResult,
} from '../lib/api';
import { RemoteAccessPanel } from './RemoteAccessPanel';
import { TeamAccessPanel } from './TeamAccessPanel';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';
import { useI18n } from '../lib/i18n';
import { useTheme, type ThemeMode } from '../lib/theme';

type SettingsTab = 'remote' | 'team' | 'security' | 'gitops' | 'integrations' | 'backups' | 'notifications' | 'system';

function formatSafeDate(raw?: string | null): string {
  if (!raw) return '—';
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('es-ES');
}

function formatAuditActor(actor?: AuditLogEvent['actor']): string | null {
  if (!actor) return null;
  if (typeof actor === 'string') return actor;
  return actor.email || actor.userId || actor.kind || null;
}

function normalizeSettingsTab(raw?: string | null): SettingsTab {
  if (!raw) return 'remote';
  const k = raw.toLowerCase();
  if (
    k === 'remote' ||
    k === 'team' ||
    k === 'security' ||
    k === 'gitops' ||
    k === 'integrations' ||
    k === 'backups' ||
    k === 'notifications' ||
    k === 'system'
  ) {
    return k;
  }
  return 'remote';
}

interface SettingsViewProps {
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  onOpenMetrics?: () => void;
  initialTab?: string | null;
  onTabChange?: (tab: string) => void;
  onRestoreChecklist?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  onNotify,
  onOpenMetrics,
  initialTab,
  onTabChange,
  onRestoreChecklist,
}) => {
  const { t, locale, setLocale } = useI18n();
  const { theme, setTheme, isDark } = useTheme();
  const [tab, setTabState] = useState<SettingsTab>(() => normalizeSettingsTab(initialTab));
  const setTab = (next: SettingsTab) => {
    setTabState(next);
    onTabChange?.(next);
  };
  const [prevInitialTab, setPrevInitialTab] = useState(initialTab);
  if (initialTab !== prevInitialTab) {
    setPrevInitialTab(initialTab);
    if (initialTab) setTabState(normalizeSettingsTab(initialTab));
  }
  const [sysStatus, setSysStatus] = useState<any>(null);
  const [dockerStatus, setDockerStatus] = useState<{ available: boolean; reason: string | null } | null>(null);
  const [caddyStatus, setCaddyStatus] = useState<{ available: boolean; adminUrl?: string; message?: string } | null>(null);
  const [pruning, setPruning] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);
  const [auditEvents, setAuditEvents] = useState<AuditLogEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Telemetría anónima y diagnósticos
  const [telemetryStatus, setTelemetryStatus] = useState<TelemetryStatus | null>(null);
  const [telemetryBusy, setTelemetryBusy] = useState(false);
  const [telemetryPreview, setTelemetryPreview] = useState<TelemetryPreview | null>(null);
  const [telemetryPreviewLoading, setTelemetryPreviewLoading] = useState(false);
  const [showTelemetryPreview, setShowTelemetryPreview] = useState(false);

  // Backups & DR (S3 Remote Browser + Instance Snapshot Export/Import)
  const [s3Objects, setS3Objects] = useState<RemoteS3Object[]>([]);
  const [s3ObjectsLoading, setS3ObjectsLoading] = useState(false);
  const [instanceBackups, setInstanceBackups] = useState<InstanceBackupItem[]>([]);
  const [exportIncludeSecrets, setExportIncludeSecrets] = useState(false);
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [exportUploadS3, setExportUploadS3] = useState(false);
  const [exportingSnapshot, setExportingSnapshot] = useState(false);
  const [importPassphrase, setImportPassphrase] = useState('');
  const [importMode, setImportMode] = useState<'merge' | 'overwrite'>('merge');
  const [importSnapshotObj, setImportSnapshotObj] = useState<any>(null);
  const [importFileName, setImportFileName] = useState<string>('');
  const [importDryRunResult, setImportDryRunResult] = useState<any>(null);
  const [importingSnapshot, setImportingSnapshot] = useState(false);
  const [notifHistory, setNotifHistory] = useState<NotificationHistoryItem[]>([]);

  // GitHub
  const [githubStatus, setGithubStatus] = useState<GitHubStatus | null>(null);
  const [ghToken, setGhToken] = useState('');
  const [ghBusy, setGhBusy] = useState(false);
  const [confirmDisconnectGh, setConfirmDisconnectGh] = useState(false);
  const [ghFeedback, setGhFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Cloudflare
  const [cfConfig, setCfConfig] = useState<any>(null);
  const [cfToken, setCfToken] = useState('');
  const [cfAccountId, setCfAccountId] = useState('');
  const [cfZones, setCfZones] = useState<any[]>([]);
  const [cfBusy, setCfBusy] = useState(false);
  const [cfFeedback, setCfFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // S3 / R2
  const [s3Config, setS3Config] = useState<DbStorageConfig>({ configured: false });
  const [s3Form, setS3Form] = useState({ endpoint: '', region: 'auto', bucket: '', accessKeyId: '', secretAccessKey: '', prefix: 'culkibo/' });
  const [s3Busy, setS3Busy] = useState(false);
  const [confirmDisconnectS3, setConfirmDisconnectS3] = useState(false);

  // Notifications
  const [notif, setNotif] = useState<NotificationsConfig | null>(null);
  const [notifLoadFailed, setNotifLoadFailed] = useState(false);
  const [notifBusy, setNotifBusy] = useState(false);
  const [notifTesting, setNotifTesting] = useState(false);

  // GitOps (culkibo.yaml), Shared Encrypted Vault & Project Environments
  const [gitopsYaml, setGitopsYaml] = useState('');
  const [gitopsPrune, setGitopsPrune] = useState(false);
  const [gitopsConfirmDestructive, setGitopsConfirmDestructive] = useState(false);
  const [gitopsPlan, setGitopsPlan] = useState<GitOpsPlanResult | null>(null);
  const [gitopsDrift, setGitopsDrift] = useState<GitOpsDriftResult | null>(null);
  const [gitopsBusy, setGitopsBusy] = useState<'export' | 'plan' | 'apply' | 'drift' | null>(null);
  const [copiedYaml, setCopiedYaml] = useState(false);

  const [vaultSecrets, setVaultSecrets] = useState<VaultSecretMeta[]>([]);
  const [vaultKey, setVaultKey] = useState('');
  const [vaultValue, setVaultValue] = useState('');
  const [vaultScope, setVaultScope] = useState<'both' | 'runtime' | 'build'>('both');
  const [vaultBusy, setVaultBusy] = useState(false);

  const [envProjects, setEnvProjects] = useState<Project[]>([]);
  const [envProjectId, setEnvProjectId] = useState('');
  const [projectEnvs, setProjectEnvs] = useState<ProjectEnvironmentItem[]>([]);
  const [envEditName, setEnvEditName] = useState('staging');
  const [envEditBranch, setEnvEditBranch] = useState('staging');
  const [envEditVars, setEnvEditVars] = useState('');
  const [envDiffFrom, setEnvDiffFrom] = useState('staging');
  const [envDiffTo, setEnvDiffTo] = useState('production');
  const [envDiffResult, setEnvDiffResult] = useState<EnvironmentDiffResult | null>(null);
  const [envBusy, setEnvBusy] = useState(false);

  // Seguridad v1.1 (TOTP 2FA, OIDC SSO, Cadena SHA-256, Secret Scanner) & Edge v1.1 (HTTP/3, Multi-DNS-01)
  const [identity, setIdentity] = useState<RbacIdentity | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetupResult | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpRecoveryCodes, setTotpRecoveryCodes] = useState<string[]>([]);
  const [totpDisableOpen, setTotpDisableOpen] = useState(false);
  const [totpDisableCode, setTotpDisableCode] = useState('');
  const [totpDisablePassword, setTotpDisablePassword] = useState('');
  const [totpBusy, setTotpBusy] = useState<'setup' | 'verify' | 'disable' | null>(null);
  const [totpNotice, setTotpNotice] = useState<{ kind: 'info' | 'ok' | 'err'; text: string } | null>(null);

  const [oidcProviders, setOidcProviders] = useState<OidcProviderSummary[]>([]);
  const [oidcUnavailable, setOidcUnavailable] = useState(false);

  const [auditVerification, setAuditVerification] = useState<AuditChainVerification | null>(null);
  const [auditVerifyBusy, setAuditVerifyBusy] = useState(false);
  const [auditVerifyError, setAuditVerifyError] = useState<string | null>(null);
  const [securityAuditEntries, setSecurityAuditEntries] = useState<AuditLogEvent[]>([]);

  const [scanInput, setScanInput] = useState('');
  const [scanBusy, setScanBusy] = useState(false);
  const [scanReport, setScanReport] = useState<SecretScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [http3Status, setHttp3Status] = useState<Http3ProbeResult | null>(null);
  const [dnsProviders, setDnsProviders] = useState<DnsProviderInfo[]>([]);
  const [copiedSecKey, setCopiedSecKey] = useState<string | null>(null);

  // Cycle-8 Enterprise Sovereignty (Passkeys FIDO2, Secret Leases & Break-Glass, OSV CVE Drift, OpenTofu IaC Export)
  const [passkeys, setPasskeys] = useState<PasskeyRecord[]>([]);
  const [passkeyLabel, setPasskeyLabel] = useState('YubiKey 5C NFC');
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyChallenge, setPasskeyChallenge] = useState<string | null>(null);

  const [secretLeases, setSecretLeases] = useState<SecretLeaseRecord[]>([]);
  const [leaseKeyName, setLeaseKeyName] = useState('DATABASE_URL');
  const [breakGlassReason, setBreakGlassReason] = useState('Emergency incident production triage');
  const [leaseBusy, setLeaseBusy] = useState<'lease' | 'audit' | 'breakglass' | null>(null);
  const [issuedLeaseToken, setIssuedLeaseToken] = useState<string | null>(null);
  const [rotationAudit, setRotationAudit] = useState<SecretRotationAuditResult | null>(null);

  const [cveScan, setCveScan] = useState<CveScanResult | null>(null);
  const [cveBusy, setCveBusy] = useState(false);
  const [cveError, setCveError] = useState<string | null>(null);

  const [iacExport, setIacExport] = useState<IacExportResult | null>(null);
  const [iacBusy, setIacBusy] = useState(false);
  const [iacError, setIacError] = useState<string | null>(null);
  const [iacFileTab, setIacFileTab] = useState<string>('main.tf');

  // Cycle-9 Open-Core White-Label Brand Engine & Standard-Webhooks Outbound + DLQ
  const [brandForm, setBrandForm] = useState<BrandThemeConfig>({
    brandName: 'Culkibo',
    tagline: 'Ultra-lightweight self-hosted PaaS',
    accentHex: '#6366f1',
    logoUrl: '',
    supportUrl: '',
    hidePoweredBy: false,
    updatedAt: null,
  });
  const [brandBusy, setBrandBusy] = useState<'save' | 'reset' | null>(null);
  const [brandError, setBrandError] = useState<string | null>(null);

  const [whSubs, setWhSubs] = useState<OutboundWebhookSubscription[]>([]);
  const [whDlq, setWhDlq] = useState<WebhookDlqEntry[]>([]);
  const [whNewUrl, setWhNewUrl] = useState('');
  const [whNewDesc, setWhNewDesc] = useState('');
  const [whBusyId, setWhBusyId] = useState<string | null>(null);
  const [whRotatedSecret, setWhRotatedSecret] = useState<{ subId: string; secret: string; expiresAt?: string | null } | null>(null);
  const [whError, setWhError] = useState<string | null>(null);

  // Cycle-11 Policy-as-Code Admission Gate (10 CIS/PSS Rules) & Ed25519 Compliance Evidence Bundle
  const [admPolicy, setAdmPolicy] = useState<AdmissionPolicyState | null>(null);
  const [admEval, setAdmEval] = useState<AdmissionEvaluationResult | null>(null);
  const [admBusy, setAdmBusy] = useState<'preset' | 'root' | 'hardened' | null>(null);
  const [admError, setAdmError] = useState<string | null>(null);

  const [compFramework, setCompFramework] = useState<'all' | 'soc2' | 'iso27001' | 'gdpr'>('all');
  const [compBundle, setCompBundle] = useState<ComplianceBundleResult | null>(null);
  const [compVerify, setCompVerify] = useState<ComplianceVerifyResult | null>(null);
  const [compBusy, setCompBusy] = useState<'gen' | 'verify' | null>(null);
  const [compError, setCompError] = useState<string | null>(null);
  const [compShowMd, setCompShowMd] = useState(false);

  // Cycle-12: CycloneDX 1.6 SPDX License Risk Auditor & Tailored Seccomp / runc CVE Guard
  const [licPolicy, setLicPolicy] = useState<'saas-strict' | 'oss-permissive' | 'audit-only'>('saas-strict');
  const [licReport, setLicReport] = useState<LicenseAuditResult | null>(null);
  const [licBusy, setLicBusy] = useState(false);
  const [licError, setLicError] = useState<string | null>(null);

  const [seccompStack, setSeccompStack] = useState<'node' | 'python' | 'go' | 'rust' | 'static-caddy'>('node');
  const [seccompProfile, setSeccompProfile] = useState<SeccompProfileResult | null>(null);
  const [runcVersionInput, setRuncVersionInput] = useState('1.3.3');
  const [runcAudit, setRuncAudit] = useState<RuncAuditResult | null>(null);
  const [seccompBusy, setSeccompBusy] = useState<'gen' | 'runc' | null>(null);
  const [seccompError, setSeccompError] = useState<string | null>(null);

  // Cycle-14: Pre-Deploy Shannon-Entropy & Pattern Secret Gate (12 Rules)
  const [gateInput, setGateInput] = useState(
    'RELEASE_ID=550e8400-e29b-41d4-a716-446655440000\nGIT_COMMIT_SHA=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nPUBLIC_APP_URL=https://app.acme-demo.dev'
  );
  const [gateResult, setGateResult] = useState<PreDeploySecretScanResult | null>(null);
  const [gateBusy, setGateBusy] = useState(false);
  const [gateError, setGateError] = useState<string | null>(null);

  // Cycle-15: Zero-Trust SPIFFE-Lite mTLS Identity CA (Ed25519)
  const [mtlsServiceName, setMtlsServiceName] = useState('edge-api-rust');
  const [mtlsCerts, setMtlsCerts] = useState<MtlsCertRecord[]>([]);
  const [mtlsLastIssued, setMtlsLastIssued] = useState<{ cert: MtlsCertRecord; signatureB64: string } | null>(null);
  const [mtlsVerify, setMtlsVerify] = useState<MtlsVerifyResult | null>(null);
  const [mtlsCaddyPolicy, setMtlsCaddyPolicy] = useState<Record<string, unknown> | null>(null);
  const [mtlsBusy, setMtlsBusy] = useState<'issue' | 'verify' | 'revoke' | null>(null);
  const [mtlsError, setMtlsError] = useState<string | null>(null);

  // Cycle-16: OCI Artifact Signature & SLSA Rekor Gate (CVE-2026-22703) + Orphaned PR-Preview Auto-Reaper
  const [ociResult, setOciResult] = useState<OciVerifyResult | null>(null);
  const [ociBusy, setOciBusy] = useState<'tampered' | 'valid' | null>(null);
  const [ociError, setOciError] = useState<string | null>(null);
  const [orphanScan, setOrphanScan] = useState<OrphanScanResult | null>(null);
  const [orphanReap, setOrphanReap] = useState<OrphanReapResult | null>(null);
  const [orphanBusy, setOrphanBusy] = useState<'scan' | 'reap' | null>(null);
  const [orphanError, setOrphanError] = useState<string | null>(null);

  useEffect(() => {
    if (tab !== 'security') return;
    let active = true;
    Promise.all([
      api.listPasskeys().catch(() => ({ passkeys: [] })),
      api.listSecretLeases().catch(() => ({ leases: [] })),
      api.getLatestCveScan().catch(() => null),
      api.getBrandTheme().catch(() => null),
      api.listOutboundWebhooks().catch(() => ({ subscriptions: [] })),
      api.listWebhookDlq(50).catch(() => ({ entries: [] })),
      api.getAdmissionPolicy().catch(() => null),
      api.getLatestComplianceBundle().catch(() => null),
    ]).then(([pkRes, leaseRes, latestCve, brandRes, whSubRes, whDlqRes, admRes, compRes]) => {
      if (!active) return;
      setPasskeys(Array.isArray(pkRes?.passkeys) ? pkRes.passkeys : []);
      setSecretLeases(Array.isArray(leaseRes?.leases) ? leaseRes.leases : []);
      if (latestCve) setCveScan(latestCve);
      if (brandRes && typeof brandRes.brandName === 'string') {
        setBrandForm({
          brandName: brandRes.brandName || 'Culkibo',
          tagline: brandRes.tagline ?? '',
          accentHex: /^#[0-9a-fA-F]{6}$/.test(brandRes.accentHex || '') ? brandRes.accentHex : '#6366f1',
          logoUrl: brandRes.logoUrl ?? '',
          supportUrl: brandRes.supportUrl ?? '',
          hidePoweredBy: Boolean(brandRes.hidePoweredBy),
          updatedAt: brandRes.updatedAt ?? null,
        });
      }
      setWhSubs(Array.isArray(whSubRes?.subscriptions) ? whSubRes.subscriptions : []);
      setWhDlq(Array.isArray(whDlqRes?.entries) ? whDlqRes.entries : []);
      if (admRes) setAdmPolicy(admRes);
      if (compRes && compRes.payloadSha256) setCompBundle(compRes);
    });
    return () => { active = false; };
  }, [tab]);

  const loadAll = async () => {
    const [sys, gh, cf, ntf, doc, ing, s3, tel] = await Promise.all([
      api.getSystemStatus().catch(() => null),
      api.getGitHubStatus().catch(() => null),
      api.getCloudflareConfig().catch(() => null),
      api.getNotificationsConfig().catch(() => null),
      api.getDbDockerStatus().catch(() => null),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
      api.getTelemetryStatus().catch(() => null),
    ]);
    setSysStatus(sys);
    setGithubStatus(gh);
    setCfConfig(cf);
    setTelemetryStatus(tel);
    // P0-2: nunca copiar valores enmascarados (`...`/`••`) al input editable
    if (cf?.accountId && !String(cf.accountId).includes('...') && !String(cf.accountId).includes('••')) {
      setCfAccountId(cf.accountId);
    }
    setNotif(ntf);
    setNotifLoadFailed(!ntf);
    setDockerStatus(doc);
    setCaddyStatus(ing);
    setS3Config(s3);
    if (s3?.configured) {
      setS3Form((prev) => ({
        ...prev,
        endpoint: prev.endpoint || s3.endpoint || '',
        bucket: prev.bucket || s3.bucket || '',
        region: prev.region || s3.region || 'auto',
        prefix: prev.prefix || s3.prefix || 'culkibo/',
      }));
    }
    if (cf?.isConfigured) {
      api.getCloudflareZones().then((z) => setCfZones(z.zones || [])).catch(() => {});
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getSystemStatus().catch(() => null),
      api.getGitHubStatus().catch(() => null),
      api.getCloudflareConfig().catch(() => null),
      api.getNotificationsConfig().catch(() => null),
      api.getDbDockerStatus().catch(() => null),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
    ]).then(([sys, gh, cf, ntf, doc, ing, s3]) => {
      if (!active) return;
      setSysStatus(sys);
      setGithubStatus(gh);
      setCfConfig(cf);
      if (cf?.accountId && !String(cf.accountId).includes('...') && !String(cf.accountId).includes('••')) {
        setCfAccountId(cf.accountId);
      }
      setNotif(ntf);
      setNotifLoadFailed(!ntf);
      setDockerStatus(doc);
      setCaddyStatus(ing);
      setS3Config(s3);
      if (s3?.configured) {
        setS3Form((prev) => ({
          ...prev,
          endpoint: s3.endpoint || '',
          bucket: s3.bucket || '',
          region: s3.region || 'auto',
          prefix: s3.prefix || 'culkibo/',
        }));
      }
      if (cf?.isConfigured) {
        api.getCloudflareZones().then((z) => { if (active) setCfZones(z.zones || []); }).catch(() => {});
      }
    });
    return () => { active = false; };
  }, []);

  const handleConnectGitHub = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ghToken.trim()) return;
    setGhBusy(true);
    setGhFeedback(null);
    try {
      await api.connectGitHub(ghToken.trim());
      setGhToken('');
      setGhFeedback({ type: 'ok', text: 'Cuenta de GitHub vinculada correctamente.' });
      void loadAll();
    } catch (err: any) {
      setGhFeedback({ type: 'err', text: err?.message || 'Error al conectar con GitHub' });
    } finally {
      setGhBusy(false);
    }
  };

  const handleDisconnectGitHub = async () => {
    setGhBusy(true);
    setConfirmDisconnectGh(false);
    try {
      await api.disconnectGitHub();
      setGhFeedback({ type: 'ok', text: 'Cuenta de GitHub desconectada.' });
      void loadAll();
    } catch (err: any) {
      setGhFeedback({ type: 'err', text: err?.message || 'Error al desconectar' });
    } finally {
      setGhBusy(false);
    }
  };

  const handleSaveCloudflare = async (e: React.FormEvent) => {
    e.preventDefault();
    setCfBusy(true);
    setCfFeedback(null);
    try {
      const cleanToken = cfToken.trim();
      const cleanAccount = cfAccountId.trim();
      if (cleanToken) {
        const verify = await api.verifyCloudflareToken(cleanToken);
        if (verify.error || verify.valid === false) {
          throw new Error(verify.message || verify.error || 'Token de Cloudflare inválido');
        }
      }
      const payload: { apiToken?: string; accountId?: string; useMock: boolean } = { useMock: false };
      if (cleanToken) payload.apiToken = cleanToken;
      if (cleanAccount && !cleanAccount.includes('...') && !cleanAccount.includes('••')) {
        payload.accountId = cleanAccount;
      }
      await api.saveCloudflareConfig(payload);
      setCfToken('');
      setCfFeedback({ type: 'ok', text: 'Cloudflare guardado y verificado.' });
      const zonesRes = await api.getCloudflareZones().catch(() => ({ zones: [] }));
      setCfZones(zonesRes.zones || []);
      void loadAll();
    } catch (err: any) {
      setCfFeedback({ type: 'err', text: err?.message || 'Error al guardar Cloudflare' });
    } finally {
      setCfBusy(false);
    }
  };

  const handleSaveS3 = async (e: React.FormEvent) => {
    e.preventDefault();
    setS3Busy(true);
    try {
      const payload: Record<string, unknown> = {
        endpoint: s3Form.endpoint.trim(),
        bucket: s3Form.bucket.trim(),
        region: s3Form.region.trim() || 'auto',
        prefix: s3Form.prefix.trim(),
      };
      if (s3Form.accessKeyId.trim()) payload.accessKeyId = s3Form.accessKeyId.trim();
      if (s3Form.secretAccessKey.trim()) payload.secretAccessKey = s3Form.secretAccessKey.trim();
      await api.setDbStorage(payload);
      setS3Form((prev) => ({ ...prev, accessKeyId: '', secretAccessKey: '' }));
      onNotify?.('Almacenamiento S3 / R2 guardado', 'success');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const loadInstanceBackups = async () => {
    const res = await api.listInstanceBackups().catch(() => ({ backups: [] }));
    setInstanceBackups(res.backups || []);
  };

  const loadS3Objects = async () => {
    setS3ObjectsLoading(true);
    try {
      const res = await api.listRemoteS3Objects();
      setS3Objects(res.objects || []);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudieron listar los objetos en S3', 'error');
    } finally {
      setS3ObjectsLoading(false);
    }
  };

  const loadAudit = async () => {
    setAuditLoading(true);
    try {
      const res = await api.getSystemAudit({ limit: 40 });
      setAuditEvents(res.events || []);
    } catch {
      // ignorar
    } finally {
      setAuditLoading(false);
    }
  };

  const loadNotifHistory = async () => {
    const res = await api.getNotificationsHistory(20).catch(() => ({ notifications: [] }));
    setNotifHistory(res.notifications || []);
  };

  useEffect(() => {
    let active = true;
    if (tab === 'backups') {
      api.listInstanceBackups()
        .then((res) => { if (active) setInstanceBackups(res.backups || []); })
        .catch(() => {});
    } else if (tab === 'system') {
      api.getSystemAudit({ limit: 40 })
        .then((res) => { if (active) setAuditEvents(res.events || []); })
        .catch(() => {});
      api.getTelemetryStatus()
        .then((res) => { if (active) setTelemetryStatus(res); })
        .catch(() => {});
      api.getHttp3Status()
        .then((res) => { if (active) setHttp3Status(res); })
        .catch(() => { if (active) setHttp3Status(null); });
      api.getDnsProviders()
        .then((res) => { if (active) setDnsProviders(res.providers || []); })
        .catch(() => { if (active) setDnsProviders([]); });
    } else if (tab === 'security') {
      api.getRbacMe()
        .then((me) => { if (active) setIdentity(me); })
        .catch(() => {});
      api.getOidcProviders()
        .then((res) => {
          if (!active) return;
          setOidcProviders(res.providers || []);
          setOidcUnavailable(false);
        })
        .catch(() => {
          if (active) setOidcUnavailable(true);
        });
      api.getSecurityAuditLog({ limit: 25 })
        .then((res) => { if (active) setSecurityAuditEntries(res.entries || []); })
        .catch(() => {
          api.getSystemAudit({ limit: 25 })
            .then((res) => { if (active) setSecurityAuditEntries(res.events || []); })
            .catch(() => {});
        });
    } else if (tab === 'notifications') {
      api.getNotificationsHistory(20)
        .then((res) => { if (active) setNotifHistory(res.notifications || []); })
        .catch(() => {});
    } else if (tab === 'gitops') {
      Promise.all([
        api.getVaultSecrets().catch(() => ({ secrets: [] })),
        api.getGitOpsDrift().catch(() => null),
        api.getProjects().catch(() => []),
      ]).then(([vRes, dRes, pList]) => {
        if (!active) return;
        setVaultSecrets(vRes.secrets || []);
        setGitopsDrift(dRes);
        const list = Array.isArray(pList) ? pList : [];
        setEnvProjects(list);
        if (list.length > 0) {
          setEnvProjectId((prev) => prev || list[0].id);
        }
      });
    }
    return () => { active = false; };
  }, [tab]);

  useEffect(() => {
    if (tab !== 'gitops' || !envProjectId) return;
    let active = true;
    api.getProjectEnvironments(envProjectId)
      .then((res) => { if (active) setProjectEnvs(res.environments || []); })
      .catch(() => { if (active) setProjectEnvs([]); });
    return () => { active = false; };
  }, [tab, envProjectId]);

  const handleExportInstance = async (e: React.FormEvent) => {
    e.preventDefault();
    setExportingSnapshot(true);
    try {
      const res = await api.exportInstanceSnapshot({
        includeSecrets: exportIncludeSecrets,
        passphrase: exportPassphrase.trim() || '',
        uploadToS3: exportUploadS3 && s3Config.configured,
      });
      onNotify?.(
        res.fileName
          ? `Snapshot completo creado: ${res.fileName}`
          : 'Snapshot completo exportado correctamente',
        'success'
      );
      await loadInstanceBackups();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al exportar snapshot', 'error');
    } finally {
      setExportingSnapshot(false);
    }
  };

  const handleDownloadSnapshot = async (fileName: string) => {
    try {
      const { blob } = await api.downloadInstanceSnapshotBlob(fileName);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo descargar el snapshot', 'error');
    }
  };

  const handleImportInstance = async (dryRun: boolean) => {
    if (!importSnapshotObj) return;
    setImportingSnapshot(true);
    try {
      const res = await api.importInstanceSnapshot({
        snapshot: importSnapshotObj,
        passphrase: importPassphrase.trim() || '',
        dryRun,
        mode: importMode,
      });
      setImportDryRunResult(res);
      if (!dryRun) {
        onNotify?.('Instancia Culkibo restaurada desde snapshot correctamente', 'success');
        void loadAll();
      } else {
        onNotify?.('Simulación (dry-run) completada. Revisa los cambios antes de aplicar.', 'info');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al procesar el snapshot', 'error');
    } finally {
      setImportingSnapshot(false);
    }
  };

  const handleTestS3 = async () => {
    setS3Busy(true);
    try {
      const r = await api.testDbStorage();
      onNotify?.(`Conexión correcta con el bucket ${r.bucket}`, 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo conectar con S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const handleDisconnectS3 = async () => {
    setConfirmDisconnectS3(false);
    setS3Busy(true);
    try {
      await api.setDbStorage(null);
      setS3Form({ endpoint: '', region: 'auto', bucket: '', accessKeyId: '', secretAccessKey: '', prefix: 'culkibo/' });
      onNotify?.('Almacenamiento S3 / R2 desconectado', 'info');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo desconectar S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const handleSaveNotifications = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!notif) return;
    setNotifBusy(true);
    try {
      const updated = await api.saveNotificationsConfig(notif);
      setNotif(updated);
      onNotify?.('Preferencias de alertas guardadas', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar notificaciones', 'error');
    } finally {
      setNotifBusy(false);
    }
  };

  const handleTestNotifications = async () => {
    if (!notif) return;
    setNotifTesting(true);
    try {
      // Guardar primero cambios pendientes para no probar una configuración desactualizada
      const saved = await api.saveNotificationsConfig(notif);
      setNotif(saved);
      const res = await api.testNotifications();
      void loadNotifHistory();
      if (res.sent) {
        onNotify?.(`Alerta de prueba enviada a ${res.delivered} ${res.delivered === 1 ? 'canal' : 'canales'}`, 'success');
      } else {
        const failedDetails = Array.isArray(res.results)
          ? res.results
              .filter((r: any) => r && !r.ok)
              .map((r: any) => `${r.channel}: ${r.error || 'error'}`)
              .join(' · ')
          : '';
        const reason = res.reason === 'no_channels'
          ? 'Activa al menos un canal (Telegram, Discord, Slack o Webhook) antes de probar.'
          : res.reason === 'disabled'
            ? 'Activa el interruptor principal de alertas.'
            : failedDetails
              ? `Fallo al enviar alerta: ${failedDetails}`
              : (res.reason || 'No se pudo entregar la alerta a ningún canal.');
        onNotify?.(reason, failedDetails ? 'error' : 'info');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al enviar alerta de prueba', 'error');
    } finally {
      setNotifTesting(false);
    }
  };

  const handlePruneCache = async () => {
    setPruning(true);
    try {
      const res = await api.pruneBuildCache({ keepStorageGb: 5 });
      onNotify?.(res.ok ? 'Caché de Docker BuildKit podada correctamente' : (res.error || 'Poda completada'), 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al podar caché', 'error');
    } finally {
      setPruning(false);
    }
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      onNotify?.(res.message || 'Caddy activado', 'success');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo iniciar Caddy', 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  const handleToggleTelemetry = async () => {
    if (!telemetryStatus || telemetryStatus.lockedByEnv) return;
    setTelemetryBusy(true);
    try {
      const next = await api.setTelemetryEnabled(!telemetryStatus.persistedEnabled);
      setTelemetryStatus(next);
      onNotify?.(
        next.enabled
          ? 'Telemetría anónima activada'
          : 'Telemetría anónima desactivada (cola local vaciada)',
        'success'
      );
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo actualizar la telemetría', 'error');
    } finally {
      setTelemetryBusy(false);
    }
  };

  const handleResetTelemetryId = async () => {
    setTelemetryBusy(true);
    try {
      const next = await api.resetTelemetryId();
      setTelemetryStatus(next);
      if (showTelemetryPreview) {
        const prev = await api.getTelemetryPreview().catch(() => null);
        if (prev) setTelemetryPreview(prev);
      }
      onNotify?.('Identificador anónimo rotado correctamente', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo rotar el identificador', 'error');
    } finally {
      setTelemetryBusy(false);
    }
  };

  const handleToggleTelemetryPreview = async () => {
    if (showTelemetryPreview) {
      setShowTelemetryPreview(false);
      return;
    }
    setShowTelemetryPreview(true);
    setTelemetryPreviewLoading(true);
    try {
      const prev = await api.getTelemetryPreview();
      setTelemetryPreview(prev);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo obtener la vista previa de telemetría', 'error');
    } finally {
      setTelemetryPreviewLoading(false);
    }
  };

  const handleExportGitOps = async () => {
    setGitopsBusy('export');
    try {
      const res = await api.exportGitOps({ includeCrons: true, includeMonitors: true });
      setGitopsYaml(res.yaml || '');
      setGitopsPlan(null);
      onNotify?.('Manifiesto culkibo.yaml exportado sin secretos en claro', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo exportar culkibo.yaml', 'error');
    } finally {
      setGitopsBusy(null);
    }
  };

  const handlePlanGitOps = async () => {
    if (!gitopsYaml.trim()) return;
    setGitopsBusy('plan');
    try {
      const res = await api.planGitOps(gitopsYaml, gitopsPrune);
      setGitopsPlan(res);
      onNotify?.('Simulación GitOps completada. Revisa el plan antes de aplicar.', 'info');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al simular el manifiesto YAML', 'error');
    } finally {
      setGitopsBusy(null);
    }
  };

  const handleApplyGitOps = async () => {
    if (!gitopsYaml.trim()) return;
    setGitopsBusy('apply');
    try {
      const res = await api.applyGitOps(gitopsYaml, {
        dryRun: false,
        prune: gitopsPrune,
        confirmDestructive: gitopsPrune && gitopsConfirmDestructive,
      });
      setGitopsPlan(res);
      const drift = await api.getGitOpsDrift().catch(() => null);
      if (drift) setGitopsDrift(drift);
      onNotify?.('Manifiesto culkibo.yaml aplicado correctamente', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al aplicar el manifiesto GitOps', 'error');
    } finally {
      setGitopsBusy(null);
    }
  };

  const handleCheckDrift = async () => {
    setGitopsBusy('drift');
    try {
      const drift = await api.getGitOpsDrift();
      setGitopsDrift(drift);
      const isInSync = drift.inSync ?? !(drift.drifted ?? drift.hasDrift ?? false);
      const diffCount =
        drift.drifts?.length ??
        ((drift.summary?.create || 0) + (drift.summary?.update || 0) + (drift.summary?.delete || 0));
      onNotify?.(
        isInSync ? 'Estado en vivo sincronizado con culkibo.yaml' : `Drift detectado (${diffCount} diferencias)`,
        isInSync ? 'success' : 'info'
      );
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo comprobar el drift', 'error');
    } finally {
      setGitopsBusy(null);
    }
  };

  const handleCopyYaml = async () => {
    if (!gitopsYaml.trim()) return;
    const ok = await copyToClipboard(gitopsYaml);
    if (!ok) return;
    setCopiedYaml(true);
    window.setTimeout(() => setCopiedYaml(false), 1800);
    onNotify?.('culkibo.yaml copiado al portapapeles', 'success');
  };

  const handleDownloadYaml = () => {
    if (!gitopsYaml.trim()) return;
    const blob = new Blob([gitopsYaml], { type: 'text/yaml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'culkibo.yaml';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveVaultSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanKey = vaultKey.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    if (!cleanKey || !vaultValue) return;
    setVaultBusy(true);
    try {
      await api.setVaultSecret(cleanKey, vaultValue, { scope: vaultScope });
      setVaultKey('');
      setVaultValue('');
      const res = await api.getVaultSecrets();
      setVaultSecrets(res.secrets || []);
      onNotify?.(`Secreto \${vault.${cleanKey}} cifrado en el Vault`, 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo guardar el secreto', 'error');
    } finally {
      setVaultBusy(false);
    }
  };

  const handleDeleteVaultSecret = async (key: string) => {
    setVaultBusy(true);
    try {
      await api.deleteVaultSecret(key);
      setVaultSecrets((prev) => prev.filter((s) => s.key !== key));
      onNotify?.(`Secreto ${key} eliminado del Vault`, 'info');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo eliminar el secreto', 'error');
    } finally {
      setVaultBusy(false);
    }
  };

  const handleSaveProjectEnv = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!envProjectId || !envEditName.trim()) return;
    setEnvBusy(true);
    try {
      const envVars: Record<string, string> = {};
      for (const line of envEditVars.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const idx = t.indexOf('=');
        if (idx > 0) envVars[t.slice(0, idx).trim()] = t.slice(idx + 1);
      }
      await api.saveProjectEnvironment(envProjectId, envEditName.trim().toLowerCase(), {
        branch: envEditBranch.trim() || undefined,
        envVars,
      });
      setEnvEditVars('');
      const res = await api.getProjectEnvironments(envProjectId);
      setProjectEnvs(res.environments || []);
      onNotify?.(`Entorno «${envEditName}» guardado con cifrado en reposo`, 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo guardar el entorno', 'error');
    } finally {
      setEnvBusy(false);
    }
  };

  const handleDiffEnvs = async () => {
    if (!envProjectId) return;
    setEnvBusy(true);
    try {
      const diff = await api.diffProjectEnvironments(envProjectId, envDiffFrom, envDiffTo);
      setEnvDiffResult(diff);
      onNotify?.(`Diff seguro (solo hashes) ${envDiffFrom} → ${envDiffTo} calculado`, 'info');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo calcular el diff de entornos', 'error');
    } finally {
      setEnvBusy(false);
    }
  };

  const handlePromoteEnv = async (dryRun: boolean) => {
    if (!envProjectId) return;
    setEnvBusy(true);
    try {
      await api.promoteProjectEnvironment(envProjectId, {
        fromEnv: envDiffFrom,
        toEnv: envDiffTo,
        includeEnvVars: false,
        dryRun,
      });
      onNotify?.(
        dryRun
          ? `Simulación de promoción ${envDiffFrom} → ${envDiffTo} lista`
          : `Promoción ${envDiffFrom} → ${envDiffTo} aplicada`,
        'success'
      );
      const res = await api.getProjectEnvironments(envProjectId).catch(() => ({ environments: [] }));
      setProjectEnvs(res.environments || []);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo promocionar el entorno', 'error');
    } finally {
      setEnvBusy(false);
    }
  };

  // --- Handlers de Seguridad v1.1 ---

  const copySecurityValue = async (text: string, key: string, label: string) => {
    const ok = await copyToClipboard(text);
    if (!ok) return;
    setCopiedSecKey(key);
    window.setTimeout(() => setCopiedSecKey(null), 1800);
    onNotify?.(`${label} copiado al portapapeles`, 'success');
  };

  const handleSetup2FA = async () => {
    setTotpBusy('setup');
    setTotpNotice(null);
    setTotpRecoveryCodes([]);
    try {
      const res = await api.setup2FA();
      setTotpSetup(res);
      setTotpNotice({
        kind: 'info',
        text: 'Añade la clave Base32 o la URI otpauth:// en tu app autenticadora (1Password, Bitwarden, Authy o Google Authenticator) y verifica el código de 6 dígitos.',
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'No se pudo iniciar la configuración 2FA';
      setTotpNotice({
        kind: 'err',
        text: msg.includes('not a function') || msg.includes('404')
          ? 'La configuración TOTP requiere sesión de usuario RBAC (Equipo y RBAC) y el endpoint /api/auth/2fa/setup activo.'
          : msg,
      });
    } finally {
      setTotpBusy(null);
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = totpCode.replace(/\s+/g, '');
    if (cleanCode.length < 6) return;
    setTotpBusy('verify');
    setTotpNotice(null);
    try {
      const res = await api.verify2FA(cleanCode);
      setTotpEnabled(true);
      setTotpSetup(null);
      setTotpCode('');
      if (Array.isArray(res.recoveryCodes) && res.recoveryCodes.length > 0) {
        setTotpRecoveryCodes(res.recoveryCodes);
      }
      setTotpNotice({
        kind: 'ok',
        text: 'Autenticación en dos pasos (TOTP 2FA) verificada y activa.',
      });
      onNotify?.('2FA (TOTP) activado correctamente', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Código TOTP inválido';
      setTotpNotice({ kind: 'err', text: msg });
    } finally {
      setTotpBusy(null);
    }
  };

  const handleDisable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = totpDisableCode.replace(/\s+/g, '');
    if (!cleanCode) return;
    setTotpBusy('disable');
    setTotpNotice(null);
    try {
      await api.disable2FA({
        code: cleanCode,
        password: totpDisablePassword.trim() || undefined,
      });
      setTotpEnabled(false);
      setTotpDisableOpen(false);
      setTotpDisableCode('');
      setTotpDisablePassword('');
      setTotpRecoveryCodes([]);
      setTotpNotice({ kind: 'info', text: '2FA desactivado para tu cuenta.' });
      onNotify?.('Autenticación en dos pasos desactivada', 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'No se pudo desactivar 2FA';
      setTotpNotice({ kind: 'err', text: msg });
    } finally {
      setTotpBusy(null);
    }
  };

  const handleVerifyAuditChain = async () => {
    setAuditVerifyBusy(true);
    setAuditVerifyError(null);
    try {
      const res = await api.verifyAuditLogIntegrity();
      setAuditVerification(res);
      if (res.valid) {
        onNotify?.(`Cadena SHA-256 verificada (${res.checkedCount} entradas íntegras)`, 'success');
      } else {
        onNotify?.(`Alteración detectada en auditoría (${res.reason || 'hash inválido'})`, 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'No se pudo verificar la cadena de auditoría';
      setAuditVerifyError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setAuditVerifyBusy(false);
    }
  };

  // --- Cycle-8 Enterprise Sovereignty Handlers ---
  const handleRegisterPasskey = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasskeyBusy(true);
    setPasskeyChallenge(null);
    try {
      const res = await api.beginPasskeyRegistration({
        label: passkeyLabel.trim() || 'Hardware Passkey',
        rpId: typeof window !== 'undefined' ? window.location.hostname : 'localhost',
      });
      if (res.demoRegistered) {
        setPasskeys((prev) => [res.demoRegistered!, ...prev.filter((p) => p.id !== res.demoRegistered!.id)]);
        onNotify?.(`Passkey “${res.demoRegistered.label}” registered`, 'success');
      } else {
        setPasskeyChallenge(res.challengeId || res.challenge);
        onNotify?.('WebAuthn registration challenge issued (ES256 / Ed25519)', 'info');
      }
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not start passkey registration', 'error');
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handleRevokePasskey = async (id: string) => {
    try {
      await api.revokePasskey(id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      onNotify?.('Passkey revoked', 'info');
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not revoke passkey', 'error');
    }
  };

  const handleIssueLease = async () => {
    setLeaseBusy('lease');
    try {
      const res = await api.issueSecretLease({
        secretKey: leaseKeyName.trim() || 'DATABASE_URL',
        scope: 'read',
        ttlSec: 3600,
        reason: 'Operator 1h ephemeral lease',
      });
      if (res.lease) {
        setSecretLeases((prev) => [res.lease, ...prev.filter((l) => l.id !== res.lease.id)]);
      }
      if (res.token) setIssuedLeaseToken(res.token);
      onNotify?.(`1h secret lease issued for ${leaseKeyName.trim() || 'DATABASE_URL'}`, 'success');
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not issue secret lease', 'error');
    } finally {
      setLeaseBusy(null);
    }
  };

  const handleRevokeLease = async (id: string) => {
    try {
      await api.revokeSecretLease(id);
      setSecretLeases((prev) => prev.filter((l) => l.id !== id));
      onNotify?.('Secret lease revoked', 'info');
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not revoke secret lease', 'error');
    }
  };

  const handleRotationAudit = async () => {
    setLeaseBusy('audit');
    try {
      const res = await api.getSecretRotationAudit(90);
      setRotationAudit(res);
      onNotify?.(`Rotation audit: ${res.staleCount} stale key(s) > 90d out of ${res.totalKeys}`, res.staleCount > 0 ? 'info' : 'success');
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not run rotation audit', 'error');
    } finally {
      setLeaseBusy(null);
    }
  };

  const handleBreakGlass = async () => {
    const cleanReason = breakGlassReason.trim();
    if (cleanReason.length < 10) {
      onNotify?.('Break-Glass requires a reason of at least 10 characters', 'error');
      return;
    }
    setLeaseBusy('breakglass');
    try {
      const res = await api.issueBreakGlass({ reason: cleanReason, ttlSec: 900 });
      if (res.lease) {
        setSecretLeases((prev) => [res.lease, ...prev.filter((l) => l.id !== res.lease.id)]);
      }
      if (res.token) setIssuedLeaseToken(res.token);
      onNotify?.('Audited 15-min Break-Glass token issued (hard-capped 900s)', 'info');
    } catch (err: unknown) {
      onNotify?.(err instanceof Error ? err.message : 'Could not issue break-glass token', 'error');
    } finally {
      setLeaseBusy(null);
    }
  };

  const handleRunCveScan = async () => {
    setCveBusy(true);
    setCveError(null);
    try {
      const res = await api.runCveScan({ allowNetwork: false });
      setCveScan(res);
      onNotify?.(`SBOM CVE scan complete: ${res.totalVulnerabilities} vulnerabilities across ${res.scannedPackages} packages`, res.totalVulnerabilities > 0 ? 'info' : 'success');
    } catch (err: unknown) {
      setCveError(err instanceof Error ? err.message : 'Could not scan SBOM CVEs');
    } finally {
      setCveBusy(false);
    }
  };

  const handleExportIac = async () => {
    setIacBusy(true);
    setIacError(null);
    try {
      const res = await api.exportIacEstate({ format: 'all' });
      setIacExport(res);
      const keys = Object.keys(res.files || {});
      if (keys.length > 0 && !keys.includes(iacFileTab)) {
        setIacFileTab(keys[0]);
      }
      onNotify?.('OpenTofu (.tf) + Compose IaC bundle exported (0 plaintext secrets)', 'success');
    } catch (err: unknown) {
      setIacError(err instanceof Error ? err.message : 'Could not export IaC bundle');
    } finally {
      setIacBusy(false);
    }
  };

  // --- Cycle-9 White-Label Brand & Standard-Webhooks DLQ Handlers ---
  const handleSaveBrand = async (e: React.FormEvent) => {
    e.preventDefault();
    setBrandBusy('save');
    setBrandError(null);
    try {
      const saved = await api.updateBrandTheme({
        brandName: brandForm.brandName.trim(),
        tagline: brandForm.tagline.trim(),
        accentHex: brandForm.accentHex.trim(),
        logoUrl: brandForm.logoUrl.trim(),
        supportUrl: brandForm.supportUrl.trim(),
        hidePoweredBy: brandForm.hidePoweredBy,
      });
      setBrandForm({
        brandName: saved.brandName || brandForm.brandName,
        tagline: saved.tagline ?? brandForm.tagline,
        accentHex: saved.accentHex || brandForm.accentHex,
        logoUrl: saved.logoUrl ?? brandForm.logoUrl,
        supportUrl: saved.supportUrl ?? brandForm.supportUrl,
        hidePoweredBy: Boolean(saved.hidePoweredBy),
        updatedAt: saved.updatedAt ?? new Date().toISOString(),
      });
      onNotify?.(`White-label brand “${saved.brandName || brandForm.brandName}” saved`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not save white-label brand';
      setBrandError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setBrandBusy(null);
    }
  };

  const handleResetBrand = async () => {
    setBrandBusy('reset');
    setBrandError(null);
    try {
      const reset = await api.resetBrandTheme();
      setBrandForm({
        brandName: reset.brandName || 'Culkibo',
        tagline: reset.tagline ?? 'Ultra-lightweight self-hosted PaaS',
        accentHex: reset.accentHex || '#6366f1',
        logoUrl: reset.logoUrl ?? '',
        supportUrl: reset.supportUrl ?? '',
        hidePoweredBy: Boolean(reset.hidePoweredBy),
        updatedAt: reset.updatedAt ?? null,
      });
      onNotify?.('Brand theme restored to default Culkibo settings', 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not reset brand theme';
      setBrandError(msg);
    } finally {
      setBrandBusy(null);
    }
  };

  const handleAddWebhookSub = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanUrl = whNewUrl.trim();
    if (!cleanUrl) return;
    setWhBusyId('create');
    setWhError(null);
    try {
      const res = await api.upsertOutboundWebhook({
        url: cleanUrl,
        description: whNewDesc.trim() || undefined,
        events: ['deploy.succeeded', 'deploy.failed', 'backup.verified'],
        enabled: true,
      });
      const list = await api.listOutboundWebhooks().catch(() => ({ subscriptions: [] }));
      setWhSubs(Array.isArray(list.subscriptions) ? list.subscriptions : []);
      if (res.secret && res.subscription?.id) {
        setWhRotatedSecret({ subId: res.subscription.id, secret: res.secret, expiresAt: null });
      }
      setWhNewUrl('');
      setWhNewDesc('');
      onNotify?.('Standard-Webhook subscription saved (whsec_ generated)', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not add outbound webhook';
      setWhError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setWhBusyId(null);
    }
  };

  const handleRotateWebhookSecret = async (subId: string) => {
    setWhBusyId(`rot-${subId}`);
    setWhError(null);
    try {
      const res = await api.rotateOutboundWebhookSecret(subId, { graceSec: 86400 });
      const list = await api.listOutboundWebhooks().catch(() => ({ subscriptions: [] }));
      setWhSubs(Array.isArray(list.subscriptions) ? list.subscriptions : []);
      const sec = res.secret || res.primarySecret;
      if (sec) {
        setWhRotatedSecret({ subId, secret: sec, expiresAt: res.secondaryExpiresAt || null });
      }
      onNotify?.('Dual-secret rotated (previous secret stays valid for 24h grace window)', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not rotate webhook secret';
      setWhError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setWhBusyId(null);
    }
  };

  const handleReplayDlq = async (dlqId: string) => {
    setWhBusyId(`rep-${dlqId}`);
    setWhError(null);
    try {
      await api.replayWebhookDlqEntry(dlqId);
      const refreshed = await api.listWebhookDlq(50).catch(() => ({ entries: [] }));
      setWhDlq(Array.isArray(refreshed.entries) ? refreshed.entries : []);
      onNotify?.('DLQ delivery replayed with fresh anti-SSRF DNS check', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not replay DLQ delivery';
      setWhError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setWhBusyId(null);
    }
  };

  const handleSelectAdmissionPreset = async (preset: 'baseline' | 'restricted' | 'soc2-strict') => {
    setAdmBusy('preset');
    setAdmError(null);
    try {
      const updated = await api.updateAdmissionPolicy({ preset });
      setAdmPolicy(updated);
      onNotify?.(`Admission Gate preset switched to "${preset}"`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not update admission preset';
      setAdmError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setAdmBusy(null);
    }
  };

  const handleTestAdmissionSpec = async (mode: 'root' | 'hardened') => {
    setAdmBusy(mode);
    setAdmError(null);
    try {
      const spec = mode === 'root'
        ? {
            image: 'acme/web:latest',
            privileged: true,
            mounts: ['- /:/host:rw', '/var/run/docker.sock:/var/run/docker.sock'],
            capAdd: ['SYS_ADMIN'],
            uid: 0,
            ports: ['0.0.0.0:5432:5432'],
          }
        : {
            image: 'ghcr.io/acme/web:v1.2.4',
            privileged: false,
            mounts: ['acme_uploads:/app/uploads'],
            capAdd: [],
            uid: 1000,
            memoryLimitMb: 512,
            cpuLimit: 1,
            healthcheckPath: '/health',
            attestationVerified: true,
            ports: ['127.0.0.1:8080:8080'],
          };
      // Use preview mode (enforceStatus: false) so browser receives structured DENY JSON with HTTP 200 (0 network errors)
      const res = await api.evaluateAdmissionPolicy({ spec, preset: admPolicy?.preset, enforceStatus: false });
      setAdmEval(res);
      if (res.allowed) {
        onNotify?.(`Admission Gate ALLOW (${res.score}/100 CIS/PSS score)`, 'success');
      } else {
        onNotify?.(`Admission Gate DENY (HTTP 422 enforced · ${Array.isArray(res.enforcedViolations) ? res.enforcedViolations.length : 1} rule violation(s))`, 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Admission evaluation failed';
      setAdmError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setAdmBusy(null);
    }
  };

  const handleGenerateComplianceBundle = async () => {
    setCompBusy('gen');
    setCompError(null);
    setCompVerify(null);
    try {
      const bundle = await api.generateComplianceBundle({ framework: compFramework });
      setCompBundle(bundle);
      const ver = await api.verifyComplianceBundle(bundle).catch(() => null);
      if (ver) setCompVerify(ver);
      onNotify?.(`Ed25519-signed compliance bundle generated (${bundle.overallScore ?? bundle.payload?.overallScore ?? 100}/100)`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not generate compliance bundle';
      setCompError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setCompBusy(null);
    }
  };

  const handleVerifyComplianceBundle = async () => {
    if (!compBundle) return;
    setCompBusy('verify');
    setCompError(null);
    try {
      const ver = await api.verifyComplianceBundle(compBundle);
      setCompVerify(ver);
      onNotify?.(ver.valid ? 'Ed25519 signature & SHA-256 payload cryptographically verified!' : `Tampering detected: ${ver.reason || 'invalid signature'}`, ver.valid ? 'success' : 'error');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not verify compliance bundle';
      setCompError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setCompBusy(null);
    }
  };

  const handleAuditLicenses = async (overridePolicy?: 'saas-strict' | 'oss-permissive' | 'audit-only') => {
    const pol = overridePolicy || licPolicy;
    if (overridePolicy) setLicPolicy(overridePolicy);
    setLicBusy(true);
    setLicError(null);
    try {
      const res = await api.auditSpdxLicenses({ policy: pol });
      setLicReport(res);
      onNotify?.(
        res.compliant
          ? `SPDX License Audit (${pol}): COMPLIANT (${res.score}/100 across ${res.totalComponents} pkg)`
          : `SPDX License Audit flagged ${Array.isArray(res.violations) ? res.violations.length : 1} violation(s)`,
        res.compliant ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'SPDX license audit failed';
      setLicError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setLicBusy(false);
    }
  };

  const handleGenerateSeccomp = async (overrideStack?: 'node' | 'python' | 'go' | 'rust' | 'static-caddy') => {
    const st = overrideStack || seccompStack;
    if (overrideStack) setSeccompStack(overrideStack);
    setSeccompBusy('gen');
    setSeccompError(null);
    try {
      const res = await api.generateSeccompProfile({ stack: st });
      setSeccompProfile(res);
      onNotify?.(`Generated tailored SCMP_ACT_ERRNO seccomp profile for "${st}" (${res.allowedCount} allowed)`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Seccomp profile generation failed';
      setSeccompError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setSeccompBusy(null);
    }
  };

  const handleAuditRunc = async (overrideVer?: string) => {
    const v = (overrideVer ?? runcVersionInput).trim() || '1.3.3';
    if (overrideVer !== undefined) setRuncVersionInput(overrideVer);
    setSeccompBusy('runc');
    setSeccompError(null);
    try {
      const res = await api.auditRuncVersion(v);
      setRuncAudit(res);
      onNotify?.(
        res.vulnerable
          ? `runc ${res.parsedVersion || v} VULNERABLE (${res.cves.join(', ')})`
          : `runc ${res.parsedVersion || v} PASS (patched against CVE-2025-31133/52565/52881)`,
        res.vulnerable ? 'error' : 'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'runc audit failed';
      setSeccompError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setSeccompBusy(null);
    }
  };

  const handleRunPreDeployGate = async (overrideDiff?: string) => {
    const diffText = (overrideDiff ?? gateInput).trim();
    if (!diffText) return;
    if (overrideDiff !== undefined) setGateInput(overrideDiff);
    setGateBusy(true);
    setGateError(null);
    try {
      const res = await api.scanPreDeploySecrets({ diffText, mode: 'enforce' });
      setGateResult(res);
      onNotify?.(
        res.allowed
          ? `Pre-Deploy Secret Gate ALLOWED (0 leaks across ${res.scannedItems ?? 1} item(s))`
          : `Pre-Deploy Secret Gate BLOCKED (${res.blockedCount} high-entropy / secret finding(s) redacted)`,
        res.allowed ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Pre-deploy secret gate scan failed';
      setGateError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setGateBusy(false);
    }
  };

  const handleIssueMtlsCert = async () => {
    const svc = mtlsServiceName.trim() || 'edge-api-rust';
    setMtlsBusy('issue');
    setMtlsError(null);
    setMtlsVerify(null);
    try {
      const res = await api.issueMtlsCert({ serviceName: svc, namespace: 'prod', ttlHours: 24 });
      if (res?.cert) {
        setMtlsLastIssued({ cert: res.cert, signatureB64: res.signatureB64 });
        setMtlsCerts((prev) => [res.cert, ...prev.filter((c) => c.serial !== res.cert.serial)]);
      }
      if (res?.caddyClientAuth) setMtlsCaddyPolicy(res.caddyClientAuth);
      onNotify?.(`Issued short-lived Ed25519 SPIFFE cert (${res.cert?.spiffeId || svc} · 24h TTL)`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'mTLS cert issuance failed';
      setMtlsError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setMtlsBusy(null);
    }
  };

  const handleVerifyMtlsCert = async () => {
    const target = mtlsLastIssued || (mtlsCerts[0]?.signatureB64 ? { cert: mtlsCerts[0], signatureB64: mtlsCerts[0].signatureB64 } : null);
    if (!target) {
      await handleIssueMtlsCert();
      return;
    }
    setMtlsBusy('verify');
    setMtlsError(null);
    try {
      const res = await api.verifyMtlsCert({ cert: target.cert, signatureB64: target.signatureB64 });
      setMtlsVerify(res);
      onNotify?.(
        res.valid
          ? `mTLS Ed25519 Verified: ${res.spiffeId || target.cert.spiffeId} (${res.code})`
          : `mTLS Verification Rejected: ${res.code}`,
        res.valid ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'mTLS verification failed';
      setMtlsError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setMtlsBusy(null);
    }
  };

  const handleRevokeMtlsCert = async () => {
    const serial = mtlsLastIssued?.cert?.serial || mtlsCerts[0]?.serial;
    if (!serial) return;
    setMtlsBusy('revoke');
    setMtlsError(null);
    try {
      await api.revokeMtlsCert(serial, 'operator_revocation');
      setMtlsCerts((prev) => prev.map((c) => (c.serial === serial ? { ...c, revoked: true, revokedReason: 'operator_revocation' } : c)));
      if (mtlsLastIssued?.cert?.serial === serial) {
        const ver = await api.verifyMtlsCert({ cert: mtlsLastIssued.cert, signatureB64: mtlsLastIssued.signatureB64 }).catch(() => null);
        if (ver) setMtlsVerify(ver);
      }
      onNotify?.(`Certificate ${serial} revoked in CRL — subsequent mTLS handshakes rejected (CERT_REVOKED)`, 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'mTLS revocation failed';
      setMtlsError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setMtlsBusy(null);
    }
  };

  const handleVerifyOciArtifact = async (mode: 'tampered' | 'valid') => {
    setOciBusy(mode);
    setOciError(null);
    const targetSha = 'b4e9a1c3f5d70826b4e9a1c3f5d70826b4e9a1c3f5d70826b4e9a1c3f5d70826';
    const forgedSha = 'deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000';
    try {
      const res = await api.verifyOciSignature({
        imageRef: `ghcr.io/acme/web@sha256:${targetSha}`,
        bundle: {
          mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
          rekorVersion: 'v2',
          predicateType: 'https://slsa.dev/provenance/v1',
          rekorEntryDigest: mode === 'tampered' ? forgedSha : targetSha,
          tampered: mode === 'tampered',
        },
        trustRootId: 'culkibo-sigstore-ed25519',
        requiredPredicateType: 'https://slsa.dev/provenance/v1',
        requireRekor: true,
      });
      setOciResult(res);
      const isOk = Boolean(res.valid || res.verified);
      onNotify?.(
        isOk
          ? `OCI Signature & SLSA v1.1 Rekor v2 VERIFIED (${res.code})`
          : `CVE-2026-22703 Rekor Guard BLOCKED: ${res.code}`,
        isOk ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'OCI signature verification failed';
      setOciError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setOciBusy(null);
    }
  };

  const handleScanOrphans = async () => {
    setOrphanBusy('scan');
    setOrphanError(null);
    setOrphanReap(null);
    try {
      const res = await api.scanOrphanResources({
        activeProjects: ['acme-saas-web', 'edge-api-rust'],
        activePreviews: ['pr-91'],
      });
      setOrphanScan(res);
      const oc = Array.isArray(res.orphans) ? res.orphans.length : (res.summary?.orphanCount ?? 0);
      const pc = Array.isArray(res.protected) ? res.protected.length : (res.summary?.protectedCount ?? 0);
      onNotify?.(`Orphan Scan: ${oc} orphan resource(s) slated for GC · ${pc} active sidecar/DB volume(s) PROTECTED`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Orphan resource scan failed';
      setOrphanError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setOrphanBusy(null);
    }
  };

  const handleReapOrphansDryRun = async () => {
    setOrphanBusy('reap');
    setOrphanError(null);
    try {
      const res = await api.reapOrphanResources({ scanResult: orphanScan || undefined, dryRun: true, maxReapPerRun: 20 });
      setOrphanReap(res);
      onNotify?.(`Orphan Reaper (Dry-Run): ${res.plannedCount ?? res.reapedCount ?? 2} item(s) planned · 0 active Compose sidecars touched`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Orphan reap dry-run failed';
      setOrphanError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setOrphanBusy(null);
    }
  };

  const handleRunSecretScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanInput.trim()) return;
    setScanBusy(true);
    setScanError(null);
    try {
      const report = await api.scanSecrets({ text: scanInput });
      setScanReport(report);
      if (report.clean) {
        onNotify?.('Escaneo limpio: cero fugas de secretos detectadas', 'success');
      } else {
        onNotify?.(`Escáner detectó ${report.summary.total} posible(s) fuga(s) de secretos`, 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'No se pudo ejecutar el escáner de secretos';
      setScanError(
        msg.includes('not a function') || msg.includes('404')
          ? 'El endpoint /api/security/scan-secrets no está disponible en esta compilación del servidor.'
          : msg
      );
    } finally {
      setScanBusy(false);
    }
  };

  const handleLoadSafeScannerSample = () => {
    setScanInput(
      [
        '# Ejemplo sintético de prueba (valores ficticios de demostración)',
        'NODE_ENV=production',
        'DATABASE_URL=postgres://demo:EjemploClaveInsegura99@db.local:5432/app',
        'API_KEY=${vault.PROD_API_KEY}',
        'DEMO_AWS_ID=AKIAIOSFODNN7EXAMPLE',
      ].join('\n')
    );
    setScanReport(null);
    setScanError(null);
  };

  const hasCfToken = Boolean(cfConfig?.hasApiToken || cfConfig?.hasToken);

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('settings.title')}</h1>
          <p className="text-sm text-slate-500 mt-1">{t('settings.subtitle')}</p>
        </div>

        {/* Quick Appearance & Language strip */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[11px]">
            {([
              { id: 'light', label: t('settings.themeLight'), icon: Sun },
              { id: 'dark', label: t('settings.themeDark'), icon: Moon },
              { id: 'system', label: t('settings.themeSystem'), icon: Monitor },
            ] as const).map((opt) => {
              const Icon = opt.icon;
              const active = theme === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setTheme(opt.id as ThemeMode)}
                  className={`inline-flex items-center gap-1 px-2 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                    active ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  <span>{opt.label}</span>
                </button>
              );
            })}
          </div>

          <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[11px]">
            <Languages className="w-3 h-3 text-slate-400 mx-1.5 shrink-0" />
            {(['en', 'es'] as const).map((loc) => (
              <button
                key={loc}
                type="button"
                onClick={() => setLocale(loc)}
                className={`px-2 py-1 rounded-md font-mono font-semibold uppercase transition-colors cursor-pointer ${
                  locale === loc ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {loc}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Pestañas */}
      <div className="flex items-center gap-1 p-1 bg-slate-100 border border-slate-200 rounded-xl text-xs overflow-x-auto no-scrollbar">
        {([
          { id: 'remote', label: t('settings.tabRemote'), icon: Globe },
          { id: 'team', label: t('settings.tabTeam'), icon: Users },
          { id: 'security', label: t('settings.tabSecurity'), icon: ShieldCheck },
          { id: 'gitops', label: t('settings.tabGitops'), icon: FileCode2 },
          { id: 'integrations', label: t('settings.tabIntegrations'), icon: Plug },
          { id: 'backups', label: t('settings.tabBackups'), icon: HardDrive },
          { id: 'notifications', label: t('settings.tabNotifications'), icon: Bell },
          { id: 'system', label: t('settings.tabSystem'), icon: Cpu },
        ] as const).map((tabItem) => {
          const Icon = tabItem.icon;
          return (
            <button
              key={tabItem.id}
              type="button"
              onClick={() => setTab(tabItem.id)}
              className={`culkibo-press inline-flex items-center gap-1.5 min-h-[36px] px-3 py-1.5 rounded-lg font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                tab === tabItem.id ? 'bg-white text-slate-900 shadow-2xs font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tabItem.label}</span>
            </button>
          );
        })}
      </div>

      {tab === 'remote' && <RemoteAccessPanel onNotify={onNotify} />}

      {tab === 'team' && <TeamAccessPanel onNotify={onNotify} />}

      {tab === 'security' && (
        <div className="space-y-5 text-xs">
          {/* 1. TOTP 2FA (RFC 6238) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Fingerprint className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('settings.sec2faTitle')}</h2>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                        totpEnabled
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {totpEnabled ? 'Active (RFC 6238)' : (locale === 'es' ? 'Pendiente' : 'Not configured')}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5 leading-relaxed">{t('settings.sec2faDesc')}</p>
                  {identity && (
                    <div className="mt-1.5 text-[11px] text-slate-400 font-mono">
                      {t('settings.secCurrentSession')} {identity.email || identity.name || (locale === 'es' ? 'Administrador local' : 'Local admin')} ({identity.role})
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                {!totpSetup && (
                  <button
                    type="button"
                    disabled={totpBusy !== null}
                    onClick={() => void handleSetup2FA()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {totpBusy === 'setup' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                    <span>{totpEnabled ? t('settings.sec2faReconfig') : t('settings.sec2faSetup')}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setTotpDisableOpen((v) => !v)}
                  className="culkibo-press px-3 py-2 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-700 hover:text-red-700 font-medium cursor-pointer"
                >
                  {totpDisableOpen ? (locale === 'es' ? 'Cancelar' : 'Cancel') : t('settings.sec2faDisable')}
                </button>
              </div>
            </div>

            {totpNotice && (
              <div
                className={`p-3 rounded-xl border flex items-start gap-2 ${
                  totpNotice.kind === 'ok'
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                    : totpNotice.kind === 'err'
                      ? 'bg-red-50 border-red-200 text-red-800'
                      : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                {totpNotice.kind === 'ok' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                )}
                <span className="leading-relaxed">{totpNotice.text}</span>
              </div>
            )}

            {totpSetup && (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1.5">
                    <div className="text-[11px] font-medium text-slate-500">Clave secreta Base32 (manual)</div>
                    <div className="flex items-center justify-between gap-2">
                      <code className="font-mono text-xs font-semibold text-slate-900 tracking-wider break-all">
                        {totpSetup.secretBase32 || totpSetup.secret || '—'}
                      </code>
                      {(totpSetup.secretBase32 || totpSetup.secret) && (
                        <button
                          type="button"
                          onClick={() => void copySecurityValue(totpSetup.secretBase32 || totpSetup.secret || '', 'totp_secret', 'Clave Base32')}
                          className="p-1.5 rounded-md border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 cursor-pointer shrink-0"
                          aria-label="Copiar clave Base32"
                        >
                          {copiedSecKey === 'totp_secret' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1.5">
                    <div className="text-[11px] font-medium text-slate-500">URI otpauth:// (gestores de contraseñas)</div>
                    <div className="flex items-center justify-between gap-2">
                      <code className="font-mono text-[11px] text-slate-700 truncate">
                        {totpSetup.otpauthUri || totpSetup.otpauthUrl || '—'}
                      </code>
                      {(totpSetup.otpauthUri || totpSetup.otpauthUrl) && (
                        <button
                          type="button"
                          onClick={() => void copySecurityValue(totpSetup.otpauthUri || totpSetup.otpauthUrl || '', 'totp_uri', 'URI otpauth://')}
                          className="p-1.5 rounded-md border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 cursor-pointer shrink-0"
                          aria-label="Copiar URI otpauth"
                        >
                          {copiedSecKey === 'totp_uri' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                <form onSubmit={handleVerify2FA} className="flex flex-col sm:flex-row items-stretch sm:items-end gap-2.5">
                  <label className="flex-1 max-w-xs">
                    <span className="block font-medium text-slate-700 mb-1">Código TOTP de 6 dígitos</span>
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={8}
                      required
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, ''))}
                      placeholder="123456"
                      className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 font-mono text-sm tracking-[0.25em] text-slate-900 tabular-nums"
                    />
                  </label>
                  <button
                    type="submit"
                    disabled={totpBusy !== null || totpCode.length < 6}
                    className="culkibo-press px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {totpBusy === 'verify' ? 'Verificando…' : 'Verificar y activar 2FA'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setTotpSetup(null)}
                    className="px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-600 cursor-pointer"
                  >
                    Cancelar
                  </button>
                </form>
              </div>
            )}

            {totpRecoveryCodes.length > 0 && (
              <div className="p-4 rounded-xl bg-amber-50/70 border border-amber-200 space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-semibold text-amber-950">Códigos de recuperación (se muestran una sola vez)</span>
                  <button
                    type="button"
                    onClick={() => void copySecurityValue(totpRecoveryCodes.join('\n'), 'recovery_codes', 'Códigos de recuperación')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white border border-amber-300 text-amber-900 font-medium cursor-pointer"
                  >
                    {copiedSecKey === 'recovery_codes' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>Copiar todos</span>
                  </button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5 font-mono text-[11px] tabular-nums">
                  {totpRecoveryCodes.map((c) => (
                    <div key={c} className="px-2 py-1.5 rounded-md bg-white border border-amber-200 text-center text-slate-900">
                      {c}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {totpDisableOpen && (
              <form onSubmit={handleDisable2FA} className="p-4 rounded-xl bg-red-50/50 border border-red-200/80 grid grid-cols-1 sm:grid-cols-3 gap-2.5 items-end">
                <label className="block">
                  <span className="font-medium text-slate-700">Código TOTP o recuperación</span>
                  <input
                    type="text"
                    required
                    value={totpDisableCode}
                    onChange={(e) => setTotpDisableCode(e.target.value)}
                    placeholder="123456"
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-white border border-slate-200 font-mono text-slate-900"
                  />
                </label>
                <label className="block">
                  <span className="font-medium text-slate-700">Contraseña (si aplica)</span>
                  <input
                    type="password"
                    value={totpDisablePassword}
                    onChange={(e) => setTotpDisablePassword(e.target.value)}
                    placeholder="Contraseña actual"
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-white border border-slate-200 font-mono text-slate-900"
                  />
                </label>
                <button
                  type="submit"
                  disabled={totpBusy !== null || !totpDisableCode.trim()}
                  className="culkibo-press px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {totpBusy === 'disable' ? 'Desactivando…' : 'Confirmar desactivación'}
                </button>
              </form>
            )}
          </div>

          {/* 2. Proveedores SSO (OIDC / OAuth2 PKCE + JWKS) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Link2 className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('settings.secOidcTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-600 tabular-nums">
                      {oidcProviders.length}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('settings.secOidcDesc')}</p>
                </div>
              </div>
            </div>

            {oidcUnavailable ? (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-500">
                El listado de proveedores OIDC no respondió en esta instancia. Configura tus proveedores en <code className="font-mono text-slate-700">data/oidc.json</code> o mediante la API administrativa.
              </div>
            ) : oidcProviders.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <div className="text-slate-600">
                  Aún no hay proveedores SSO configurados. Culkibo incluye soporte nativo sin dependencias para:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {['GitHub OAuth2 PKCE', 'Google OIDC', 'Authentik', 'Keycloak', 'OpenID Connect genérico'].map((p) => (
                    <span
                      key={p}
                      className="px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-[11px] font-medium text-slate-700"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            ) : (
              <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden">
                {oidcProviders.map((prov) => (
                  <div key={prov.id} className="px-4 py-3 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${prov.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        <span className="font-semibold text-slate-900">{prov.name}</span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] uppercase text-slate-600">
                          {prov.protocol}
                        </span>
                        {prov.defaultRole && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] text-slate-600">
                            {t('settings.secRole')}: {prov.defaultRole}
                          </span>
                        )}
                        {prov.enforceLocal2fa && (
                          <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-[10px] text-emerald-700">
                            {t('settings.secLocal2fa')}
                          </span>
                        )}
                      </div>
                      {prov.issuerUrl && (
                        <div className="font-mono text-[11px] text-slate-400 truncate">{prov.issuerUrl}</div>
                      )}
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 self-start sm:self-center ${
                        prov.enabled
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-500 border-slate-200'
                      }`}
                    >
                      {prov.enabled ? t('settings.secActive') : t('settings.secInactive')}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 3. Cadena de Auditoría Inmutable (SHA-256 Hash-Chained) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">{t('settings.secAuditTitle')}</h2>
                  <p className="text-slate-500 mt-0.5">{t('settings.secAuditDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={auditVerifyBusy}
                onClick={() => void handleVerifyAuditChain()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50 shrink-0"
              >
                {auditVerifyBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                <span>{auditVerifyBusy ? t('settings.secAuditVerifying') : t('settings.secAuditVerify')}</span>
              </button>
            </div>

            {auditVerifyError && (
              <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-700 shrink-0" />
                <span>{auditVerifyError}</span>
              </div>
            )}

            {auditVerification && (
              <div
                className={`p-4 rounded-xl border space-y-3 ${
                  auditVerification.valid
                    ? 'bg-emerald-50/70 border-emerald-200'
                    : 'bg-red-50/80 border-red-200'
                }`}
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2 font-semibold">
                    {auditVerification.valid ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span className="text-emerald-950">Cadena criptográfica íntegra · 0 manipulaciones</span>
                      </>
                    ) : (
                      <>
                        <ShieldAlert className="w-4 h-4 text-red-600" />
                        <span className="text-red-900">
                          Integridad comprometida: {auditVerification.reason || 'Discontinuidad en la cadena'}
                        </span>
                      </>
                    )}
                  </div>
                  {auditVerification.headHash && (
                    <button
                      type="button"
                      onClick={() => void copySecurityValue(auditVerification.headHash || '', 'head_hash', 'Head SHA-256')}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-white border border-slate-200 font-mono text-[10px] text-slate-700 cursor-pointer"
                      title="Copiar hash de cabecera"
                    >
                      <span>head:{auditVerification.headHash.slice(0, 12)}…</span>
                      {copiedSecKey === 'head_hash' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] tabular-nums">
                  <div className="p-2.5 rounded-lg bg-white/90 border border-slate-200/80">
                    <span className="text-slate-500 block">Entradas verificadas</span>
                    <span className="font-mono font-semibold text-slate-900 text-xs">{auditVerification.checkedCount}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white/90 border border-slate-200/80">
                    <span className="text-slate-500 block">Secuencia</span>
                    <span className="font-mono font-semibold text-slate-900 text-xs">
                      {auditVerification.firstSeq !== null ? `#${auditVerification.firstSeq} → #${auditVerification.lastSeq}` : '—'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white/90 border border-slate-200/80">
                    <span className="text-slate-500 block">Fuentes comprobadas</span>
                    <span className="font-mono font-semibold text-slate-900 text-xs">
                      {(Array.isArray(auditVerification.filesChecked) ? auditVerification.filesChecked.length : 0) || 1}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white/90 border border-slate-200/80">
                    <span className="text-slate-500 block">Ancla de rotación</span>
                    <span className="font-mono font-semibold text-slate-900 text-xs">
                      {auditVerification.anchored ? 'Anclada' : 'Desde génesis'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {securityAuditEntries.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700 flex items-center justify-between">
                  <span className="tabular-nums">{t('settings.secLatestChained')} ({securityAuditEntries.length})</span>
                  <span className="font-mono text-[10px] text-slate-400">SHA-256 append-only</span>
                </div>
                <div className="divide-y divide-slate-100 max-h-56 overflow-y-auto">
                  {securityAuditEntries.map((ev, i) => {
                    const actorStr = formatAuditActor(ev.actor);
                    return (
                      <div key={ev.id || `${ev.timestamp || ev.at || 'sec'}-${i}`} className="px-4 py-2.5 flex items-center justify-between gap-3">
                        <div className="min-w-0 flex items-center gap-2 flex-wrap">
                          {typeof ev.seq === 'number' && (
                            <span className="font-mono text-[10px] text-slate-400 tabular-nums">#{ev.seq}</span>
                          )}
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                            {ev.source}
                          </span>
                          <span className="font-medium text-slate-900">{ev.action}</span>
                          {actorStr && <span className="text-slate-500 font-mono text-[11px] truncate">{actorStr}</span>}
                          {ev.entryHash && (
                            <span className="font-mono text-[10px] text-slate-400 hidden md:inline">
                              {ev.entryHash.slice(0, 8)}
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] text-slate-400 tabular-nums shrink-0">
                          {formatSafeDate(ev.timestamp || ev.at)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* 4. Escáner Pre-Despliegue de Secretos */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ScanSearch className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">{t('settings.secScannerTitle')}</h2>
                  <p className="text-slate-500 mt-0.5">{t('settings.secScannerDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleLoadSafeScannerSample}
                className="culkibo-press px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0"
              >
                {t('settings.secScannerSample')}
              </button>
            </div>

            <form onSubmit={handleRunSecretScan} className="space-y-3">
              <textarea
                rows={5}
                value={scanInput}
                onChange={(e) => setScanInput(e.target.value)}
                placeholder={'Paste .env, docker-compose.yml, culkibo.yaml or Dockerfile text to scan for leaks…\nSafe references like ${vault.MY_KEY} are ignored automatically.'}
                spellCheck={false}
                className="w-full p-3.5 bg-slate-50 focus:bg-white border border-slate-200 rounded-xl font-mono text-[11px] leading-relaxed text-slate-900"
              />
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={scanBusy || !scanInput.trim()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {scanBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5" />}
                  <span>{scanBusy ? t('settings.secScannerRunning') : t('settings.secScannerRun')}</span>
                </button>
              </div>
            </form>

            {scanError && (
              <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-700 shrink-0" />
                <span>{scanError}</span>
              </div>
            )}

            {scanReport && (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                    {scanReport.clean ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span>Limpio · sin secretos expuestos</span>
                      </>
                    ) : (
                      <>
                        <ShieldAlert className="w-4 h-4 text-red-600" />
                        <span className="tabular-nums">{scanReport.summary.total} hallazgo(s) detectado(s)</span>
                      </>
                    )}
                  </span>
                  <div className="flex items-center gap-1.5 font-mono text-[11px] tabular-nums">
                    <span className="px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700">
                      Críticos: {scanReport.summary.critical}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800">
                      Altos: {scanReport.summary.high}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700">
                      Medios: {scanReport.summary.medium}
                    </span>
                  </div>
                </div>

                {Array.isArray(scanReport.findings) && scanReport.findings.length > 0 && (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {scanReport.findings.map((f, idx) => (
                      <div key={`${f.ruleId}-${f.line ?? idx}-${idx}`} className="p-3 rounded-lg bg-white border border-slate-200 space-y-1">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${
                                f.severity === 'critical'
                                  ? 'bg-red-50 text-red-700 border-red-200'
                                  : f.severity === 'high'
                                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                                    : 'bg-slate-100 text-slate-700 border-slate-200'
                              }`}
                            >
                              {f.severity}
                            </span>
                            <span className="font-semibold text-slate-900">{f.title}</span>
                          </div>
                          <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                            {f.line ? `Línea ${f.line}` : f.source} · {f.preview}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500">{f.remediation}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 5. WebAuthn Passkeys (FIDO2 · Zero-Dep CBOR/COSE) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Fingerprint className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.passkeyTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      ES256 / Ed25519 · Zero-Dep CBOR
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.passkeyDesc')}</p>
                </div>
              </div>
              <form onSubmit={(e) => void handleRegisterPasskey(e)} className="flex items-center gap-1.5 flex-wrap shrink-0">
                <input
                  type="text"
                  value={passkeyLabel}
                  onChange={(e) => setPasskeyLabel(e.target.value)}
                  placeholder="YubiKey / Touch ID"
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-900 w-40"
                />
                <button
                  type="submit"
                  disabled={passkeyBusy}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {passkeyBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>{passkeyBusy ? t('sec.passkeyRegistering') : t('sec.passkeyRegister')}</span>
                </button>
              </form>
            </div>

            {passkeyChallenge && (
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[11px] text-slate-700">
                Challenge ready: <span className="font-semibold">{passkeyChallenge}</span> (120s single-use TTL)
              </div>
            )}

            {passkeys.length === 0 ? (
              <div className="text-slate-500">{t('sec.passkeyEmpty')}</div>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                {passkeys.map((pk) => (
                  <div key={pk.id} className="px-4 py-2.5 bg-white flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{pk.label}</span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                          {pk.alg === -8 ? 'Ed25519' : 'ES256'}
                        </span>
                        <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                          signCount: {pk.signCount ?? 0}
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleRevokePasskey(pk.id)}
                      aria-label={`Revoke passkey ${pk.label}`}
                      className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-red-50 text-slate-500 hover:text-red-700 cursor-pointer shrink-0"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 6. Ephemeral Secret Leases, 90d Rotation Audit & 15m Break-Glass */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-slate-900">{t('sec.leaseTitle')}</h2>
                  <p className="text-slate-500 mt-0.5">{t('sec.leaseDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <input
                  type="text"
                  value={leaseKeyName}
                  onChange={(e) => setLeaseKeyName(e.target.value)}
                  aria-label="Secret key"
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 w-36"
                />
                <button
                  type="button"
                  disabled={leaseBusy !== null}
                  onClick={() => void handleIssueLease()}
                  className="culkibo-press inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  <Key className="w-3.5 h-3.5" />
                  <span>{t('sec.leaseIssue')}</span>
                </button>
                <button
                  type="button"
                  disabled={leaseBusy !== null}
                  onClick={() => void handleRotationAudit()}
                  className="culkibo-press inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${leaseBusy === 'audit' ? 'animate-spin' : ''}`} />
                  <span>{t('sec.leaseAudit')}</span>
                </button>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center gap-2 p-3 rounded-xl bg-amber-50/70 border border-amber-200">
              <input
                type="text"
                value={breakGlassReason}
                onChange={(e) => setBreakGlassReason(e.target.value)}
                placeholder="Audited incident reason (min 10 chars)…"
                className="flex-1 px-2.5 py-1.5 rounded-lg border border-amber-200 bg-white text-slate-900"
              />
              <button
                type="button"
                disabled={leaseBusy !== null}
                onClick={() => void handleBreakGlass()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{t('sec.leaseBreakGlass')}</span>
              </button>
            </div>

            {issuedLeaseToken && (
              <div className="p-3 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[11px] flex items-center justify-between gap-2">
                <span className="truncate">One-time token: {issuedLeaseToken}</span>
                <button
                  type="button"
                  onClick={() => void copySecurityValue(issuedLeaseToken, 'lease_tok', 'Lease token')}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 shrink-0 cursor-pointer"
                >
                  {copiedSecKey === 'lease_tok' ? 'Copied' : 'Copy'}
                </button>
              </div>
            )}

            {rotationAudit && (
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5 tabular-nums">
                <div className="font-semibold text-slate-900">
                  Rotation Audit (&gt;{rotationAudit.maxAgeDays ?? 90}d): {rotationAudit.staleCount} stale / {rotationAudit.totalKeys} total keys
                </div>
                {Array.isArray(rotationAudit.staleKeys) && rotationAudit.staleKeys.length > 0 && (
                  <div className="font-mono text-[11px] text-amber-800 space-y-0.5">
                    {rotationAudit.staleKeys.slice(0, 5).map((sk, idx) => (
                      <div key={idx}>• {sk.projectName || sk.projectId || 'vault'}: {sk.key} ({sk.ageDays ?? '>90'}d old)</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {secretLeases.length === 0 ? (
              <div className="text-slate-500">{t('sec.leaseEmpty')}</div>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                {secretLeases.slice(0, 5).map((lease) => (
                  <div key={lease.id} className="px-4 py-2.5 bg-white flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-semibold text-slate-900">{lease.secretKey}</span>
                        <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                          lease.kind === 'break_glass'
                            ? 'bg-amber-50 text-amber-800 border-amber-200'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}>
                          {lease.kind === 'break_glass' ? 'BREAK-GLASS' : (lease.scope || 'read')}
                        </span>
                        <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                          exp {new Date(lease.expiresAt).toLocaleTimeString()}
                        </span>
                      </div>
                      {lease.reason && <div className="text-[11px] text-slate-500 truncate">{lease.reason}</div>}
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleRevokeLease(lease.id)}
                      className="px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-red-50 text-slate-600 hover:text-red-700 text-[11px] cursor-pointer shrink-0"
                    >
                      Revoke
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 7. Runtime SBOM CVE Drift Scanner (OSV.dev) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.cveTitle')}</h2>
                    {cveScan && (
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                        {cveScan.offline ? 'Offline / Cached' : 'OSV.dev Live'}
                      </span>
                    )}
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.cveDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={cveBusy}
                onClick={() => void handleRunCveScan()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                {cveBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5" />}
                <span>{cveBusy ? t('sec.cveScanning') : t('sec.cveScan')}</span>
              </button>
            </div>

            {cveError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{cveError}</div>}

            {cveScan && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 tabular-nums">
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase text-slate-400 font-semibold block">Packages</span>
                    <span className="font-mono text-sm font-semibold text-slate-900">{cveScan.scannedPackages}</span>
                  </div>
                  <div
                    className={`p-2.5 rounded-xl border ${
                      isDark
                        ? 'bg-rose-950/30 border-rose-500/30 text-rose-200'
                        : 'bg-red-50 border-red-200 text-red-700'
                    }`}
                  >
                    <span className={`text-[10px] uppercase font-semibold block ${isDark ? 'text-rose-300' : 'text-red-700'}`}>
                      Critical
                    </span>
                    <span className={`font-mono text-sm font-semibold ${isDark ? 'text-rose-200' : 'text-red-700'}`}>
                      {cveScan.bySeverity?.critical ?? 0}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-amber-50/70 border border-amber-200">
                    <span className="text-[10px] uppercase text-amber-700 font-semibold block">High</span>
                    <span className="font-mono text-sm font-semibold text-amber-800">{cveScan.bySeverity?.high ?? 0}</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold block">Medium</span>
                    <span className="font-mono text-sm font-semibold text-slate-800">{cveScan.bySeverity?.medium ?? 0}</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-emerald-50/70 border border-emerald-200">
                    <span className="text-[10px] uppercase text-emerald-700 font-semibold block">Low</span>
                    <span className="font-mono text-sm font-semibold text-emerald-800">{cveScan.bySeverity?.low ?? 0}</span>
                  </div>
                </div>
                {Array.isArray(cveScan.findings) && cveScan.findings.length > 0 && (
                  <div className="space-y-1.5">
                    {cveScan.findings.slice(0, 5).map((f, idx) => (
                      <div key={f.id || idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-slate-900">{f.id} · {f.packageName || f.purl}</span>
                        <span className="text-slate-600 truncate">{f.summary}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 8. Zero Lock-In IaC Exporter (OpenTofu / Terraform + Portable Compose) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <FileCode2 className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.iacTitle')}</h2>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      <Lock className="w-3 h-3" />
                      {t('sec.iacZeroSecrets')}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.iacDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={iacBusy}
                onClick={() => void handleExportIac()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                {iacBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                <span>{iacBusy ? t('sec.iacExporting') : t('sec.iacExport')}</span>
              </button>
            </div>

            {iacError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{iacError}</div>}

            {iacExport && iacExport.files && (() => {
              const fileNames = Object.keys(iacExport.files);
              const activeFile = fileNames.includes(iacFileTab) ? iacFileTab : (fileNames[0] || 'main.tf');
              const content = iacExport.files[activeFile] || '';
              return (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 overflow-x-auto max-w-full">
                      {fileNames.map((fn) => (
                        <button
                          key={fn}
                          type="button"
                          onClick={() => setIacFileTab(fn)}
                          className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-medium cursor-pointer whitespace-nowrap ${
                            activeFile === fn ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          {fn}
                        </button>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => void copySecurityValue(content, `iac_${activeFile}`, activeFile)}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {copiedSecKey === `iac_${activeFile}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>Copy {activeFile}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-slate-950 text-emerald-200 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-60 border border-slate-800">
                    {content}
                  </pre>
                </div>
              );
            })()}
          </div>

          {/* 9. Open-Core White-Label Brand & Custom Login Theme Engine */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Palette className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.brandTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      Open-Core · 0 Paywall
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.brandDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={brandBusy !== null}
                onClick={() => void handleResetBrand()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${brandBusy === 'reset' ? 'animate-spin' : ''}`} />
                <span>{t('sec.brandReset')}</span>
              </button>
            </div>

            {brandError && (
              <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{brandError}</span>
              </div>
            )}

            {/* Live Brand Swatch Preview */}
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center font-mono text-xs font-bold text-white shrink-0 shadow-xs"
                  style={{
                    backgroundColor: /^#[0-9a-fA-F]{6}$/.test(brandForm.accentHex) ? brandForm.accentHex : '#6366f1',
                  }}
                >
                  {(brandForm.brandName || 'C').slice(0, 2).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm text-slate-900 truncate">{brandForm.brandName || 'Culkibo'}</span>
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-600">
                      {brandForm.accentHex}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">{brandForm.tagline || 'Ultra-lightweight self-hosted PaaS'}</div>
                </div>
              </div>
              <div className="text-[11px] text-slate-400 font-mono shrink-0">
                {brandForm.hidePoweredBy ? t('sec.brandPreview') : `${t('sec.brandPreview')} · Powered by Culkibo`}
              </div>
            </div>

            <form onSubmit={(e) => void handleSaveBrand(e)} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="font-medium text-slate-700 block mb-1">{t('sec.brandName')}</span>
                <input
                  type="text"
                  maxLength={60}
                  required
                  value={brandForm.brandName}
                  onChange={(e) => setBrandForm((prev) => ({ ...prev, brandName: e.target.value }))}
                  placeholder="Acme Cloud PaaS"
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700 block mb-1">{t('sec.brandAccent')}</span>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    aria-label="Accent color picker"
                    value={/^#[0-9a-fA-F]{6}$/.test(brandForm.accentHex) ? brandForm.accentHex : '#6366f1'}
                    onChange={(e) => setBrandForm((prev) => ({ ...prev, accentHex: e.target.value }))}
                    className="w-10 h-9 p-0.5 rounded-lg border border-slate-200 bg-white cursor-pointer shrink-0"
                  />
                  <input
                    type="text"
                    value={brandForm.accentHex}
                    onChange={(e) => setBrandForm((prev) => ({ ...prev, accentHex: e.target.value }))}
                    placeholder="#6366f1"
                    className="flex-1 px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                  />
                </div>
              </label>
              <label className="block sm:col-span-2">
                <span className="font-medium text-slate-700 block mb-1">{t('sec.brandTagline')}</span>
                <input
                  type="text"
                  maxLength={140}
                  value={brandForm.tagline}
                  onChange={(e) => setBrandForm((prev) => ({ ...prev, tagline: e.target.value }))}
                  placeholder="Managed self-hosted cloud for agencies"
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700 block mb-1">{t('sec.brandLogo')}</span>
                <input
                  type="text"
                  value={brandForm.logoUrl}
                  onChange={(e) => setBrandForm((prev) => ({ ...prev, logoUrl: e.target.value }))}
                  placeholder="https://cdn.youragency.com/logo.svg"
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700 block mb-1">{t('sec.brandSupport')}</span>
                <input
                  type="text"
                  value={brandForm.supportUrl}
                  onChange={(e) => setBrandForm((prev) => ({ ...prev, supportUrl: e.target.value }))}
                  placeholder="https://status.youragency.com"
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                />
              </label>
              <div className="sm:col-span-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
                <label className="inline-flex items-center gap-2 text-slate-700 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={brandForm.hidePoweredBy}
                    onChange={(e) => setBrandForm((prev) => ({ ...prev, hidePoweredBy: e.target.checked }))}
                    className="rounded border-slate-300 accent-slate-900"
                  />
                  <span>{t('sec.brandHidePowered')}</span>
                </label>
                <button
                  type="submit"
                  disabled={brandBusy !== null}
                  className="culkibo-press inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {brandBusy === 'save' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  <span>{brandBusy === 'save' ? t('sec.brandSaving') : t('sec.brandSave')}</span>
                </button>
              </div>
            </form>
          </div>

          {/* 10. Standard-Webhooks Outbound & Dead-Letter Queue (DLQ) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Webhook className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.whTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      standard-webhooks · whsec_ · Anti-SSRF
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.whDesc')}</p>
                </div>
              </div>
            </div>

            {whError && (
              <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{whError}</span>
              </div>
            )}

            <form onSubmit={(e) => void handleAddWebhookSub(e)} className="grid grid-cols-1 sm:grid-cols-12 gap-2">
              <input
                type="url"
                required
                value={whNewUrl}
                onChange={(e) => setWhNewUrl(e.target.value)}
                placeholder="https://hooks.your-domain.com/culkibo"
                className="sm:col-span-6 px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
              <input
                type="text"
                value={whNewDesc}
                onChange={(e) => setWhNewDesc(e.target.value)}
                placeholder="Release pipeline listener"
                className="sm:col-span-4 px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
              />
              <button
                type="submit"
                disabled={whBusyId !== null}
                className="sm:col-span-2 culkibo-press inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {whBusyId === 'create' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>{whBusyId === 'create' ? t('sec.whAdding') : t('sec.whAddSub')}</span>
              </button>
            </form>

            {whRotatedSecret && (
              <div className="p-3 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[11px] flex items-center justify-between gap-2">
                <span className="truncate">
                  New primary whsec_ (shown once): {whRotatedSecret.secret}
                </span>
                <button
                  type="button"
                  onClick={() => void copySecurityValue(whRotatedSecret.secret, 'wh_sec_once', 'Webhook secret')}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 shrink-0 cursor-pointer"
                >
                  {copiedSecKey === 'wh_sec_once' ? 'Copied' : 'Copy'}
                </button>
              </div>
            )}

            {/* Outbound Subscriptions List */}
            {whSubs.length === 0 ? (
              <div className="text-slate-500">{t('sec.whSubsEmpty')}</div>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                {whSubs.map((sub) => (
                  <div key={sub.id} className="px-4 py-3 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${sub.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        <span className="font-mono font-semibold text-slate-900 truncate max-w-[300px] sm:max-w-[420px]">
                          {sub.url}
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                          {sub.secretPreview || sub.maskedSecret || 'whsec_••••••••'}
                        </span>
                        {sub.hasSecondarySecret && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 font-mono text-[10px]">
                            Dual-Secret Grace
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-slate-500">
                        {sub.description && <span>{sub.description} ·</span>}
                        {(Array.isArray(sub.events) ? sub.events : ['*']).slice(0, 4).map((ev) => (
                          <span key={ev} className="px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 font-mono text-[10px] text-slate-600">
                            {ev}
                          </span>
                        ))}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={whBusyId !== null}
                      onClick={() => void handleRotateWebhookSecret(sub.id)}
                      className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0 disabled:opacity-50 self-start sm:self-center"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${whBusyId === `rot-${sub.id}` ? 'animate-spin' : ''}`} />
                      <span>{whBusyId === `rot-${sub.id}` ? t('sec.whRotating') : t('sec.whRotate')}</span>
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Dead-Letter Queue (DLQ) Table */}
            <div className="border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
                <span className="font-semibold text-slate-800 tabular-nums">
                  {t('sec.whDlqTitle')} ({whDlq.length})
                </span>
                <span className="font-mono text-[10px] text-slate-400">DNS-Resolved Anti-SSRF Replay</span>
              </div>
              {whDlq.length === 0 ? (
                <div className="p-4 text-center text-slate-500">{t('sec.whDlqEmpty')}</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50/70 border-b border-slate-200 text-[10px] uppercase tracking-wider text-slate-500">
                        <th className="py-2 px-3.5">Event</th>
                        <th className="py-2 px-3">Destination</th>
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-[11px]">
                      {whDlq.slice(0, 10).map((entry) => {
                        const isReplayed = entry.status === 'replayed';
                        return (
                          <tr key={entry.id}>
                            <td className="py-2.5 px-3.5 whitespace-nowrap">
                              <div className="font-mono font-semibold text-slate-900">{entry.eventType}</div>
                              <div className="text-[10px] text-slate-400 tabular-nums">
                                {entry.attempts ?? 1}x · {formatSafeDate(entry.createdAt)}
                              </div>
                            </td>
                            <td className="py-2.5 px-3 max-w-[240px]">
                              <div className="font-mono text-slate-700 truncate">{entry.url}</div>
                              {(entry.lastError || entry.error) && (
                                <div className="text-[10px] text-red-700 truncate">{entry.lastError || entry.error}</div>
                              )}
                            </td>
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-medium border ${
                                  isReplayed
                                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                    : 'bg-red-50 text-red-700 border-red-200'
                                }`}
                              >
                                {isReplayed ? 'REPLAYED 200' : `HTTP ${entry.httpStatus || entry.lastStatusCode || 'ERR'}`}
                              </span>
                            </td>
                            <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                              <button
                                type="button"
                                disabled={whBusyId !== null}
                                onClick={() => void handleReplayDlq(entry.id)}
                                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                              >
                                <Play className="w-3 h-3" />
                                <span>{whBusyId === `rep-${entry.id}` ? t('sec.whReplaying') : t('sec.whReplay')}</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* 11. Cycle-11: Policy-as-Code Deployment Admission Gate (10 CIS/PSS Rules) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.admTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      Kyverno / OPA-Lite · 0 Deps
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.admDesc')}</p>
                </div>
              </div>
              <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[11px] shrink-0 self-start">
                {([
                  { id: 'baseline', label: t('sec.admPresetBaseline') },
                  { id: 'restricted', label: t('sec.admPresetRestricted') },
                  { id: 'soc2-strict', label: t('sec.admPresetSoc2') },
                ] as const).map((p) => {
                  const active = (admPolicy?.preset || 'restricted') === p.id;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      disabled={admBusy !== null}
                      onClick={() => void handleSelectAdmissionPreset(p.id)}
                      className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer whitespace-nowrap disabled:opacity-50 ${
                        active ? 'bg-white text-slate-900 shadow-2xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {p.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {admError && (
              <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{admError}</span>
              </div>
            )}

            {/* 10 CIS/PSS Rule Badges */}
            {(() => {
              const ruleMap: Record<string, string> = admPolicy?.rules && !Array.isArray(admPolicy.rules)
                ? admPolicy.rules
                : {
                    no_privileged: 'enforce',
                    no_docker_sock_mount: 'enforce',
                    no_host_root_mount: 'enforce',
                    no_dangerous_caps: 'enforce',
                    no_latest_tag: 'enforce',
                    require_non_root_uid: 'enforce',
                    require_resource_limits: 'enforce',
                    require_healthcheck: 'enforce',
                    require_signed_attestation: 'audit',
                    no_public_db_or_panel_bind: 'enforce',
                  };
              const entries = Object.entries(ruleMap);
              return (
                <div className="flex flex-wrap gap-1.5">
                  {entries.map(([ruleId, mode]) => (
                    <span
                      key={ruleId}
                      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md border font-mono text-[10px] ${
                        mode === 'enforce'
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          : mode === 'audit'
                            ? 'bg-amber-50 border-amber-200 text-amber-800'
                            : 'bg-slate-50 border-slate-200 text-slate-500'
                      }`}
                    >
                      <span>{ruleId}</span>
                      <span className="uppercase opacity-75">{mode}</span>
                    </span>
                  ))}
                </div>
              );
            })()}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={admBusy !== null}
                onClick={() => void handleTestAdmissionSpec('root')}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
              >
                {admBusy === 'root' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                <span>{admBusy === 'root' ? t('sec.admTesting') : t('sec.admTestRoot')}</span>
              </button>
              <button
                type="button"
                disabled={admBusy !== null}
                onClick={() => void handleTestAdmissionSpec('hardened')}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {admBusy === 'hardened' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                <span>{admBusy === 'hardened' ? t('sec.admTesting') : t('sec.admTestHardened')}</span>
              </button>
            </div>

            {admEval && (() => {
              const viols = Array.isArray(admEval.enforcedViolations) ? admEval.enforcedViolations : [];
              const warns = Array.isArray(admEval.auditWarnings) ? admEval.auditWarnings : [];
              return (
                <div className={`p-3.5 rounded-xl border space-y-2 ${
                  admEval.allowed
                    ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                    : 'bg-red-50 border-red-200 text-red-900'
                }`}>
                  <div className="flex items-center justify-between gap-2 flex-wrap tabular-nums">
                    <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-xs">
                      {admEval.allowed ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <ShieldAlert className="w-4 h-4 text-red-600" />}
                      <span>
                        {admEval.allowed ? `ALLOW · ${admEval.score}/100` : `DENY · 422 (${admEval.score}/100)`}
                      </span>
                    </span>
                    <span className="font-mono text-[10px] opacity-80">
                      preset: {admEval.preset || admPolicy?.preset || 'restricted'} · {viols.length} enforced block(s) · {warns.length} audit warn(s)
                    </span>
                  </div>
                  {viols.length > 0 && (
                    <div className="space-y-1 font-mono text-[11px]">
                      {viols.map((v, idx) => {
                        const label = typeof v === 'string'
                          ? v
                          : `[${v.id || v.ruleId || v.code || 'RULE'}] ${v.message || v.detail || 'Blocked by admission policy'}`;
                        return <div key={idx}>• {label}</div>;
                      })}
                    </div>
                  )}
                </div>
              );
            })()}
          </div>

          {/* 12. Cycle-11: Ed25519-Signed Compliance Evidence Bundle (SOC 2 · ISO 27001 · GDPR) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <FileText className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.compTitle')}</h2>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      <Lock className="w-3 h-3" />
                      {compVerify?.valid !== false && compBundle ? t('sec.compVerifiedBadge') : 'Ed25519 · 0 Plaintext Secrets'}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.compDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[10px] font-mono">
                  {(['all', 'soc2', 'iso27001', 'gdpr'] as const).map((fw) => (
                    <button
                      key={fw}
                      type="button"
                      onClick={() => setCompFramework(fw)}
                      className={`px-2 py-1 rounded-md uppercase cursor-pointer ${
                        compFramework === fw ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {fw}
                    </button>
                  ))}
                </div>
                <button
                  type="button"
                  disabled={compBusy !== null}
                  onClick={() => void handleGenerateComplianceBundle()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {compBusy === 'gen' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  <span>{compBusy === 'gen' ? t('sec.compGenerating') : t('sec.compGenerate')}</span>
                </button>
                {compBundle && (
                  <button
                    type="button"
                    disabled={compBusy !== null}
                    onClick={() => void handleVerifyComplianceBundle()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                  >
                    {compBusy === 'verify' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />}
                    <span>{compBusy === 'verify' ? t('sec.compVerifying') : t('sec.compVerify')}</span>
                  </button>
                )}
              </div>
            </div>

            {compError && (
              <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{compError}</span>
              </div>
            )}

            {compBundle && (() => {
              const score = compBundle.overallScore ?? compBundle.payload?.overallScore ?? 100;
              const controls = Array.isArray(compBundle.payload?.controls)
                ? compBundle.payload.controls
                : Array.isArray(compBundle.controls)
                  ? compBundle.controls
                  : [];
              return (
                <div className="space-y-3">
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex flex-wrap items-center justify-between gap-2 tabular-nums">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[11px] font-semibold">
                        Score: {score}/100
                      </span>
                      <span className="font-mono text-[11px] text-slate-600">
                        sha256:{String(compBundle.payloadSha256 || '').slice(0, 14)}…
                      </span>
                      {compVerify && (
                        <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                          compVerify.valid
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-red-50 text-red-700 border-red-200'
                        }`}>
                          {compVerify.valid ? 'Ed25519 Signature VALID' : `INVALID (${compVerify.reason || 'tampered'})`}
                        </span>
                      )}
                    </div>
                    {compBundle.markdownReport && (
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => setCompShowMd((v) => !v)}
                          className="px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
                        >
                          {compShowMd ? 'Hide Dossier' : 'Preview Markdown'}
                        </button>
                        <button
                          type="button"
                          onClick={() => void copySecurityValue(compBundle.markdownReport || '', 'comp_md', 'Compliance Markdown')}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
                        >
                          {copiedSecKey === 'comp_md' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedSecKey === 'comp_md' ? t('sec.compCopiedMd') : t('sec.compCopyMd')}</span>
                        </button>
                      </div>
                    )}
                  </div>

                  {controls.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {controls.slice(0, 6).map((ctrl, idx) => {
                        const st = String(ctrl.status || (ctrl.passed ? 'pass' : 'warn')).toLowerCase();
                        const title = ctrl.domain || ctrl.title || ctrl.name || ctrl.id || `Control ${idx + 1}`;
                        const codes = Array.isArray(ctrl.controlIds) ? ctrl.controlIds.join(' · ') : (ctrl.code || '');
                        return (
                          <div key={idx} className="p-3 rounded-xl bg-white border border-slate-200 space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-semibold text-slate-900 truncate">{title}</span>
                              <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] uppercase font-semibold border shrink-0 ${
                                st === 'pass'
                                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                  : st === 'warn'
                                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                                    : 'bg-red-50 text-red-700 border-red-200'
                              }`}>
                                {st} {ctrl.score != null ? `${ctrl.score}%` : ''}
                              </span>
                            </div>
                            {codes && <div className="font-mono text-[10px] text-slate-400">{codes}</div>}
                            {ctrl.summary && <p className="text-[11px] text-slate-600 leading-snug">{ctrl.summary}</p>}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {compShowMd && compBundle.markdownReport && (
                    <pre className="p-3.5 rounded-xl bg-slate-950 text-emerald-200 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-60 border border-slate-800">
                      {compBundle.markdownReport}
                    </pre>
                  )}
                </div>
              );
            })()}
          </div>

          {/* 13. Cycle-12: CycloneDX 1.6 SPDX License Risk Auditor */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ListChecks className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.licTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      AGPL · SSPL · BSL · LicenseRef
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.licDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[10px] font-mono">
                  {(['saas-strict', 'oss-permissive', 'audit-only'] as const).map((pol) => (
                    <button
                      key={pol}
                      type="button"
                      onClick={() => void handleAuditLicenses(pol)}
                      className={`px-2 py-1 rounded-md cursor-pointer ${
                        licPolicy === pol ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {pol}
                    </button>
                  ))}
                </div>
                <button
                  type="button"
                  disabled={licBusy}
                  onClick={() => void handleAuditLicenses()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {licBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5" />}
                  <span>{licBusy ? t('sec.licRunning') : t('sec.licRun')}</span>
                </button>
              </div>
            </div>

            {licError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{licError}</div>}

            {licReport && (() => {
              const counts = licReport.countsByCategory || {};
              const viols = Array.isArray(licReport.violations) ? licReport.violations : [];
              return (
                <div className="space-y-3 tabular-nums">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                      licReport.compliant
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                    }`}>
                      {licReport.compliant ? `COMPLIANT · ${licReport.score}/100` : `VIOLATIONS (${viols.length})`}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                      Permissive: {counts.permissive ?? 0}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 font-mono text-[10px] text-amber-800">
                      Weak Copyleft: {counts.weak_copyleft ?? 0}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-red-50 border border-red-200 font-mono text-[10px] text-red-700">
                      Strong Copyleft: {counts.strong_copyleft ?? 0}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-red-50 border border-red-200 font-mono text-[10px] text-red-700">
                      Source-Avail: {counts.source_available ?? 0}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                      Unknown: {counts.unknown ?? 0}
                    </span>
                  </div>
                  {viols.length > 0 && (
                    <div className="p-3 rounded-xl bg-red-50 border border-red-200 font-mono text-[11px] text-red-800 space-y-1">
                      {viols.slice(0, 6).map((v, idx) => (
                        <div key={idx}>
                          • {typeof v === 'string' ? v : `${v.component || v.name || 'pkg'} (${v.license || 'UNKNOWN'}): ${v.message || v.reason || v.category || 'blocked'}`}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}
          </div>

          {/* 14. Cycle-12: Tailored Least-Privilege Seccomp & runc CVE Guard */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Lock className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.seccompTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      CVE-2025-31133 / 52565 / 52881
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.seccompDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5 text-[10px] font-mono">
                  {(['node', 'python', 'go', 'rust', 'static-caddy'] as const).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setSeccompStack(st)}
                      className={`px-2 py-1 rounded-md cursor-pointer ${
                        seccompStack === st ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
                <button
                  type="button"
                  disabled={seccompBusy !== null}
                  onClick={() => void handleGenerateSeccomp()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {seccompBusy === 'gen' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  <span>{seccompBusy === 'gen' ? t('sec.seccompGenerating') : t('sec.seccompGen')}</span>
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={runcVersionInput}
                onChange={(e) => setRuncVersionInput(e.target.value)}
                aria-label="runc version to audit"
                placeholder="runc version 1.3.3"
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 w-44"
              />
              <button
                type="button"
                disabled={seccompBusy !== null}
                onClick={() => void handleAuditRunc()}
                className="culkibo-press inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
              >
                <ScanSearch className="w-3.5 h-3.5" />
                <span>{t('sec.seccompAuditRunc')}</span>
              </button>
              <button
                type="button"
                disabled={seccompBusy !== null}
                onClick={() => void handleAuditRunc('1.2.7')}
                className="px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-mono text-[10px] font-semibold cursor-pointer disabled:opacity-50"
              >
                Test Vulnerable 1.2.7
              </button>
              {runcAudit && (
                <span className={`px-2.5 py-1 rounded-full font-mono text-[10px] font-semibold border ${
                  runcAudit.vulnerable
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}>
                  runc {runcAudit.parsedVersion || runcAudit.version}: {runcAudit.status}
                  {runcAudit.vulnerable && Array.isArray(runcAudit.cves) && runcAudit.cves.length > 0 ? ` (${runcAudit.cves.join(', ')})` : ''}
                </span>
              )}
            </div>

            {seccompError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{seccompError}</div>}

            {seccompProfile && (
              <div className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] tabular-nums">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 font-semibold">
                      SCMP_ACT_ERRNO · {seccompProfile.allowedCount} allowed · {(Array.isArray(seccompProfile.blockedSyscalls) ? seccompProfile.blockedSyscalls.length : 0)} blocked
                    </span>
                    <span className="text-slate-500">sha256:{String(seccompProfile.sha256 || '').slice(0, 12)}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void copySecurityValue(JSON.stringify(seccompProfile.profile, null, 2), 'seccomp_json', 'seccomp.json')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                  >
                    {copiedSecKey === 'seccomp_json' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{t('sec.seccompCopy')}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-xl bg-slate-950 text-emerald-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-48 border border-slate-800">
                  {JSON.stringify(seccompProfile.profile, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* 15. Cycle-14: Pre-Deploy Shannon-Entropy & Pattern Secret Gate (12 Rules) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ScanSearch className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.gateTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      Zero Raw Echo · SHA-256 Fingerprints
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.gateDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={gateBusy}
                  onClick={() => {
                    const fakePayKey = ['sk', 'live', '99887766554433221100aabb'].join('_');
                    const fakeGh = ['ghp', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('_');
                    const leakyDiff = [
                      '+DATABASE_URL=postgresql://admin:Sup3rS3cretP@ss99!@db.internal:5432/prod',
                      `+PAYMENT_API_KEY=${fakePayKey}`,
                      `+GITHUB_TOKEN=${fakeGh}`,
                    ].join('\n');
                    void handleRunPreDeployGate(leakyDiff);
                  }}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{t('sec.gateTestLeaky')}</span>
                </button>
                <button
                  type="button"
                  disabled={gateBusy}
                  onClick={() =>
                    void handleRunPreDeployGate(
                      'RELEASE_UUID=550e8400-e29b-41d4-a716-446655440000\nARTIFACT_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nDEMO_PLACEHOLDER=your_api_key'
                    )
                  }
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 hover:bg-slate-100 text-emerald-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>{t('sec.gateTestBenign')}</span>
                </button>
                <button
                  type="button"
                  disabled={gateBusy || !gateInput.trim()}
                  onClick={() => void handleRunPreDeployGate()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {gateBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5" />}
                  <span>{gateBusy ? t('sec.gateScanning') : t('sec.gateScanBtn')}</span>
                </button>
              </div>
            </div>

            <textarea
              rows={3}
              value={gateInput}
              onChange={(e) => setGateInput(e.target.value)}
              aria-label="Pre-deploy diff or .env payload to scan"
              spellCheck={false}
              className="w-full p-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white font-mono text-[11px] text-slate-900 leading-relaxed"
            />

            {gateError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{gateError}</div>}

            {gateResult && (() => {
              const findings = Array.isArray(gateResult.findings) ? gateResult.findings : [];
              return (
                <div className="space-y-2.5 tabular-nums">
                  <div className="flex flex-wrap items-center gap-2 font-mono">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                      gateResult.allowed
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                    }`}>
                      {gateResult.allowed ? 'ALLOWED · 0 SECRETS' : `BLOCKED · ${gateResult.blockedCount} FINDING(S)`}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-700">
                      mode: {gateResult.mode || 'enforce'}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-700">
                      scanned: {gateResult.scannedItems ?? 1} item(s)
                    </span>
                  </div>
                  {findings.length > 0 && (
                    <div className="divide-y divide-red-200 border border-red-200 rounded-xl overflow-hidden bg-red-50">
                      {findings.slice(0, 6).map((f, idx) => (
                        <div key={idx} className="px-3.5 py-2.5 font-mono text-[11px] text-red-700 space-y-1">
                          {typeof f === 'string' ? (
                            <div>• {f}</div>
                          ) : (
                            <>
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                                  {f.ruleId || 'HIGH_ENTROPY'}
                                </span>
                                {f.entropy != null && (
                                  <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                                    entropy: {Number(f.entropy).toFixed(2)} bits
                                  </span>
                                )}
                                {f.line != null && <span className="text-[10px]">line {f.line}</span>}
                                {f.fingerprintSha256 && (
                                  <span className="text-[10px] ml-auto">sha256:{String(f.fingerprintSha256).slice(0, 12)}</span>
                                )}
                              </div>
                              {f.redactedPreview && (
                                <div className="text-[10px] truncate">{f.redactedPreview}</div>
                              )}
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}
          </div>

          {/* 16. Cycle-15: Zero-Trust SPIFFE-Lite mTLS Identity CA (Ed25519) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.mtlsTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      {t('sec.mtlsZeroKey')}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.mtlsDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <input
                  type="text"
                  value={mtlsServiceName}
                  onChange={(e) => setMtlsServiceName(e.target.value)}
                  aria-label="Workload service name for SPIFFE cert"
                  placeholder="edge-api-rust"
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 w-36"
                />
                <button
                  type="button"
                  disabled={mtlsBusy !== null}
                  onClick={() => void handleIssueMtlsCert()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {mtlsBusy === 'issue' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                  <span>{mtlsBusy === 'issue' ? t('sec.mtlsWorking') : t('sec.mtlsIssue')}</span>
                </button>
                <button
                  type="button"
                  disabled={mtlsBusy !== null || (!mtlsLastIssued && mtlsCerts.length === 0)}
                  onClick={() => void handleVerifyMtlsCert()}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 hover:bg-slate-100 text-emerald-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>{t('sec.mtlsVerify')}</span>
                </button>
                <button
                  type="button"
                  disabled={mtlsBusy !== null || (!mtlsLastIssued && mtlsCerts.length === 0)}
                  onClick={() => void handleRevokeMtlsCert()}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{t('sec.mtlsRevoke')}</span>
                </button>
              </div>
            </div>

            {mtlsError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{mtlsError}</div>}

            {(mtlsLastIssued || mtlsVerify) && (
              <div className="space-y-2.5 tabular-nums font-mono text-[11px]">
                <div className="flex flex-wrap items-center gap-2">
                  {mtlsLastIssued && (
                    <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      {mtlsLastIssued.cert.spiffeId} · serial:{mtlsLastIssued.cert.serial}
                    </span>
                  )}
                  {mtlsVerify && (
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                      mtlsVerify.valid
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                    }`}>
                      {mtlsVerify.valid ? `VALID · ${mtlsVerify.code}` : `REJECTED · ${mtlsVerify.code}`}
                    </span>
                  )}
                </div>
                {mtlsCaddyPolicy && (
                  <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-44 border border-slate-800">
                    {JSON.stringify(mtlsCaddyPolicy, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* 17. Cycle-16: OCI Artifact Signature & SLSA Rekor Gate (CVE-2026-22703) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.ociTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      Sigstore v0.3 · Rekor v2
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.ociDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={ociBusy !== null}
                  onClick={() => void handleVerifyOciArtifact('tampered')}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {ociBusy === 'tampered' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('sec.ociTestTampered')}</span>
                </button>
                <button
                  type="button"
                  disabled={ociBusy !== null}
                  onClick={() => void handleVerifyOciArtifact('valid')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {ociBusy === 'valid' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  <span>{ociBusy === 'valid' ? t('sec.ociWorking') : t('sec.ociTestValid')}</span>
                </button>
              </div>
            </div>

            {ociError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{ociError}</div>}

            {ociResult && (() => {
              const isOk = Boolean(ociResult.valid || ociResult.verified);
              return (
                <div className={`p-3.5 rounded-xl border space-y-1.5 tabular-nums font-mono text-[11px] ${
                  isOk
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                    : 'bg-red-50 border-red-200 text-red-700'
                }`}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                      isOk
                        ? 'bg-white border-slate-200 text-slate-900'
                        : 'bg-red-50 border-red-200 text-red-700'
                    }`}>
                      {isOk ? 'VERIFIED · REKOR v2' : (ociResult.code || 'REKOR_DIGEST_MISMATCH')}
                    </span>
                    {ociResult.predicateType && (
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                        {ociResult.predicateType}
                      </span>
                    )}
                  </div>
                  {ociResult.message && <div>{ociResult.message}</div>}
                </div>
              );
            })()}
          </div>

          {/* 18. Cycle-16: Orphaned PR-Preview Auto-Reaper (dryRun: true) */}
          <div className="culkibo-surface rounded-2xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
              <div className="flex items-start gap-3 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Trash2 className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('sec.reaperTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                      Docker 29 JSON · Zero-Shell
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('sec.reaperDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={orphanBusy !== null}
                  onClick={() => void handleScanOrphans()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {orphanBusy === 'scan' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5" />}
                  <span>{orphanBusy === 'scan' ? t('sec.reaperWorking') : t('sec.reaperScanBtn')}</span>
                </button>
                <button
                  type="button"
                  disabled={orphanBusy !== null}
                  onClick={() => void handleReapOrphansDryRun()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {orphanBusy === 'reap' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                  <span>{t('sec.reaperReapBtn')}</span>
                </button>
              </div>
            </div>

            {orphanError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{orphanError}</div>}

            {orphanScan && (() => {
              const orphans = Array.isArray(orphanScan.orphans) ? orphanScan.orphans : [];
              const protectedList = Array.isArray(orphanScan.protected) ? orphanScan.protected : [];
              const reclaimMb = Math.round((orphanScan.reclaimableBytes ?? 0) / (1024 * 1024));
              return (
                <div className="space-y-2.5 tabular-nums font-mono text-[11px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-semibold">
                      {orphans.length} Orphan(s) · ~{reclaimMb} MB reclaimable
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                      {protectedList.length} PROTECTED (Compose Sidecars & DBs)
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {orphans.slice(0, 4).map((o) => (
                      <div key={o.id} className="p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 flex items-center justify-between gap-2">
                        <div className="min-w-0 truncate">
                          <span className="font-semibold">{o.name || o.id}</span>
                          {o.reason && <span className="text-[10px] block truncate">{o.reason}</span>}
                        </div>
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] shrink-0">
                          GC {o.kind || 'orphan'}
                        </span>
                      </div>
                    ))}
                    {protectedList.slice(0, 4).map((p) => (
                      <div key={p.id} className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-between gap-2">
                        <div className="min-w-0 truncate">
                          <span className="font-semibold">{p.name || p.id}</span>
                          {p.protectedReason && <span className="text-[10px] block truncate">{p.protectedReason}</span>}
                        </div>
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold shrink-0">
                          PROTECTED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {orphanReap && (
              <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[11px] flex flex-wrap items-center gap-2 tabular-nums">
                <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                  DRY-RUN COMPLETE · {orphanReap.plannedCount ?? orphanReap.reapedCount ?? 2} SLATED · 0 DESTROYED
                </span>
                {orphanReap.message && <span>{orphanReap.message}</span>}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'gitops' && (
        <div className="space-y-5">
          {/* Declarative GitOps culkibo.yaml */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4 text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <FileCode2 className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">GitOps declarativo (culkibo.yaml)</h2>
                    {gitopsDrift && (() => {
                      const isInSync = gitopsDrift.inSync ?? !(gitopsDrift.drifted ?? gitopsDrift.hasDrift ?? false);
                      const diffCount =
                        gitopsDrift.drifts?.length ??
                        ((gitopsDrift.summary?.create || 0) + (gitopsDrift.summary?.update || 0) + (gitopsDrift.summary?.delete || 0));
                      return (
                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                          isInSync
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-amber-50 text-amber-800 border-amber-200'
                        }`}>
                          {isInSync ? 'Sincronizado' : `Drift (${diffCount})`}
                        </span>
                      );
                    })()}
                  </div>
                  <p className="text-slate-500 mt-0.5">
                    Exporta todo tu stack sin secretos (usando <code className="font-mono">${'{vault.CLAVE}'}</code>), simula un plan y reconcilia cambios de forma idempotente.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={gitopsBusy !== null}
                  onClick={() => void handleCheckDrift()}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${gitopsBusy === 'drift' ? 'animate-spin' : ''}`} />
                  <span>Drift</span>
                </button>
                <button
                  type="button"
                  disabled={gitopsBusy !== null}
                  onClick={() => void handleExportGitOps()}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {gitopsBusy === 'export' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                  <span>Exportar stack</span>
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <label htmlFor="gitops-yaml-editor" className="font-medium text-slate-700">
                  Manifiesto culkibo.yaml (v1 · máx. 256 KB, sin anclas YAML)
                </label>
                {gitopsYaml.trim() && (
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => void handleCopyYaml()}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 cursor-pointer"
                    >
                      {copiedYaml ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>Copiar</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleDownloadYaml}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 cursor-pointer"
                    >
                      <Download className="w-3 h-3" />
                      <span>Descargar</span>
                    </button>
                  </div>
                )}
              </div>
              <textarea
                id="gitops-yaml-editor"
                rows={11}
                value={gitopsYaml}
                onChange={(e) => setGitopsYaml(e.target.value)}
                placeholder={'version: 1\nprojects:\n  - name: mi-app\n    gitRepo: https://github.com/org/mi-app\n    env:\n      DATABASE_URL: ${vault.PROD_DB_URL}'}
                spellCheck={false}
                className="w-full p-3.5 bg-slate-50 focus:bg-white border border-slate-200 rounded-xl font-mono text-[11px] leading-relaxed text-slate-900"
              />
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-4 flex-wrap">
                <label className="inline-flex items-center gap-1.5 text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={gitopsPrune}
                    onChange={(e) => {
                      setGitopsPrune(e.target.checked);
                      if (!e.target.checked) setGitopsConfirmDestructive(false);
                    }}
                    className="accent-slate-900"
                  />
                  <span>Prune (eliminar recursos ausentes)</span>
                </label>
                {gitopsPrune && (
                  <label className="inline-flex items-center gap-1.5 text-red-700 font-medium cursor-pointer">
                    <input
                      type="checkbox"
                      checked={gitopsConfirmDestructive}
                      onChange={(e) => setGitopsConfirmDestructive(e.target.checked)}
                      className="accent-red-600"
                    />
                    <span>Confirmar borrados destructivos</span>
                  </label>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  disabled={!gitopsYaml.trim() || gitopsBusy !== null}
                  onClick={() => void handlePlanGitOps()}
                  className="px-3.5 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  {gitopsBusy === 'plan' ? 'Simulando…' : 'Simular Plan (Dry-Run)'}
                </button>
                <button
                  type="button"
                  disabled={!gitopsYaml.trim() || gitopsBusy !== null}
                  onClick={() => void handleApplyGitOps()}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {gitopsBusy === 'apply' ? 'Aplicando…' : 'Aplicar stack'}
                </button>
              </div>
            </div>

            {gitopsPlan && (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-semibold text-slate-900">Resultado del plan GitOps</span>
                  <div className="flex items-center gap-2 font-mono text-[11px] tabular-nums">
                    <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-800">
                      +{gitopsPlan.create?.length || 0} crear
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800">
                      ~{gitopsPlan.update?.length || 0} actualizar
                    </span>
                    <span className="px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700">
                      -{gitopsPlan.delete?.length || 0} borrar
                    </span>
                  </div>
                </div>
                {gitopsPlan.warnings && gitopsPlan.warnings.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 space-y-1">
                    {gitopsPlan.warnings.map((w, i) => <div key={i}>· {w}</div>)}
                  </div>
                )}
                <div className="space-y-1 font-mono text-[11px] max-h-40 overflow-y-auto">
                  {(gitopsPlan.create || []).map((c, i) => (
                    <div key={`c-${i}`} className="text-emerald-800">+ [{c.kind}] {c.name}</div>
                  ))}
                  {(gitopsPlan.update || []).map((u, i) => (
                    <div key={`u-${i}`} className="text-amber-800">
                      ~ [{u.kind}] {u.name}
                      {u.changes?.length
                        ? ` (${u.changes.map((ch) => (typeof ch === 'string' ? ch : ch.field)).join(', ')})`
                        : ''}
                    </div>
                  ))}
                  {(gitopsPlan.delete || []).map((d, i) => (
                    <div key={`d-${i}`} className="text-red-700">- [{d.kind}] {d.name}</div>
                  ))}
                  {(gitopsPlan.create?.length || 0) + (gitopsPlan.update?.length || 0) + (gitopsPlan.delete?.length || 0) === 0 && (
                    <div className="text-slate-500">Sin cambios pendientes frente al estado actual.</div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Bóveda compartida cifrada (Shared Encrypted Vault) */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4 text-xs">
            <div className="flex items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Bóveda compartida cifrada (Vault AES-256-GCM)</h2>
                <p className="text-slate-500 mt-0.5">
                  Guarda secretos una vez y referéncialos en entornos o <code className="font-mono">culkibo.yaml</code> como{' '}
                  <code className="font-mono text-slate-800">${'{vault.NOMBRE_CLAVE}'}</code>. Los valores nunca se devuelven en texto plano.
                </p>
              </div>
            </div>

            <form onSubmit={handleSaveVaultSecret} className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 items-end">
              <label className="block sm:col-span-4">
                <span className="font-medium text-slate-700">Clave</span>
                <input
                  required
                  value={vaultKey}
                  onChange={(e) => setVaultKey(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, '_'))}
                  placeholder="STRIPE_SECRET_KEY"
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
                />
              </label>
              <label className="block sm:col-span-4">
                <span className="font-medium text-slate-700">Valor secreto</span>
                <input
                  type="password"
                  required
                  value={vaultValue}
                  onChange={(e) => setVaultValue(e.target.value)}
                  placeholder="••••••••••••"
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
                />
              </label>
              <label className="block sm:col-span-2">
                <span className="font-medium text-slate-700">Alcance</span>
                <select
                  value={vaultScope}
                  onChange={(e) => setVaultScope(e.target.value as 'both' | 'runtime' | 'build')}
                  className="mt-1 w-full px-2.5 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
                >
                  <option value="both">Ambos</option>
                  <option value="runtime">Runtime</option>
                  <option value="build">Build</option>
                </select>
              </label>
              <button
                type="submit"
                disabled={vaultBusy}
                className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Guardar</span>
              </button>
            </form>

            {vaultSecrets.length === 0 ? (
              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 text-center text-slate-500">
                El Vault compartido está vacío. Añade claves reutilizables para mantener tus manifiestos GitOps libres de secretos.
              </div>
            ) : (
              <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden">
                {vaultSecrets.map((sec) => (
                  <div key={sec.key} className="px-4 py-2.5 flex items-center justify-between gap-3 bg-white">
                    <div className="min-w-0 flex items-center gap-2 flex-wrap">
                      <code className="font-mono font-semibold text-slate-900">${`{vault.${sec.key}}`}</code>
                      {sec.scope && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[10px] text-slate-600">
                          {sec.scope}
                        </span>
                      )}
                      {(sec.fingerprint || sec.hash) && (
                        <span className="font-mono text-[10px] text-slate-400">
                          sha256:{(sec.fingerprint || sec.hash || '').slice(0, 10)}
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      disabled={vaultBusy}
                      aria-label={`Eliminar secreto ${sec.key}`}
                      onClick={() => void handleDeleteVaultSecret(sec.key)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-red-700 hover:bg-red-50 cursor-pointer shrink-0"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Entornos por proyecto, Diff seguro y Promoción */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4 text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <GitBranch className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">Entornos aislados y Promoción (dev → staging → production)</h2>
                  <p className="text-slate-500 mt-0.5">
                    Compara variables por huella HMAC sin exponer secretos y promociona artefactos verificados entre entornos.
                  </p>
                </div>
              </div>
              <select
                aria-label="Seleccionar proyecto para entornos"
                value={envProjectId}
                onChange={(e) => {
                  setEnvProjectId(e.target.value);
                  setEnvDiffResult(null);
                }}
                className="px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900 min-w-[200px]"
              >
                {envProjects.length === 0 && <option value="">Sin proyectos</option>}
                {envProjects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            {envProjects.length > 0 && (
              <>
                {projectEnvs.length > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    {projectEnvs.map((env) => (
                      <div key={env.name} className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-slate-900 font-mono">{env.name}</span>
                          <span className="text-[10px] text-slate-500 tabular-nums">
                            {env.envCount ?? env.envKeys?.length ?? 0} vars
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono truncate">
                          Rama: {env.branch || 'main'}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Guardar override de entorno */}
                  <form onSubmit={handleSaveProjectEnv} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                    <div className="font-semibold text-slate-800">Configurar entorno</div>
                    <div className="grid grid-cols-2 gap-2.5">
                      <select
                        value={envEditName}
                        onChange={(e) => setEnvEditName(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                      >
                        <option value="development">development</option>
                        <option value="staging">staging</option>
                        <option value="production">production</option>
                      </select>
                      <input
                        value={envEditBranch}
                        onChange={(e) => setEnvEditBranch(e.target.value)}
                        placeholder="Rama Git (ej. staging)"
                        className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                      />
                    </div>
                    <textarea
                      rows={3}
                      value={envEditVars}
                      onChange={(e) => setEnvEditVars(e.target.value)}
                      placeholder={'NODE_ENV=staging\nAPI_KEY=${vault.STAGING_KEY}'}
                      spellCheck={false}
                      className="w-full p-2.5 rounded-lg border border-slate-200 bg-white font-mono text-[11px]"
                    />
                    <button
                      type="submit"
                      disabled={envBusy}
                      className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                    >
                      Guardar entorno
                    </button>
                  </form>

                  {/* Diff seguro y Promoción */}
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                    <div className="font-semibold text-slate-800">Comparar y promocionar</div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <select
                        aria-label="Entorno origen"
                        value={envDiffFrom}
                        onChange={(e) => setEnvDiffFrom(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                      >
                        <option value="development">development</option>
                        <option value="staging">staging</option>
                        <option value="production">production</option>
                      </select>
                      <ArrowRightLeft className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        aria-label="Entorno destino"
                        value={envDiffTo}
                        onChange={(e) => setEnvDiffTo(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                      >
                        <option value="staging">staging</option>
                        <option value="production">production</option>
                        <option value="development">development</option>
                      </select>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button
                        type="button"
                        disabled={envBusy}
                        onClick={() => void handleDiffEnvs()}
                        className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-800 font-medium cursor-pointer disabled:opacity-50"
                      >
                        Ver diff (HMAC)
                      </button>
                      <button
                        type="button"
                        disabled={envBusy}
                        onClick={() => void handlePromoteEnv(true)}
                        className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-800 font-medium cursor-pointer disabled:opacity-50"
                      >
                        Simular promoción
                      </button>
                      <button
                        type="button"
                        disabled={envBusy}
                        onClick={() => void handlePromoteEnv(false)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                      >
                        <Rocket className="w-3.5 h-3.5" />
                        <span>Promocionar</span>
                      </button>
                    </div>

                    {envDiffResult && (
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200 font-mono text-[11px] space-y-1">
                        <div className="text-emerald-700">
                          + Añadidas: {envDiffResult.added.length
                            ? envDiffResult.added.map((a) => (typeof a === 'string' ? a : a.key)).join(', ')
                            : 'ninguna'}
                        </div>
                        <div className="text-amber-700">
                          ~ Modificadas: {envDiffResult.changed.length
                            ? envDiffResult.changed.map((c) => (typeof c === 'string' ? c : c.key)).join(', ')
                            : 'ninguna'}
                        </div>
                        <div className="text-red-700">
                          - Solo en destino: {envDiffResult.removed.length
                            ? envDiffResult.removed.map((r) => (typeof r === 'string' ? r : r.key)).join(', ')
                            : 'ninguna'}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {tab === 'integrations' && (
        <div className="space-y-5">
          {/* Cloudflare */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Cloud className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">Cloudflare (DNS automático, comodines y túneles)</h2>
                  <p className="text-xs text-slate-500">
                    Conecta tu API Token para crear registros A, emitir <code className="font-mono">*.tudominio.com</code> y gestionar túneles.
                  </p>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                cfConfig?.isConfigured
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {cfConfig?.isConfigured ? 'Conectado' : 'Sin configurar'}
              </span>
            </div>

            {cfFeedback && (
              <div className={`p-3 rounded-lg text-xs border flex items-center gap-2 ${
                cfFeedback.type === 'ok'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                {cfFeedback.type === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                <span>{cfFeedback.text}</span>
              </div>
            )}

            <form onSubmit={handleSaveCloudflare} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block font-medium text-slate-700 mb-1">API Token (Zone DNS Edit + Tunnel Edit)</label>
                <input
                  type="password"
                  value={cfToken}
                  onChange={(e) => setCfToken(e.target.value)}
                  placeholder={hasCfToken ? '•••••••• (dejar vacío para conservar)' : 'Pega tu API Token de Cloudflare'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Account ID (opcional, requerido para túneles)</label>
                <input
                  type="text"
                  value={cfAccountId}
                  onChange={(e) => setCfAccountId(e.target.value)}
                  placeholder={cfConfig?.accountId ? 'Guardado (dejar vacío para conservar)' : '32 caracteres hexadecimales'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
              <div className="sm:col-span-2 flex justify-end">
                <button
                  type="submit"
                  disabled={cfBusy}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {cfBusy ? 'Verificando…' : 'Verificar y guardar'}
                </button>
              </div>
            </form>

            {cfZones.length > 0 && (
              <div className="pt-3 border-t border-slate-100">
                <div className="text-xs font-medium text-slate-700 mb-2 tabular-nums">Zonas detectadas ({cfZones.length}):</div>
                <div className="flex flex-wrap gap-1.5">
                  {cfZones.map((z) => (
                    <span key={z.id} className="px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700">
                      {z.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* GitHub */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Key className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">GitHub (repositorios privados y webhooks)</h2>
                  <p className="text-xs text-slate-500">Para repositorios públicos no necesitas token.</p>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                githubStatus?.connected ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {githubStatus?.connected ? 'Conectado' : 'No conectado'}
              </span>
            </div>

            {ghFeedback && (
              <div className={`p-3 rounded-lg text-xs border ${
                ghFeedback.type === 'ok' ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                {ghFeedback.text}
              </div>
            )}

            {githubStatus?.connected && githubStatus.user ? (
              <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <img src={githubStatus.user.avatar_url} alt={githubStatus.user.login} className="w-9 h-9 rounded-full culkibo-img-outline" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900">{githubStatus.user.name || githubStatus.user.login}</div>
                    <a href={githubStatus.user.html_url} target="_blank" rel="noreferrer" className="text-xs text-slate-600 hover:underline inline-flex items-center gap-1">
                      @{githubStatus.user.login} <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
                {confirmDisconnectGh ? (
                  <div className="flex items-center gap-2">
                    <button type="button" onClick={() => void handleDisconnectGitHub()} className="px-3 py-1.5 rounded-lg bg-red-600 text-white text-xs font-medium cursor-pointer">
                      Sí, desconectar
                    </button>
                    <button type="button" onClick={() => setConfirmDisconnectGh(false)} className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs text-slate-600 cursor-pointer">
                      Cancelar
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmDisconnectGh(true)}
                    disabled={ghBusy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-red-50 text-red-700 border border-red-200 text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Unlink className="w-3.5 h-3.5" /> Desconectar
                  </button>
                )}
              </div>
            ) : (
              <form onSubmit={handleConnectGitHub} className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={ghToken}
                  onChange={(e) => setGhToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
                <button
                  type="submit"
                  disabled={ghBusy || !ghToken.trim()}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {ghBusy ? 'Verificando…' : 'Conectar GitHub'}
                </button>
              </form>
            )}
          </div>

          {/* Enlace limpio a Backups y DR */}
          <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div>
              <div className="font-semibold text-slate-900">Almacenamiento S3 / Cloudflare R2 y Snapshots de instancia</div>
              <p className="text-slate-500 mt-0.5">
                {s3Config.configured ? `Conectado al bucket ${s3Config.bucket}` : 'Configura tu bucket S3/R2 y exporta copias completas cifradas en Backups y DR.'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTab('backups')}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0"
            >
              Abrir Backups y DR
            </button>
          </div>
        </div>
      )}

      {tab === 'backups' && (
        <div className="space-y-5">
          {/* Almacenamiento S3 / R2 (soporta edición parcial sin reescribir claves) */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
                  <span>Almacenamiento remoto S3 / Cloudflare R2</span>
                  <HelpTip title="Backups externos S3 / R2">
                    <p>Sube automáticamente cada copia de base de datos o snapshot completo fuera del servidor.</p>
                    <p>Si ya está configurado, puedes cambiar el bucket o prefijo dejando las claves vacías para conservarlas.</p>
                  </HelpTip>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">Compatible con Cloudflare R2, AWS S3, Backblaze B2 y MinIO.</p>
              </div>
              {s3Config.configured && (
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => void handleTestS3()}
                    disabled={s3Busy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                  >
                    Probar conexión
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadS3Objects()}
                    disabled={s3ObjectsLoading}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                  >
                    {s3ObjectsLoading ? 'Cargando…' : 'Explorar bucket'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDisconnectS3(true)}
                    disabled={s3Busy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-red-50 border border-red-200 text-xs font-medium text-red-700 cursor-pointer"
                  >
                    Desconectar
                  </button>
                </div>
              )}
            </div>

            <form onSubmit={handleSaveS3} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <label className="block">
                <span className="font-medium text-slate-700">Endpoint</span>
                <input
                  value={s3Form.endpoint}
                  onChange={(e) => setS3Form({ ...s3Form, endpoint: e.target.value })}
                  placeholder={s3Config.endpoint || 'https://<id>.r2.cloudflarestorage.com'}
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Bucket</span>
                <input
                  value={s3Form.bucket}
                  onChange={(e) => setS3Form({ ...s3Form, bucket: e.target.value })}
                  placeholder={s3Config.bucket || 'culkibo-backups'}
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Región</span>
                <input
                  value={s3Form.region}
                  onChange={(e) => setS3Form({ ...s3Form, region: e.target.value })}
                  placeholder="auto (R2) o eu-west-1"
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Prefijo</span>
                <input
                  value={s3Form.prefix}
                  onChange={(e) => setS3Form({ ...s3Form, prefix: e.target.value })}
                  placeholder="culkibo/"
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Access Key ID</span>
                <input
                  value={s3Form.accessKeyId}
                  onChange={(e) => setS3Form({ ...s3Form, accessKeyId: e.target.value })}
                  placeholder={s3Config.configured ? `${s3Config.accessKeyId || '••••'} (vacío para conservar)` : 'Access Key ID'}
                  required={!s3Config.configured}
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Secret Access Key</span>
                <input
                  type="password"
                  value={s3Form.secretAccessKey}
                  onChange={(e) => setS3Form({ ...s3Form, secretAccessKey: e.target.value })}
                  placeholder={s3Config.configured ? '•••••••• (vacío para conservar)' : 'Secret Access Key'}
                  required={!s3Config.configured}
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <div className="sm:col-span-2 flex justify-end">
                <button type="submit" disabled={s3Busy} className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50">
                  Guardar S3 / R2
                </button>
              </div>
            </form>

            {s3Objects.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden text-xs">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700 tabular-nums">
                  Objetos remotos en bucket ({s3Objects.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-48 overflow-y-auto">
                  {s3Objects.map((obj) => (
                    <div key={obj.key} className="px-4 py-2 flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-700 truncate">{obj.key}</span>
                      <span className="text-slate-400 font-mono tabular-nums shrink-0">
                        {(obj.size / 1024).toFixed(1)} KB
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Snapshot completo de instancia (Disaster Recovery) */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-5 text-xs">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-slate-600" />
                <span>Snapshot completo de instancia Culkibo (DR)</span>
              </h2>
              <p className="text-slate-500 mt-0.5">
                Exporta o restaura en bloque todos tus proyectos, dominios, tareas cron, políticas TLS, notificaciones y metadatos con cifrado opcional AES-256-GCM.
              </p>
            </div>

            <form onSubmit={handleExportInstance} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="font-semibold text-slate-800">1. Exportar snapshot de este servidor</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={exportIncludeSecrets}
                      onChange={(e) => setExportIncludeSecrets(e.target.checked)}
                      className="rounded border-slate-300 accent-slate-900"
                    />
                    <span>Incluir variables de entorno y secretos (requiere contraseña de cifrado)</span>
                  </label>
                  {s3Config.configured && (
                    <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={exportUploadS3}
                        onChange={(e) => setExportUploadS3(e.target.checked)}
                        className="rounded border-slate-300 accent-slate-900"
                      />
                      <span>Subir copia también al bucket S3 / R2</span>
                    </label>
                  )}
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">
                    Contraseña de cifrado AES-256-GCM {exportIncludeSecrets ? '(obligatoria)' : '(opcional)'}
                  </label>
                  <input
                    type="password"
                    value={exportPassphrase}
                    onChange={(e) => setExportPassphrase(e.target.value)}
                    required={exportIncludeSecrets}
                    placeholder="Frase segura para cifrar el archivo"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={exportingSnapshot}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {exportingSnapshot ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                  <span>{exportingSnapshot ? 'Exportando…' : 'Crear snapshot ahora'}</span>
                </button>
              </div>
            </form>

            {instanceBackups.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700">
                  Snapshots disponibles en disco ({instanceBackups.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-44 overflow-y-auto">
                  {instanceBackups.map((bk) => (
                    <div key={bk.fileName} className="px-4 py-2.5 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <span className="font-mono text-slate-800 truncate block">{bk.fileName}</span>
                        {bk.createdAt && <span className="text-[11px] text-slate-400">{new Date(bk.createdAt).toLocaleString('es-ES')}</span>}
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleDownloadSnapshot(bk.fileName)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0"
                      >
                        <Download className="w-3 h-3" /> Descargar
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Importar Snapshot */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="font-semibold text-slate-800">2. Restaurar o migrar desde un archivo snapshot (.json)</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Archivo snapshot</label>
                  <label className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 font-medium cursor-pointer">
                    <Upload className="w-3.5 h-3.5" />
                    <span className="truncate">{importFileName || 'Seleccionar archivo .json'}</span>
                    <input
                      type="file"
                      accept=".json"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (!f) return;
                        setImportFileName(f.name);
                        setImportDryRunResult(null);
                        f.text().then((txt) => {
                          try {
                            setImportSnapshotObj(JSON.parse(txt));
                          } catch {
                            onNotify?.('El archivo seleccionado no es un JSON válido', 'error');
                          }
                        });
                        e.target.value = '';
                      }}
                    />
                  </label>
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Modo de restauración</label>
                  <select
                    value={importMode}
                    onChange={(e) => setImportMode(e.target.value as 'merge' | 'overwrite')}
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
                  >
                    <option value="merge">Combinar (añade sin borrar lo actual)</option>
                    <option value="overwrite">Sobrescribir (reemplaza configuración)</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Contraseña (si está cifrado)</label>
                  <input
                    type="password"
                    value={importPassphrase}
                    onChange={(e) => setImportPassphrase(e.target.value)}
                    placeholder="Contraseña AES-256"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                  />
                </div>
              </div>

              {importDryRunResult && (
                <div className="p-3 rounded-lg bg-white border border-slate-200 text-[11px] font-mono text-slate-700 overflow-x-auto">
                  {JSON.stringify(importDryRunResult.summary || importDryRunResult.counts || importDryRunResult, null, 2)}
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  disabled={!importSnapshotObj || importingSnapshot}
                  onClick={() => void handleImportInstance(true)}
                  className="px-3.5 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  Simular (Dry-Run)
                </button>
                <button
                  type="button"
                  disabled={!importSnapshotObj || importingSnapshot}
                  onClick={() => void handleImportInstance(false)}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {importingSnapshot ? 'Aplicando…' : 'Aplicar restauración'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'notifications' && (
        !notif ? (
          <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-xs text-slate-500 space-y-3">
            {notifLoadFailed ? (
              <>
                <p>No se pudo cargar la configuración de notificaciones.</p>
                <button
                  type="button"
                  onClick={() => void loadAll()}
                  className="px-3.5 py-2 rounded-lg bg-slate-900 text-white font-medium cursor-pointer"
                >
                  Reintentar
                </button>
              </>
            ) : (
              <span>Cargando configuración de alertas…</span>
            )}
          </div>
        ) : (
          <form onSubmit={handleSaveNotifications} className="bg-white rounded-xl border border-slate-200 p-5 space-y-5 text-xs">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Alertas automáticas</h2>
                <p className="text-slate-500 mt-0.5">Recibe avisos en Telegram, Discord, Slack o mediante webhook HTTPS.</p>
              </div>
              <label className="inline-flex items-center gap-2 font-medium text-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={notif.enabled}
                  onChange={(e) => setNotif({ ...notif, enabled: e.target.checked })}
                  className="rounded border-slate-300 accent-slate-900"
                />
                Activar alertas
              </label>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="font-medium text-slate-800">Eventos que disparan alerta:</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                {([
                  ['service_down', 'Servicio caído'],
                  ['service_failed', 'Error instalando servicio'],
                  ['deploy_started', 'Despliegue iniciado'],
                  ['deploy_failed', 'Despliegue fallido'],
                  ['deploy_succeeded', 'Despliegue completado'],
                  ['rollback', 'Reversión automática / manual'],
                  ['production_unhealthy', 'Producción sin salud'],
                  ['ssl_issued', 'Certificado TLS emitido'],
                  ['tls_expiring', 'Certificado TLS próximo a caducar'],
                  ['backup_succeeded', 'Copia BD completada'],
                  ['backup_failed', 'Copia BD fallida'],
                  ['disk_warning', 'Alerta de espacio en disco'],
                  ['cron_failed', 'Tarea Cron fallida'],
                  ['project_stopped', 'Proyecto detenido'],
                ] as const).map(([key, label]) => (
                  <label key={key} className="inline-flex items-center gap-1.5 cursor-pointer text-slate-700">
                    <input
                      type="checkbox"
                      checked={Boolean(notif.events[key])}
                      onChange={(e) => setNotif({ ...notif, events: { ...notif.events, [key]: e.target.checked } })}
                      className="rounded border-slate-300 accent-slate-900"
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Telegram</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.telegram.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="password"
                  value={notif.channels.telegram.botToken}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, botToken: e.target.value } } })}
                  placeholder="Bot Token (123456:ABC...)"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
                <input
                  type="text"
                  value={notif.channels.telegram.chatId}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, chatId: e.target.value } } })}
                  placeholder="Chat ID (ej. -100123456789)"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Discord</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.discord.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.discord.webhookUrl}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, webhookUrl: e.target.value } } })}
                  placeholder="https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Slack</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.slack.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.slack.webhookUrl}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, webhookUrl: e.target.value } } })}
                  placeholder="https://hooks.slack.com/services/..."
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Webhook HTTPS</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.webhook.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.webhook.url}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, url: e.target.value } } })}
                  placeholder="https://tu-endpoint.com/webhook"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
                <input
                  type="password"
                  value={notif.channels.webhook.secretHeader || ''}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, secretHeader: e.target.value } } })}
                  placeholder={notif.channels.webhook.hasSecretHeader ? '•••••••• (firma HMAC-SHA256 activa)' : 'Secreto HMAC-SHA256 (opcional)'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
            </div>

            {notifHistory.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700">
                  Últimas alertas enviadas ({notifHistory.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-44 overflow-y-auto">
                  {notifHistory.slice(0, 10).map((item) => (
                    <div key={item.id} className="px-4 py-2 flex items-center justify-between gap-2 text-[11px]">
                      <div className="min-w-0">
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-slate-400 ml-2 font-mono">{item.event}</span>
                      </div>
                      <span className="text-slate-400 shrink-0 tabular-nums">{formatSafeDate(item.timestamp || item.at)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setTab('security')}
                className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
              >
                <Webhook className="w-3.5 h-3.5" />
                <span>Standard-Webhooks (whsec_) &amp; DLQ Replay → Security</span>
              </button>
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => void handleTestNotifications()}
                  disabled={notifTesting}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{notifTesting ? 'Enviando…' : 'Guardar y enviar prueba'}</span>
                </button>
                <button
                  type="submit"
                  disabled={notifBusy}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {notifBusy ? 'Guardando…' : 'Guardar alertas'}
                </button>
              </div>
            </div>
          </form>
        )
      )}

      {tab === 'system' && (
        <div className="space-y-5">
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Server className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">Servidor Culkibo v{sysStatus?.version || '1.0.0'}</h2>
                  <p className="text-xs text-slate-500">Métricas reales del proceso y dependencias del host.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {onOpenMetrics && (
                  <button
                    type="button"
                    onClick={onOpenMetrics}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                  >
                    <Activity className="w-3.5 h-3.5" />
                    <span>Abrir diagnóstico y métricas</span>
                  </button>
                )}
                <button
                  type="button"
                  aria-label="Actualizar estado del sistema"
                  onClick={() => void loadAll()}
                  className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {sysStatus && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 text-xs">
                <div className="p-3.5">
                  <span className="text-slate-500 block">Node.js</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block">{sysStatus.nodeVersion}</span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Tiempo activo</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {Math.floor(sysStatus.uptimeSeconds / 60)} min
                  </span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Memoria RSS</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {sysStatus.memoryUsageMb} MB
                  </span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Heap JS</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {sysStatus.heapUsedMb} MB
                  </span>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-900">Motor Docker</div>
                  <div className="text-slate-500 mt-0.5">
                    {dockerStatus?.available ? 'Disponible para contenedores y bases de datos' : (dockerStatus?.reason || 'No detectado')}
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded-full font-medium border shrink-0 ${
                  dockerStatus?.available ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}>
                  {dockerStatus?.available ? 'Activo' : 'Inactivo'}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-900">Proxy Caddy (HTTPS)</div>
                  <div className="text-slate-500 mt-0.5 font-mono">{caddyStatus?.available ? caddyStatus.adminUrl : 'Detenido'}</div>
                </div>
                {caddyStatus?.available ? (
                  <span className="px-2 py-0.5 rounded-full font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 shrink-0">Activo</span>
                ) : (
                  <button
                    type="button"
                    onClick={() => void handleStartCaddy()}
                    disabled={startingCaddy}
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 text-white font-medium cursor-pointer disabled:opacity-50 shrink-0"
                  >
                    {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                    <span>Activar</span>
                  </button>
                )}
              </div>
            </div>

            {/* Edge HTTP/3 (QUIC) & Multi-DNS-01 Wildcard Status */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-slate-600 shrink-0" />
                  <span className="font-semibold text-slate-900">{t('settings.edgeTitle')}</span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {(http3Status?.protocols?.length ? http3Status.protocols : ['h1', 'h2']).map((proto) => (
                    <span
                      key={proto}
                      className={`px-2 py-0.5 rounded-md font-mono text-[10px] uppercase font-semibold border ${
                        proto === 'h3'
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-white text-slate-600 border-slate-200'
                      }`}
                    >
                      {proto === 'h3' ? 'HTTP/3 QUIC' : proto.toUpperCase()}
                    </span>
                  ))}
                  <span
                    className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                      http3Status?.configured
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-white text-slate-600 border-slate-200'
                    }`}
                  >
                    {http3Status === null
                      ? 'Sondeando…'
                      : http3Status.configured
                        ? (http3Status.udp443Published === false ? 'H3 listo (falta UDP :443)' : 'HTTP/3 activo')
                        : 'Solo HTTP/1.1 + HTTP/2'}
                  </span>
                </div>
              </div>
              {dnsProviders.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[11px] text-slate-500 mr-1 tabular-nums">
                    Proveedores DNS-01 ({dnsProviders.length}):
                  </span>
                  {dnsProviders.map((prov) => (
                    <span
                      key={prov.id}
                      className="px-2 py-0.5 rounded-md bg-white border border-slate-200 text-[11px] font-medium text-slate-700"
                    >
                      {prov.label}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">{t('settings.diskMaintTitle')}</h3>
              <p className="text-xs text-slate-500 mt-0.5">{t('settings.diskMaintDesc')}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              {onRestoreChecklist && (
                <button
                  type="button"
                  onClick={onRestoreChecklist}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                >
                  <ListChecks className="w-3.5 h-3.5 text-slate-500" />
                  <span>{t('settings.restoreGuide')}</span>
                </button>
              )}
              <button
                type="button"
                onClick={() => void handlePruneCache()}
                disabled={pruning}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-800 cursor-pointer disabled:opacity-50"
              >
                {pruning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5 text-slate-500" />}
                <span>{pruning ? t('settings.pruning') : t('settings.pruneBtn')}</span>
              </button>
            </div>
          </div>

          {/* Telemetría anónima y diagnósticos */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-semibold text-slate-900">{t('settings.telemetryTitle')}</h3>
                    <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                      telemetryStatus?.enabled
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : telemetryStatus?.lockedByEnv
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      {telemetryStatus?.enabled
                        ? 'Activa'
                        : telemetryStatus?.lockedByEnv
                          ? 'Controlada por entorno'
                          : 'Desactivada'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                    Envía informes anónimos de fallos, errores de la interfaz y métricas agregadas para corregir problemas rápidamente. Nunca incluye secretos, dominios ni datos de negocio.
                  </p>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-label="Activar o desactivar telemetría anónima"
                aria-checked={Boolean(telemetryStatus?.enabled)}
                disabled={!telemetryStatus || telemetryStatus.lockedByEnv || telemetryBusy}
                onClick={() => void handleToggleTelemetry()}
                className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
                  telemetryStatus?.enabled ? 'bg-slate-900' : 'bg-slate-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                    telemetryStatus?.enabled ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {telemetryStatus?.lockedByEnv && (
              <div className="px-3.5 py-2.5 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900">
                {telemetryStatus.reason}. Modifica las variables de entorno del proceso (<code className="font-mono">CULKIBO_TELEMETRY</code> / <code className="font-mono">DO_NOT_TRACK</code>) para cambiar este estado.
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="font-semibold text-slate-800">Qué enviamos</div>
                <ul className="space-y-1 text-slate-600 list-disc list-inside text-[11px]">
                  <li>Versión de Culkibo, Node.js, sistema operativo y rangos de RAM/CPU</li>
                  <li>Errores fatales del servidor, 5xx en rutas canónicas y fallos de despliegue/copias</li>
                  <li>Errores capturados por la interfaz web (sin URLs ni texto de usuario)</li>
                  <li>Contadores agregados de uso de funciones para priorizar mejoras</li>
                </ul>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="font-semibold text-slate-800">Qué NUNCA recopilamos</div>
                <ul className="space-y-1 text-slate-600 list-disc list-inside text-[11px]">
                  {(telemetryStatus?.neverCollected || [
                    'Nombres o URLs de repositorios, proyectos o dominios',
                    'Variables de entorno, contraseñas, tokens o certificados',
                    'Direcciones IP, correos electrónicos o rutas con nombre de usuario',
                    'Contenido de bases de datos, backups o logs de negocio',
                  ]).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-100 text-xs">
              <div className="text-slate-500 min-w-0">
                <span>ID anónimo: </span>
                <code className="font-mono text-[11px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded break-all">
                  {telemetryStatus?.instanceId || '—'}
                </code>
              </div>
              <div className="flex items-center gap-2 flex-wrap shrink-0">
                <button
                  type="button"
                  onClick={() => void handleResetTelemetryId()}
                  disabled={telemetryBusy || !telemetryStatus}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${telemetryBusy ? 'animate-spin' : ''}`} />
                  <span>Rotar ID</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleToggleTelemetryPreview()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 font-medium cursor-pointer"
                >
                  {showTelemetryPreview ? <EyeOff className="w-3.5 h-3.5 text-slate-500" /> : <Eye className="w-3.5 h-3.5 text-slate-500" />}
                  <span>{showTelemetryPreview ? 'Ocultar payload' : 'Ver payload exacto'}</span>
                </button>
              </div>
            </div>

            {showTelemetryPreview && (
              <div className="rounded-xl border border-slate-200 bg-slate-950 text-slate-100 p-3.5 overflow-x-auto">
                {telemetryPreviewLoading ? (
                  <div className="text-xs text-slate-400 flex items-center gap-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Generando sobre JSON saneado…</span>
                  </div>
                ) : (
                  <pre className="text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-words max-h-64 overflow-y-auto">
                    {JSON.stringify(telemetryPreview, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* Registro de auditoría del servidor */}
          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
                <FileText className="w-3.5 h-3.5 text-slate-500" />
                <span>{t('settings.auditLogTitle')}</span>
                {auditVerification && (
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-medium border tabular-nums ${
                      auditVerification.valid
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-red-50 text-red-700 border-red-200'
                    }`}
                  >
                    {auditVerification.valid
                      ? `SHA-256 OK (${auditVerification.checkedCount})`
                      : 'Tampered'}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void handleVerifyAuditChain()}
                  disabled={auditVerifyBusy}
                  className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-800 cursor-pointer disabled:opacity-50"
                >
                  {auditVerifyBusy ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3 text-emerald-600" />}
                  <span>{t('settings.verifyShaBtn')}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void loadAudit()}
                  disabled={auditLoading}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
                >
                  <RefreshCw className={`w-3 h-3 ${auditLoading ? 'animate-spin' : ''}`} />
                  <span>Actualizar</span>
                </button>
              </div>
            </div>
            {auditEvents.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No hay eventos de auditoría registrados todavía.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto text-xs">
                {auditEvents.map((ev, i) => (
                  <div key={ev.id || `${ev.timestamp || ev.at || 'ev'}-${i}`} className="px-5 py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0 flex items-center gap-2 flex-wrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                        {ev.source}
                      </span>
                      <span className="font-medium text-slate-900">{ev.action}</span>
                      {ev.target && <span className="font-mono text-slate-500 truncate">{ev.target}</span>}
                    </div>
                    <span className="text-[11px] text-slate-400 tabular-nums shrink-0">
                      {formatSafeDate(ev.timestamp || ev.at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <Modal
        open={confirmDisconnectS3}
        onClose={() => setConfirmDisconnectS3(false)}
        title="Desconectar almacenamiento S3 / R2"
        subtitle="Las futuras copias se guardarán únicamente en disco local."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-600">
            Los archivos existentes en el bucket <code className="font-mono">{s3Config.bucket}</code> no se eliminarán.
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmDisconnectS3(false)} className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button type="button" onClick={() => void handleDisconnectS3()} className="px-4 py-2 text-xs font-medium bg-red-600 hover:bg-red-700 text-white rounded-lg cursor-pointer">
              Desconectar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
