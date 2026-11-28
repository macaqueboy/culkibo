const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * ACME Rate-Limit Budget, RFC 9773 ARI & TLS Cipher Guard (100% Zero-Dep).
 *
 * Contramedida directa a `coollabsio/coolify#6800` (dominios obsoletos en `acme.json`
 * quemando la cuota de 5 fallos/h -> `429`), `Dokploy/dokploy#2238` (sobrescritura de
 * volumen `acme.json`) y cumplimiento RFC 9773 (ACME Renewal Information):
 *  - Audita cuotas semanales (50/wk) y de fallos horarios (5/hr) de Let's Encrypt.
 *  - Detecta dominios obsoletos retenidos, almacenamiento efímero de certificados y
 *    ausencia de `replaces` ARI.
 *  - Calcula ventanas jittered deterministas dentro de `suggestedWindow` (RFC 9773).
 *  - Bloquea versiones débiles TLS `1.0`/`1.1` y cifrados `RC4`/`3DES`/`CBC`, emitiendo
 *    un bloque `caddyTlsBlock` (string plano) endurecido.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/acme-tls-budget.json`.
 */

const MAX_AUDITS = 200;
const WEAK_CIPHER_RE = /(?:RC4|3DES|DES_CBC|MD5|NULL|EXPORT|ANON|_CBC_)/i;
const WEAK_TLS_SET = new Set(['ssl2', 'ssl3', '1.0', '1.1', 'tls1.0', 'tls1.1', 'tlsv1', 'tlsv1.0', 'tlsv1.1']);

/**
 * Resuelve dinámicamente la ruta a `acme-tls-budget.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'acme-tls-budget.json')
    : path.join(base, 'data', 'acme-tls-budget.json');
}

/**
 * Escritura atómica con permisos `0o600`.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Carga auditorías desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, audits: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.audits)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
}

/**
 * Guarda auditorías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, audits: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.audits.length > MAX_AUDITS) {
    store.audits = store.audits.slice(-MAX_AUDITS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Renderiza un bloque Caddy `tls` endurecido (TLS 1.2/1.3 AEAD únicamente + volumen persistente).
 * @param {string} [domain]
 * @returns {string}
 */
function buildCaddyTlsBlock(domain = 'example.com') {
  return [
    `# Hardened Caddy TLS + RFC 9773 ARI Block (${domain})`,
    `${domain} {`,
    '  tls {',
    '    protocols tls1.2 tls1.3',
    '    ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    '    curves x25519 secp256r1',
    '  }',
    '}',
    '# Persist /data/caddy on a named host volume so renewals never burn Let\'s Encrypt weekly quotas.'
  ].join('\n');
}

/**
 * Audita el presupuesto de cuotas ACME de Let's Encrypt, dominios obsoletos y persistencia de certificados.
 *
 * @param {{
 *   domain?: string,
 *   certsIssued7d?: number,
 *   failedAuthz1h?: number,
 *   staleDomainsInStore?: string[],
 *   ariSupported?: boolean,
 *   hasPersistentCertVolume?: boolean,
 *   useStagingForDebug?: boolean,
 *   replacesCertId?: string,
 *   persist?: boolean
 * }} [input]
 */
function auditAcmeRateBudget(input = {}) {
  const opts = input || {};
  const domain = String(opts.domain || 'example.com').trim().toLowerCase() || 'example.com';
  const certsIssued7d = Math.max(0, Math.floor(Number(opts.certsIssued7d) || 0));
  const failedAuthz1h = Math.max(0, Math.floor(Number(opts.failedAuthz1h) || 0));
  const staleDomainsInStore = Array.isArray(opts.staleDomainsInStore)
    ? opts.staleDomainsInStore.map((d) => String(d || '').trim()).filter(Boolean)
    : [];
  const ariSupported = opts.ariSupported !== undefined ? Boolean(opts.ariSupported) : true;
  const hasPersistentCertVolume = opts.hasPersistentCertVolume !== undefined ? Boolean(opts.hasPersistentCertVolume) : true;

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. Weekly cert cap (50 / registered domain / 7d)
  if (certsIssued7d >= 40) {
    findings.push({
      code: 'ACME_WEEKLY_QUOTA_NEAR',
      severity: 'high',
      message: `${certsIssued7d}/50 certificates issued in the past 7 days for "${domain}" — nearing Let's Encrypt weekly limit.`,
      fix: 'Use Let\'s Encrypt staging CA for debug/test runs and submit RFC 9773 ARI `replaces` headers on renewals.'
    });
  }

  // 2. Hourly failed authorization lockout (5 / account / hostname / hr)
  if (failedAuthz1h >= 4) {
    findings.push({
      code: 'ACME_AUTHZ_LOCKOUT_RISK',
      severity: 'critical',
      message: `${failedAuthz1h}/5 failed ACME authorizations in the past hour for "${domain}" — imminent 429 rate-limit lockout.`,
      fix: 'Pause automated retries, verify DNS/Cloudflare proxy reachability, and test against ACME staging first.'
    });
  }

  // 3. Stale/deleted domains lingering in cert store (Coolify#6800)
  if (staleDomainsInStore.length > 0) {
    findings.push({
      code: 'STALE_ACME_DOMAINS_DETECTED',
      severity: 'critical',
      message: `${staleDomainsInStore.length} deleted/stale domain(s) still linger in cert store (${staleDomainsInStore.join(', ')}), burning hourly ACME authz quota (Coolify#6800).`,
      fix: 'Prune decommissioned hostnames from Caddy/Traefik acme.json before next renewal cycle.'
    });
  }

  // 4. Ephemeral certificate volume (Dokploy#2238)
  if (!hasPersistentCertVolume) {
    findings.push({
      code: 'EPHEMERAL_CERT_STORAGE',
      severity: 'critical',
      message: 'ACME certificate store is mounted on ephemeral container storage — container recreates wipe certs and trigger 429 reissue storms (Dokploy#2238).',
      fix: 'Mount a persistent named volume (mode 0600) for /data/caddy or acme.json.'
    });
  }

  // 5. RFC 9773 ARI replaces waiver support
  if (!ariSupported) {
    findings.push({
      code: 'ARI_REPLACES_MISSING',
      severity: 'medium',
      message: 'ACME client lacks RFC 9773 ARI `replaces` support — emergency/revocation renewals will consume weekly rate limits.',
      fix: 'Upgrade to Caddy v2.8+ / RFC 9773 ARI-enabled ACME client to claim automatic renewal quota waivers.'
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = criticalCount > 0 || findings.some((f) => f.severity === 'high');
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const caddyTlsBlock = buildCaddyTlsBlock(domain);
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `acme_${crypto.randomBytes(5).toString('hex')}`,
    domain,
    safe,
    blocked,
    status,
    certsIssued7d,
    weeklyLimit: 50,
    failedAuthz1h,
    hourlyFailLimit: 5,
    staleDomainsInStore,
    ariSupported,
    hasPersistentCertVolume,
    findings,
    findingCodes: findings.map((f) => f.code),
    caddyTlsBlock,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      domain,
      safe,
      status,
      certsIssued7d,
      failedAuthz1h,
      findingCodes: result.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Evalúa una ventana RFC 9773 ACME Renewal Information (ARI) seleccionando un instante
 * jittered determinista dentro de `[suggestedStartIso, suggestedEndIso]` + chequeo `replaces`.
 *
 * @param {{
 *   certId?: string,
 *   suggestedStartIso?: string,
 *   suggestedEndIso?: string,
 *   suggestedWindow?: { start?: string, end?: string },
 *   nowIso?: string | number,
 *   replacesCertId?: string
 * }} input
 */
function evaluateAriRenewalWindow(input) {
  const opts = input || /** @type {any} */ ({});
  const certId = String(opts.certId || 'cert_default').trim();
  const win = opts.suggestedWindow && typeof opts.suggestedWindow === 'object' ? opts.suggestedWindow : null;
  const startMs = Date.parse(String(opts.suggestedStartIso || (win ? win.start : '') || ''));
  const endMs = Date.parse(String(opts.suggestedEndIso || (win ? win.end : '') || ''));
  const nowMs = opts.nowIso !== undefined
    ? (typeof opts.nowIso === 'number' ? opts.nowIso : (Date.parse(String(opts.nowIso)) || Date.now()))
    : Date.now();
  const replacesCertId = String(opts.replacesCertId || '').trim();

  const safeStart = Number.isFinite(startMs) ? startMs : nowMs;
  const safeEnd = Number.isFinite(endMs) && endMs >= safeStart ? endMs : safeStart + 86400000;
  const spanMs = safeEnd - safeStart;

  // Deterministic jitter fraction in [0.05, 0.95] from SHA-256(certId + window)
  const hashVal = crypto.createHash('sha256').update(`${certId}:${safeStart}:${safeEnd}`, 'utf8').digest().readUInt32BE(0);
  const jitterFrac = 0.05 + ((hashVal % 9000) / 10000);
  const chosenMs = Math.round(safeStart + (spanMs * jitterFrac));

  /** @type {Array<{ code: string, severity: string, message: string }>} */
  const findings = [];
  if (!replacesCertId) {
    findings.push({
      code: 'ARI_REPLACES_MISSING',
      severity: 'medium',
      message: 'RFC 9773 `replaces` certificate identifier omitted — renewal will not receive Let\'s Encrypt rate-limit waiver.'
    });
  }

  return {
    ok: true,
    certId,
    replacesCertId: replacesCertId || null,
    rateLimitWaiverEligible: Boolean(replacesCertId),
    suggestedStartIso: new Date(safeStart).toISOString(),
    suggestedEndIso: new Date(safeEnd).toISOString(),
    chosenRenewalIso: new Date(chosenMs).toISOString(),
    shouldRenewNow: nowMs >= chosenMs,
    findings,
    findingCodes: findings.map((f) => f.code)
  };
}

/**
 * Audita versión mínima TLS y suites de cifrado, bloqueando TLS 1.0/1.1 y RC4/3DES/CBC.
 *
 * @param {{ minTlsVersion?: string, ciphers?: string[], domain?: string }} [input]
 */
function auditTlsCipherPolicy(input = {}) {
  const opts = input || {};
  const minTlsVersion = String(opts.minTlsVersion || '1.2').trim();
  const ciphers = Array.isArray(opts.ciphers) ? opts.ciphers.map((c) => String(c || '').trim()).filter(Boolean) : [];
  /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, fix: string }>} */
  const findings = [];

  if (WEAK_TLS_SET.has(minTlsVersion.toLowerCase())) {
    findings.push({
      code: 'WEAK_TLS_VERSION',
      severity: 'critical',
      message: `Minimum TLS version "${minTlsVersion}" is deprecated/insecure (RFC 8996 forbids TLS 1.0 & 1.1).`,
      fix: 'Set `protocols tls1.2 tls1.3` in Caddy/proxy TLS policy.'
    });
  }

  const weakCiphers = ciphers.filter((c) => WEAK_CIPHER_RE.test(c));
  if (weakCiphers.length > 0) {
    findings.push({
      code: 'WEAK_CIPHER_SUITE',
      severity: 'critical',
      message: `Weak/legacy TLS cipher suite(s) enabled: ${weakCiphers.join(', ')}.`,
      fix: 'Allow only modern AEAD forward-secret ciphers (AES-GCM & ChaCha20-Poly1305).'
    });
  }

  const safe = findings.length === 0;
  return {
    ok: true,
    safe,
    blocked: !safe,
    status: safe ? 'HARDENED' : 'CRITICAL',
    minTlsVersion,
    weakCiphers,
    findings,
    findingCodes: findings.map((f) => f.code),
    caddyTlsBlock: buildCaddyTlsBlock(opts.domain || 'example.com')
  };
}

/**
 * Lista auditorías ACME/TLS almacenadas (más recientes primero).
 */
function listAcmeBudgetAudits() {
  const store = loadStore();
  return [...store.audits].reverse();
}

module.exports = {
  auditAcmeRateBudget,
  evaluateAriRenewalWindow,
  auditTlsCipherPolicy,
  listAcmeBudgetAudits
};
