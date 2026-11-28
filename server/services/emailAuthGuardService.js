const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Transactional Email Auth (`SPF` / `DKIM` / `DMARC` / `MTA-STS`) & SMTP Guard (Zero-Dep).
 *
 * Impone los mandatos 2025–2026 de Gmail/Yahoo/Microsoft para remitentes y cura
 * `coollabsio/coolify#4311` (desajuste de puerto SMTP 587/465 vs STARTTLS/TLS):
 *  - Cuenta búsquedas DNS RFC 7208 en registros SPF (`include`, `a`, `mx`, `ptr`, `exists`,
 *    `redirect`): `> 10` → `SPF_LOOKUP_LIMIT_EXCEEDED`, `+all` → `SPF_PERMISSIVE_ALL`.
 *  - Exige claves DKIM `>= 2048` bits (`DKIM_KEY_TOO_WEAK`).
 *  - Verifica DMARC + alineación de dominio con `From:` (`DMARC_MISSING_OR_UNALIGNED`).
 *  - Evalúa `MTA-STS` (`enforce` vs `none`) y paridad puerto/TLS SMTP (`465 => implicit_tls`,
 *    `587 => starttls`, `25 => BLOCKED_CLOUD_PORT`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/email-auth-guard.json`.
 */

const MAX_AUDITS = 200;

/**
 * Resuelve dinámicamente la ruta a `email-auth-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'email-auth-guard.json')
    : path.join(base, 'data', 'email-auth-guard.json');
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
 * Audita un registro DNS TXT SPF según RFC 7208 (límite estricto de 10 búsquedas DNS y `+all`).
 *
 * @param {string} spfTxt
 */
function auditSpfRecord(spfTxt) {
  const raw = String(spfTxt || '').trim();
  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  if (!raw || !/^v=spf1(?:\s|$)/i.test(raw)) {
    findings.push({
      code: 'SPF_MISSING_OR_INVALID',
      severity: 'critical',
      message: 'SPF TXT record is missing or does not start with `v=spf1`.',
      fix: 'Publish a valid `v=spf1 include:<provider> ~all` TXT record at the sending domain apex.'
    });
    return {
      ok: true,
      valid: false,
      dnsLookups: 0,
      maxLookups: 10,
      findings,
      findingCodes: findings.map((f) => f.code)
    };
  }

  const tokens = raw.split(/\s+/).slice(1);
  let dnsLookups = 0;
  let hasPermissiveAll = false;
  let hasPtr = false;

  for (const tok of tokens) {
    const t = tok.toLowerCase();
    const stripped = t.replace(/^[+\-~?]/, '');
    if (
      stripped.startsWith('include:')
      || stripped === 'a' || stripped.startsWith('a:') || stripped.startsWith('a/')
      || stripped === 'mx' || stripped.startsWith('mx:') || stripped.startsWith('mx/')
      || stripped === 'ptr' || stripped.startsWith('ptr:')
      || stripped.startsWith('exists:')
      || t.startsWith('redirect=')
    ) {
      dnsLookups++;
      if (stripped === 'ptr' || stripped.startsWith('ptr:')) hasPtr = true;
    }
    if (t === '+all' || t === 'all') {
      hasPermissiveAll = true;
    }
  }

  if (dnsLookups > 10) {
    findings.push({
      code: 'SPF_LOOKUP_LIMIT_EXCEEDED',
      severity: 'critical',
      message: `SPF record performs ${dnsLookups} DNS lookups (exceeds RFC 7208 hard limit of 10 -> PermError bounces).`,
      fix: 'Flatten or prune unused `include:` mechanisms so total DNS lookups stay <= 10.'
    });
  }

  if (hasPermissiveAll) {
    findings.push({
      code: 'SPF_PERMISSIVE_ALL',
      severity: 'critical',
      message: 'SPF record ends with `+all` (allows any IP on the Internet to spoof your domain).',
      fix: 'Replace `+all` with `~all` (softfail) or `-all` (hardfail).'
    });
  }

  if (hasPtr) {
    findings.push({
      code: 'SPF_PTR_DEPRECATED',
      severity: 'medium',
      message: 'SPF record uses deprecated `ptr` mechanism (RFC 7208 §5.5).',
      fix: 'Replace `ptr` with explicit `ip4:`/`ip6:` or `include:` entries.'
    });
  }

  return {
    ok: true,
    valid: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length === 0,
    dnsLookups,
    maxLookups: 10,
    findings,
    findingCodes: findings.map((f) => f.code)
  };
}

/**
 * Comprueba alineación organizacional básica entre el dominio `From:` y el dominio configurado.
 * @param {string} domain
 * @param {string} fromAddress
 */
function isFromAligned(domain, fromAddress) {
  const d = String(domain || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const f = String(fromAddress || '').trim().toLowerCase();
  if (!d || !f) return true;
  const fromDomain = f.includes('@') ? f.split('@').pop() || '' : f;
  if (!fromDomain) return false;
  return fromDomain === d || fromDomain.endsWith(`.${d}`);
}

/**
 * Genera el bloque de registros DNS endurecidos (SPF + DKIM 2048 + DMARC + MTA-STS, `dryRun: true` por defecto).
 *
 * @param {{
 *   domain?: string,
 *   providerInclude?: string,
 *   selector?: string,
 *   dmarcRua?: string,
 *   dryRun?: boolean
 * }} [options]
 */
function renderHardenedDnsAuthRecords(options = {}) {
  const opts = options || {};
  const domain = String(opts.domain || 'example.com').trim().toLowerCase() || 'example.com';
  const providerInclude = String(opts.providerInclude || '_spf.resend.com').trim();
  const selector = String(opts.selector || 'culkibo2026').trim();
  const dmarcRua = String(opts.dmarcRua || `dmarc@${domain}`).trim();
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;

  const records = [
    { type: 'TXT', host: domain, value: `v=spf1 include:${providerInclude} ~all` },
    { type: 'TXT', host: `${selector}._domainkey.${domain}`, value: 'v=DKIM1; k=rsa; p=<2048-BIT-PUBLIC-KEY-BASE64>' },
    { type: 'TXT', host: `_dmarc.${domain}`, value: `v=DMARC1; p=quarantine; sp=quarantine; adkim=s; aspf=s; pct=100; rua=mailto:${dmarcRua}` },
    { type: 'TXT', host: `_mta-sts.${domain}`, value: 'v=STSv1; id=2026112801' },
    { type: 'TXT', host: `_smtp._tls.${domain}`, value: `v=TLSRPTv1; rua=mailto:${dmarcRua}` }
  ];

  const dnsRecordsBlock = [
    `; Hardened Transactional Email DNS Zone for ${domain}`,
    ...records.map((r) => `${r.host}.  300  IN  ${r.type}  "${r.value}"`),
    `; HTTPS MTA-STS policy at https://mta-sts.${domain}/.well-known/mta-sts.txt:`,
    '; version: STSv1 | mode: enforce | max_age: 604800'
  ].join('\n');

  return {
    ok: true,
    dryRun,
    domain,
    records,
    dnsRecordsBlock
  };
}

/**
 * Audita SPF, DKIM, DMARC, alineación `From:`, MTA-STS y paridad puerto/TLS SMTP (`Coolify#4311`).
 *
 * @param {{
 *   domain?: string,
 *   fromAddress?: string,
 *   spfTxt?: string,
 *   dkimBits?: number,
 *   dkimSelector?: string,
 *   dmarcTxt?: string,
 *   mtaStsMode?: string,
 *   smtpPort?: number,
 *   smtpTlsMode?: string,
 *   persist?: boolean
 * }} [input]
 */
function auditEmailDeliverability(input = {}) {
  const opts = input || {};
  const domain = String(opts.domain || 'example.com').trim().toLowerCase() || 'example.com';
  const fromAddress = String(opts.fromAddress || `noreply@${domain}`).trim();
  const spfTxt = String(opts.spfTxt || '');
  const dkimBits = Math.max(0, Math.floor(Number(opts.dkimBits ?? 2048) || 0));
  const dkimSelector = String(opts.dkimSelector || 'culkibo2026').trim();
  const dmarcTxt = String(opts.dmarcTxt || '').trim();
  const mtaStsMode = String(opts.mtaStsMode || 'enforce').trim().toLowerCase();
  const smtpPort = Math.floor(Number(opts.smtpPort ?? 587) || 587);
  const smtpTlsMode = String(opts.smtpTlsMode || (smtpPort === 465 ? 'implicit_tls' : 'starttls')).trim().toLowerCase();

  const spfAudit = auditSpfRecord(spfTxt);
  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [...spfAudit.findings];

  // 1. DKIM key strength (>= 2048 bits required)
  if (dkimBits < 2048) {
    findings.push({
      code: 'DKIM_KEY_TOO_WEAK',
      severity: 'critical',
      message: `DKIM key (${dkimSelector}) is ${dkimBits}-bit (must be >= 2048-bit RSA or Ed25519 for 2025-2026 inbox delivery).`,
      fix: 'Rotate DKIM selector to a 2048-bit RSA keypair and publish the new TXT record.'
    });
  }

  // 2. DMARC presence + From: alignment
  const hasValidDmarc = /^v=DMARC1\b/i.test(dmarcTxt);
  const aligned = isFromAligned(domain, fromAddress);
  if (!hasValidDmarc || !aligned) {
    findings.push({
      code: 'DMARC_MISSING_OR_UNALIGNED',
      severity: 'critical',
      message: !hasValidDmarc
        ? `DMARC record is missing/invalid for "${domain}" (rejected by Gmail/Yahoo/Microsoft bulk sender policy).`
        : `MAIL_FROM "${fromAddress}" is NOT domain-aligned with "${domain}" — DMARC alignment will fail.`,
      fix: `Publish _dmarc.${domain} with v=DMARC1; p=quarantine; and send From an address matching @${domain}.`
    });
  } else if (/\bp=none\b/i.test(dmarcTxt)) {
    findings.push({
      code: 'DMARC_POLICY_NONE_WARNING',
      severity: 'medium',
      message: `DMARC for "${domain}" is in monitor-only mode (p=none); spoofing is not quarantined/rejected.`,
      fix: 'Promote DMARC policy from p=none to p=quarantine or p=reject once reports confirm 100% alignment.'
    });
  }

  // 3. MTA-STS enforcement
  if (mtaStsMode !== 'enforce') {
    findings.push({
      code: 'MTA_STS_NOT_ENFORCED',
      severity: 'medium',
      message: `MTA-STS mode is "${mtaStsMode}" (expected "enforce") leaving inbound/relay SMTP open to STARTTLS downgrade.`,
      fix: 'Host /.well-known/mta-sts.txt with mode: enforce and publish _mta-sts TXT record.'
    });
  }

  // 4. SMTP port vs TLS mode parity (Coolify#4311)
  if (smtpPort === 25) {
    findings.push({
      code: 'BLOCKED_CLOUD_PORT',
      severity: 'critical',
      message: 'SMTP port 25 is blocked by default across Hetzner, AWS, DigitalOcean, and GCP VPS providers.',
      fix: 'Switch outbound SMTP submission to port 587 (starttls) or port 465 (implicit_tls).'
    });
  } else if (smtpPort === 465 && smtpTlsMode !== 'implicit_tls' && smtpTlsMode !== 'tls' && smtpTlsMode !== 'ssl') {
    findings.push({
      code: 'SMTP_TLS_MISMATCH',
      severity: 'critical',
      message: `SMTP port 465 configured with tlsMode="${smtpTlsMode}" (requires implicit_tls/ssl — Coolify#4311).`,
      fix: 'Set smtpTlsMode="implicit_tls" for port 465 or move to port 587 with starttls.'
    });
  } else if (smtpPort === 587 && smtpTlsMode !== 'starttls') {
    findings.push({
      code: 'SMTP_TLS_MISMATCH',
      severity: 'critical',
      message: `SMTP port 587 configured with tlsMode="${smtpTlsMode}" (requires starttls — Coolify#4311).`,
      fix: 'Enable STARTTLS on port 587 (or switch to port 465 with implicit_tls).'
    });
  }

  const criticalOrHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const safe = findings.length === 0;
  const blocked = criticalOrHigh > 0;
  const status = blocked ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'PASS');
  const rendered = renderHardenedDnsAuthRecords({ domain, selector: dkimSelector, dryRun: true });
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `mail_${crypto.randomBytes(5).toString('hex')}`,
    domain,
    fromAddress,
    safe,
    blocked,
    status,
    spfLookups: spfAudit.dnsLookups,
    dkimBits,
    mtaStsMode,
    smtpPort,
    smtpTlsMode,
    findings,
    findingCodes: findings.map((f) => f.code),
    dnsRecordsBlock: rendered.dnsRecordsBlock,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      domain,
      safe,
      blocked,
      status,
      spfLookups: result.spfLookups,
      findingCodes: result.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Lista auditorías de entregabilidad de email almacenadas (más recientes primero).
 * @param {string} [domain]
 */
function listEmailAuthAudits(domain) {
  const store = loadStore();
  const cleanDom = domain ? String(domain).trim().toLowerCase() : '';
  const items = cleanDom
    ? store.audits.filter((a) => a.domain === cleanDom)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditSpfRecord,
  auditEmailDeliverability,
  renderHardenedDnsAuthRecords,
  listEmailAuthAudits
};
