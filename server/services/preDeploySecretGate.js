const crypto = require('crypto');

/**
 * Pre-Deploy Shannon-Entropy & Pattern Secret Gate (100% Zero-Dep Pure JS).
 *
 * Inspirado en Gitleaks / TruffleHog para despliegues PaaS shift-left:
 * escanea diffs de Git, archivos `.env`, Compose y `envMap` en sub-milisegundos
 * antes de arrancar un build.
 *
 * Invariantes de seguridad:
 *  - JAMÁS hace eco ni persiste el secreto original en resultados (`redactedPreview` + `fingerprintSha256`).
 *  - Filtra falsos positivos benignos (UUID RFC 4122, hashes SHA-1/SHA-256 hex, placeholders y `# culkibo:allow-secret`).
 *  - Cero prefijos de tokens literales en código fuente (100% Push-Protection `GH013` clean).
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PURE_HEX_HASH_RE = /^(?:sha(?:1|256|512):)?[0-9a-f]{32,128}$/i;
const PLACEHOLDER_RE = /^(?:\$\{?[A-Za-z0-9_.-]+\}?|\[REDACTED\]|\[MASKED_SECRET\])$/i;
const PLACEHOLDER_WORD_RE = /(?:changeme|your[_-]?api[_-]?key|example[_-]?(?:key|token|secret)|replace[_-]?me|placeholder|dummy[_-]?(?:key|token|secret)|<[^>]+>|xxxx{2,})/i;
const ALLOW_PRAGMA_RE = /(?:#|\/\/)\s*culkibo:allow-secret\b/i;

/**
 * Calcula la entropía de Shannon (bits por carácter) de una cadena.
 * @param {string} str
 * @returns {number}
 */
function computeShannonEntropy(str) {
  const s = String(str || '');
  if (!s.length) return 0;
  /** @type {Map<string, number>} */
  const freq = new Map();
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

/**
 * Construye las 12 reglas deterministas dinámicamente (cero literales GH013 en código fuente).
 */
const SECRET_RULES = Object.freeze([
  Object.freeze({
    id: 'PEM_PRIVATE_KEY',
    severity: 'critical',
    title: 'PEM-encoded private key material detected',
    pattern: new RegExp('-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?' + 'PRIVATE KEY-----', 'g')
  }),
  Object.freeze({
    id: 'JWT_TOKEN',
    severity: 'high',
    title: 'Hardcoded JSON Web Token (JWT) detected',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g
  }),
  Object.freeze({
    id: 'AWS_ACCESS_KEY',
    severity: 'critical',
    title: 'AWS IAM access key ID detected',
    pattern: new RegExp('\\b(?:' + 'AK' + 'IA|' + 'AS' + 'IA)[0-9A-Z]{16}\\b', 'g')
  }),
  Object.freeze({
    id: 'GITHUB_TOKEN',
    severity: 'critical',
    title: 'GitHub personal/OAuth/fine-grained access token detected',
    pattern: new RegExp('\\b(?:' + 'gh' + '[pousr]_[A-Za-z0-9]{16,}|' + 'github' + '_pat_[A-Za-z0-9_]{20,})\\b', 'g')
  }),
  Object.freeze({
    id: 'GITLAB_TOKEN',
    severity: 'critical',
    title: 'GitLab personal access token detected',
    pattern: new RegExp('\\b' + 'gl' + 'pat-[A-Za-z0-9_-]{16,}\\b', 'g')
  }),
  Object.freeze({
    id: 'STRIPE_PAYMENT_KEY',
    severity: 'critical',
    title: 'Payment provider secret/restricted API key detected',
    pattern: new RegExp('\\b(?:' + 'sk' + '|' + 'rk' + ')_(?:live|test)_[A-Za-z0-9]{12,}\\b', 'g')
  }),
  Object.freeze({
    id: 'SLACK_TOKEN',
    severity: 'high',
    title: 'Slack bot/user/app API token detected',
    pattern: new RegExp('\\b' + 'xox' + '[baprs]-[A-Za-z0-9-]{12,}\\b', 'g')
  }),
  Object.freeze({
    id: 'GENERIC_BEARER_OR_API_KEY',
    severity: 'high',
    title: 'Hardcoded Bearer token or API/auth credential assignment detected',
    pattern: /(?:\bBearer\s+([A-Za-z0-9._~+/-]{16,}=*)|\b(?:api_?key|auth_?token|access_?token|client_?secret|signing_?secret|app_?secret)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})["']?)/gi
  }),
  Object.freeze({
    id: 'DATABASE_URI_PASSWORD',
    severity: 'critical',
    title: 'Database or broker connection URI contains embedded password',
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s'"`]+:([^@\s'"`]{4,})@[^\s'"`]+/gi
  }),
  Object.freeze({
    id: 'WEBHOOK_SIGNING_SECRET',
    severity: 'high',
    title: 'Webhook signing secret detected',
    pattern: new RegExp('\\b' + 'wh' + 'sec_[A-Za-z0-9]{16,}\\b', 'g')
  }),
  Object.freeze({
    id: 'CLOUD_SERVICE_ACCOUNT_KEY',
    severity: 'critical',
    title: 'Cloud service-account private_key JSON field detected',
    pattern: /"private_key(?:_id)?"\s*:\s*"([^"]{24,})"/gi
  }),
  Object.freeze({
    id: 'HIGH_ENTROPY_ASSIGNMENT',
    severity: 'high',
    title: 'High-entropy secret assignment (Shannon entropy >= 4.2, length >= 20)',
    pattern: /\b(?:[A-Za-z_][A-Za-z0-9_.-]{1,48})\s*[:=]\s*["']?([A-Za-z0-9_/+=-]{20,})["']?/g
  })
]);

/**
 * Devuelve una vista redactada (primeros 4 / últimos 2 chars) sin exponer nunca el secreto.
 * @param {string} secret
 * @param {string} ruleId
 */
function redactSecretPreview(secret, ruleId) {
  const s = String(secret || '');
  if (ruleId === 'PEM_PRIVATE_KEY') return '-----***[REDACTED_PEM]***-----';
  if (s.length <= 10) return '[REDACTED]';
  return `${s.slice(0, 4)}***[REDACTED]***${s.slice(-2)}`;
}

/**
 * Determina si un valor candidato es benigno (UUID, hash SHA hex, placeholder, URL o ruta).
 * @param {string} val
 * @param {string} ruleId
 */
function isBenignValue(val, ruleId) {
  const s = String(val || '').trim();
  if (!s) return true;
  if (PLACEHOLDER_RE.test(s) || PLACEHOLDER_WORD_RE.test(s)) return true;
  if (ruleId === 'CLOUD_SERVICE_ACCOUNT_KEY' || ruleId === 'PEM_PRIVATE_KEY') return false;
  if (UUID_RE.test(s)) return true;
  if (PURE_HEX_HASH_RE.test(s)) return true;
  if (/^https?:\/\//i.test(s) && ruleId !== 'DATABASE_URI_PASSWORD') return true;
  if (/^\/[A-Za-z0-9_./-]+$/.test(s) && ruleId === 'HIGH_ENTROPY_ASSIGNMENT') return true;
  return false;
}

/**
 * Escanea un contenido multilínea (archivo, diff o `.env`) línea por línea.
 * @param {string} location
 * @param {string} content
 * @param {boolean} isDiff
 * @param {Set<string>} allowSet
 * @param {Array<{ location: string, line: number, ruleId: string, severity: string, entropy: number, redactedPreview: string, fingerprintSha256: string }>} findings
 */
function scanTextBlock(location, content, isDiff, allowSet, findings) {
  const lines = String(content || '').split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    let rawLine = lines[idx];
    const lineNum = idx + 1;

    if (isDiff) {
      if (
        rawLine.startsWith('diff --git ')
        || rawLine.startsWith('index ')
        || rawLine.startsWith('+++ ')
        || rawLine.startsWith('--- ')
        || rawLine.startsWith('@@ ')
      ) {
        continue;
      }
      // Ignorar líneas eliminadas en un git diff (no se están introduciendo)
      if (rawLine.startsWith('-')) continue;
      if (rawLine.startsWith('+')) rawLine = rawLine.slice(1);
    }

    if (!rawLine.trim()) continue;
    if (ALLOW_PRAGMA_RE.test(rawLine)) continue;

    /** @type {Set<string>} */
    const matchedSecretsOnLine = new Set();

    for (const rule of SECRET_RULES) {
      const re = new RegExp(rule.pattern.source, rule.pattern.flags);
      let m;
      while ((m = re.exec(rawLine)) !== null) {
        const candidate = String(m[1] || m[2] || m[0] || '').trim();
        if (!candidate) continue;
        if (isBenignValue(candidate, rule.id)) continue;

        const entropy = computeShannonEntropy(candidate);

        if (rule.id === 'HIGH_ENTROPY_ASSIGNMENT') {
          if (candidate.length < 20 || entropy < 4.2) continue;
          // Evitar duplicar un secreto ya detectado por una regla más específica en la misma línea
          if (matchedSecretsOnLine.has(candidate)) continue;
          // Evitar falsos positivos en identificadores CamelCase/snake_case puramente alfabéticos sin mezcla
          const hasDigitOrSymbol = /[0-9_/+=-]/.test(candidate);
          const hasUpperAndLower = /[A-Z]/.test(candidate) && /[a-z]/.test(candidate);
          if (!hasDigitOrSymbol && !hasUpperAndLower) continue;
        }

        if (rule.id === 'GENERIC_BEARER_OR_API_KEY' && entropy < 3.0) {
          continue;
        }

        const fingerprintSha256 = crypto
          .createHash('sha256')
          .update(`${rule.id}:${candidate}`, 'utf8')
          .digest('hex');

        const rawFingerprint = crypto
          .createHash('sha256')
          .update(candidate, 'utf8')
          .digest('hex');

        if (allowSet.has(fingerprintSha256) || allowSet.has(rawFingerprint)) {
          matchedSecretsOnLine.add(candidate);
          continue;
        }

        if (matchedSecretsOnLine.has(candidate)) continue;
        matchedSecretsOnLine.add(candidate);

        findings.push({
          location,
          line: lineNum,
          ruleId: rule.id,
          severity: rule.severity,
          entropy,
          redactedPreview: redactSecretPreview(candidate, rule.id),
          fingerprintSha256
        });
      }
    }
  }
}

/**
 * Escanea archivos, diffs y mapas de entorno antes del despliegue para bloquear fugas de secretos.
 *
 * @param {{
 *   files?: Array<{ path?: string, name?: string, content?: string }>,
 *   diffText?: string,
 *   envMap?: Record<string, any>,
 *   mode?: 'enforce' | 'warn' | string,
 *   allowlistFingerprints?: string[]
 * }} [input]
 */
function scanPreDeployPayload(input = {}) {
  const opts = input || {};
  const rawMode = String(opts.mode || 'enforce').trim().toLowerCase();
  const mode = rawMode === 'warn' ? 'warn' : 'enforce';
  const files = Array.isArray(opts.files) ? opts.files : [];
  const diffText = typeof opts.diffText === 'string' ? opts.diffText : '';
  const envMap = (opts.envMap && typeof opts.envMap === 'object' && !Array.isArray(opts.envMap))
    ? opts.envMap
    : {};
  const allowSet = new Set(
    (Array.isArray(opts.allowlistFingerprints) ? opts.allowlistFingerprints : [])
      .map((fp) => String(fp || '').trim().toLowerCase())
      .filter(Boolean)
  );

  /** @type {Array<{ location: string, line: number, ruleId: string, severity: string, entropy: number, redactedPreview: string, fingerprintSha256: string }>} */
  const findings = [];
  let scannedItems = 0;

  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (!f || typeof f !== 'object') continue;
    const loc = String(f.path || f.name || `file#${i + 1}`);
    scannedItems++;
    scanTextBlock(loc, String(f.content || ''), false, allowSet, findings);
  }

  if (diffText.trim()) {
    scannedItems++;
    const looksLikeUnifiedDiff = /^(?:diff --git |@@ |\+\+\+ |--- )/m.test(diffText);
    scanTextBlock('diff', diffText, looksLikeUnifiedDiff, allowSet, findings);
  }

  for (const [k, v] of Object.entries(envMap)) {
    scannedItems++;
    scanTextBlock(`env:${k}`, `${k}=${String(v ?? '')}`, false, allowSet, findings);
  }

  const blockedCount = findings.length;
  const allowed = mode === 'warn' ? true : blockedCount === 0;

  return {
    ok: true,
    allowed,
    mode,
    scannedItems,
    blockedCount,
    findings
  };
}

module.exports = {
  computeShannonEntropy,
  SECRET_RULES,
  scanPreDeployPayload
};
