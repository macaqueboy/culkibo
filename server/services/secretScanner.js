/**
 * Escáner pre-despliegue de fugas de secretos (cero dependencias npm, cero shell, inmune a ReDoS).
 *
 * Detecta credenciales en claro (AWS, Stripe, GitHub, GitLab, OpenAI/Anthropic, GCP, Slack,
 * Discord, claves privadas PEM, URIs de BD con contraseña, JWT, tokens Culkibo, npm/PyPI/SendGrid
 * y valores de alta entropía en claves sensibles) antes de desplegar o exportar YAML/Compose.
 *
 * Garantías:
 *  - Jamás reproduce el secreto completo en los hallazgos (siempre devuelve `preview` enmascarado).
 *  - Ignora referencias seguras `${vault.KEY}`, `${VAR}`, `$VAR`, `{{...}}` y marcadores de ejemplo.
 *  - Todas las expresiones regulares están acotadas en longitud (tiempo lineal O(n), cero ReDoS).
 */

const MAX_SCAN_BYTES = 1024 * 1024;
const MAX_FINDINGS = 200;

const SAFE_REF_RE = /^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|\[REDACTED(?:_[A-Z0-9_]+)?\]|<redacted>)$/i;
const PLACEHOLDER_RE = /(?:^|[_-])(changeme|change[_-]?me|example|placeholder|dummy|sample|fake|replace[_-]?me|your[_-]?[a-z0-9_-]*[_-]?here|insert[_-]?here|todo|test[_-]?only|not[_-]?a[_-]?secret)(?:$|[_-])/i;
const SENSITIVE_KEY_NAME_RE = /(secret|token|pass(?:word|wd|phrase)?|api[_-]?key|private[_-]?key|auth(?:_?token)?|cred(?:ential)?s?|signing|encryption|master[_-]?key|webhook|dsn|database[_-]?url|db[_-]?url|redis[_-]?url|mongo[_-]?url|aws[_-]?secret|stripe|openai|anthropic|gemini|github|gitlab|cloudflare|jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret)/i;
const SAFE_KEY_ALLOWLIST = new Set([
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'TZ', 'LOG_LEVEL', 'DEBUG',
  'APP_ENV', 'APP_NAME', 'APP_URL', 'PUBLIC_URL', 'BASE_URL', 'SITE_URL',
  'CORS_ORIGIN', 'WORKERS', 'CONCURRENCY', 'TIMEOUT_MS', 'LANG', 'LC_ALL',
  'NEXT_PUBLIC_APP_URL', 'VITE_APP_URL', 'PUBLIC_SITE_URL'
]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PURE_HEX_40_RE = /^[0-9a-f]{32,64}$/i;

/**
 * Reglas de firma acotadas (tiempo lineal, sin cuantificadores anidados).
 * @type {ReadonlyArray<{ id: string, title: string, severity: 'critical' | 'high' | 'medium', re: RegExp, captureGroup?: number }>}
 */
const SECRET_RULES = Object.freeze([
  {
    id: 'aws-access-key-id',
    title: 'AWS Access Key ID hardcoded',
    severity: 'critical',
    re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS Secret Access Key hardcoded',
    severity: 'critical',
    re: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
    captureGroup: 1
  },
  {
    id: 'stripe-live-key',
    title: 'Stripe Live Secret/Restricted Key hardcoded',
    severity: 'critical',
    re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,99}\b/g
  },
  {
    id: 'stripe-test-key',
    title: 'Stripe Test Secret Key hardcoded',
    severity: 'medium',
    re: /\b(?:sk|rk)_test_[0-9A-Za-z]{16,99}\b/g
  },
  {
    id: 'stripe-webhook-secret',
    title: 'Stripe Webhook Signing Secret hardcoded',
    severity: 'high',
    re: /\bwhsec_[0-9A-Za-z]{20,128}\b/g
  },
  {
    id: 'github-token',
    title: 'GitHub Personal/OAuth/Fine-Grained Token hardcoded',
    severity: 'critical',
    re: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g
  },
  {
    id: 'gitlab-pat',
    title: 'GitLab Personal Access Token hardcoded',
    severity: 'critical',
    re: /\bglpat-[A-Za-z0-9_-]{16,100}\b/g
  },
  {
    id: 'openai-anthropic-key',
    title: 'OpenAI / Anthropic API Key hardcoded',
    severity: 'critical',
    re: /\bsk-(?:proj-|ant-api\d*-|svcacct-)[A-Za-z0-9_-]{20,180}\b/g
  },
  {
    id: 'gcp-api-key',
    title: 'Google Cloud API Key hardcoded',
    severity: 'high',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    id: 'slack-token',
    title: 'Slack API Token hardcoded',
    severity: 'high',
    re: /\bxox[baprs]-[0-9A-Za-z-]{16,120}\b/g
  },
  {
    id: 'slack-webhook',
    title: 'Slack Incoming Webhook URL hardcoded',
    severity: 'high',
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,16}\/B[A-Z0-9]{6,16}\/[A-Za-z0-9]{16,64}/g
  },
  {
    id: 'discord-webhook',
    title: 'Discord Webhook URL hardcoded',
    severity: 'high',
    re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,22}\/[A-Za-z0-9_-]{32,120}/g
  },
  {
    id: 'private-key-pem',
    title: 'PEM Private Key block hardcoded',
    severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
  },
  {
    id: 'db-uri-credentials',
    title: 'Database / Broker URI with inline password',
    severity: 'high',
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^:\s/@"'`]{1,64}:([^@\s/"'`]{3,128})@[^\s/"'`]{1,200}/gi,
    captureGroup: 1
  },
  {
    id: 'jwt-token',
    title: 'Signed JWT Token hardcoded',
    severity: 'high',
    re: /\beyJ[A-Za-z0-9_-]{10,400}\.eyJ[A-Za-z0-9_-]{10,800}\.[A-Za-z0-9_-]{16,400}\b/g
  },
  {
    id: 'culkibo-token',
    title: 'Culkibo Control-Plane Session/API/Invite Token hardcoded',
    severity: 'critical',
    re: /\b(?:cks|ckp|cki|ckh|ckm)_[A-Za-z0-9._-]{16,256}\b/g
  },
  {
    id: 'npm-token',
    title: 'npm Registry Access Token hardcoded',
    severity: 'critical',
    re: /\bnpm_[A-Za-z0-9]{24,80}\b/g
  },
  {
    id: 'pypi-token',
    title: 'PyPI API Token hardcoded',
    severity: 'critical',
    re: /\bpypi-[A-Za-z0-9_-]{32,200}\b/g
  },
  {
    id: 'sendgrid-key',
    title: 'SendGrid API Key hardcoded',
    severity: 'high',
    re: /\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,80}\b/g
  }
]);

/**
 * Calcula la entropía de Shannon (bits por carácter) de una cadena.
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
  if (typeof str !== 'string' || str.length === 0) return 0;
  /** @type {Map<string, number>} */
  const freq = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let h = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Enmascara un secreto detectado para que JAMÁS aparezca en claro en logs, APIs o UI.
 * @param {string} raw
 * @returns {string}
 */
function maskSecret(raw) {
  const s = String(raw || '').trim();
  if (!s) return '[REDACTED]';
  if (s.includes('PRIVATE KEY')) return '[REDACTED_PEM]';
  if (s.length <= 8) return '****';
  const head = s.slice(0, Math.min(4, Math.floor(s.length / 4)));
  const tail = s.slice(-2);
  return `${head}****${tail}`;
}

/**
 * Comprueba si un valor es una referencia segura (`${vault.KEY}` / `$VAR`) o un placeholder inofensivo.
 * @param {string} val
 * @returns {boolean}
 */
function isSafeOrPlaceholderValue(val) {
  const trimmed = String(val || '').trim();
  if (!trimmed) return true;
  if (SAFE_REF_RE.test(trimmed)) return true;
  if (/^\$\{vault\.[A-Za-z_][A-Za-z0-9_]*\}$/.test(trimmed)) return true;
  if (trimmed.includes('${') && trimmed.includes('}')) return true;
  if (/^(.)\1{5,}$/.test(trimmed)) return true; // repetitivo tipo xxxxxx / 000000
  if (PLACEHOLDER_RE.test(trimmed)) return true;
  return false;
}

/**
 * Evalúa si un valor asignado a una clave sensible parece un secreto de alta entropía.
 * @param {string} key
 * @param {string} value
 * @returns {boolean}
 */
function isHighEntropySecret(key, value) {
  const k = String(key || '').trim();
  const v = String(value || '').trim();
  if (!k || !v) return false;
  if (SAFE_KEY_ALLOWLIST.has(k.toUpperCase())) return false;
  if (!SENSITIVE_KEY_NAME_RE.test(k)) return false;
  if (isSafeOrPlaceholderValue(v)) return false;
  if (v.length < 20 || v.length > 512) return false;
  if (/\s/.test(v)) return false;
  if (/^https?:\/\/[^@]+$/i.test(v)) return false;
  if (UUID_RE.test(v)) return false;
  if (/^[a-z0-9_./-]+$/i.test(v) && v.includes('/') && !/[+=]/.test(v) && v.startsWith('/')) return false;

  const hasLower = /[a-z]/.test(v);
  const hasUpper = /[A-Z]/.test(v);
  const hasDigit = /\d/.test(v);
  const hasSym = /[^A-Za-z0-9]/.test(v);
  const classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSym ? 1 : 0);
  if (classes < 2) return false;
  if (PURE_HEX_40_RE.test(v) && shannonEntropy(v) < 3.4) return false;

  return shannonEntropy(v) >= (PURE_HEX_40_RE.test(v) ? 3.5 : 4.0);
}

/**
 * @typedef {{
 *   ruleId: string,
 *   title: string,
 *   severity: 'critical' | 'high' | 'medium' | 'low',
 *   source: string,
 *   key: string | null,
 *   line: number | null,
 *   preview: string,
 *   remediation: string
 * }} SecretFinding
 */

/**
 * Escanea un bloque de texto libre línea por línea buscando firmas de secretos.
 * @param {string} text
 * @param {{ source?: string, maxBytes?: number, includeEntropy?: boolean }} [opts]
 * @returns {SecretFinding[]}
 */
function scanText(text, opts = {}) {
  if (typeof text !== 'string' || !text) return [];
  const source = String(opts.source || 'text');
  const maxBytes = Math.min(MAX_SCAN_BYTES, Math.max(1024, Number(opts.maxBytes) || MAX_SCAN_BYTES));
  const includeEntropy = opts.includeEntropy !== false;
  const bounded = text.length > maxBytes ? text.slice(0, maxBytes) : text;

  /** @type {SecretFinding[]} */
  const findings = [];
  const seen = new Set();
  const lines = bounded.split(/\r?\n/);

  for (let i = 0; i < lines.length && findings.length < MAX_FINDINGS; i++) {
    const lineText = lines[i];
    const trimmed = lineText.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    // Extraer posible par KEY=VALUE o key: value o Dockerfile ENV/ARG KEY=VALUE
    let detectedKey = /** @type {string | null} */ (null);
    let detectedVal = /** @type {string | null} */ (null);
    const kvMatch =
      trimmed.match(/^(?:(?:ENV|ARG|export)\s+)?([A-Za-z_][A-Za-z0-9_.-]{1,127})\s*[:=]\s*["']?(.+?)["']?$/i);
    if (kvMatch) {
      detectedKey = kvMatch[1];
      detectedVal = kvMatch[2].trim();
    }

    let ruleHitOnLine = false;
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(lineText)) !== null && findings.length < MAX_FINDINGS) {
        const matchedSecret = rule.captureGroup ? (m[rule.captureGroup] || m[0]) : m[0];
        if (isSafeOrPlaceholderValue(matchedSecret)) continue;
        // Evitar falsos positivos si toda la asignación es una referencia vault
        if (detectedVal && isSafeOrPlaceholderValue(detectedVal) && rule.id !== 'private-key-pem') continue;

        const dedupKey = `${source}:${i + 1}:${rule.id}:${m.index}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);
        ruleHitOnLine = true;

        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          source,
          key: detectedKey,
          line: i + 1,
          preview: maskSecret(matchedSecret),
          remediation: detectedKey
            ? `Guarda "${detectedKey}" en el Vault cifrado de Culkibo y referéncialo como \${vault.${detectedKey.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}}.`
            : 'Mueve esta credencial al Vault cifrado de Culkibo o a variables de entorno gestionadas y rota el secreto comprometido.'
        });
      }
    }

    // Comprobación GCP Service Account JSON en una línea o clave+valor de alta entropía
    if (!ruleHitOnLine && includeEntropy && detectedKey && detectedVal) {
      if (isHighEntropySecret(detectedKey, detectedVal)) {
        findings.push({
          ruleId: 'high-entropy-secret',
          title: `High-entropy secret assigned to sensitive key "${detectedKey}"`,
          severity: 'high',
          source,
          key: detectedKey,
          line: i + 1,
          preview: maskSecret(detectedVal),
          remediation: `Sustituye el literal en "${detectedKey}" por \${vault.${detectedKey.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}}.`
        });
      }
    }
  }

  // Detección multilínea específica para GCP Service Account JSON
  if (findings.length < MAX_FINDINGS && /"type"\s*:\s*"service_account"/.test(bounded) && /"private_key"\s*:/.test(bounded)) {
    const alreadyPem = findings.some((f) => f.ruleId === 'private-key-pem');
    if (!alreadyPem) {
      findings.push({
        ruleId: 'gcp-service-account-json',
        title: 'GCP Service Account JSON credentials hardcoded',
        severity: 'critical',
        source,
        key: 'private_key',
        line: null,
        preview: '[REDACTED_GCP_SA]',
        remediation: 'Almacena el JSON de cuenta de servicio GCP en el Vault cifrado de Culkibo y nunca lo incluyas en manifiestos.'
      });
    }
  }

  return findings;
}

/**
 * Escanea un mapa clave-valor de variables de entorno o `buildArgs`.
 * @param {Record<string, any> | null | undefined} envObj
 * @param {{ source?: string, includeEntropy?: boolean }} [opts]
 * @returns {SecretFinding[]}
 */
function scanEnvVars(envObj, opts = {}) {
  if (!envObj || typeof envObj !== 'object' || Array.isArray(envObj)) return [];
  const source = String(opts.source || 'env');
  const includeEntropy = opts.includeEntropy !== false;
  /** @type {SecretFinding[]} */
  const findings = [];

  for (const [rawKey, rawVal] of Object.entries(envObj)) {
    if (findings.length >= MAX_FINDINGS) break;
    const key = String(rawKey || '').trim();
    const val = rawVal == null ? '' : String(rawVal);
    if (!key || !val || isSafeOrPlaceholderValue(val)) continue;

    let hit = false;
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      const targetStr = rule.id === 'aws-secret-access-key' ? `${key}=${val}` : val;
      const m = rule.re.exec(targetStr);
      if (m) {
        const matched = rule.captureGroup ? (m[rule.captureGroup] || m[0]) : m[0];
        if (isSafeOrPlaceholderValue(matched)) continue;
        hit = true;
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          source,
          key,
          line: null,
          preview: maskSecret(matched),
          remediation: `Mueve "${key}" al Vault cifrado (\${vault.${key.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}}) o a secrets de entorno.`
        });
        break;
      }
    }

    if (!hit && includeEntropy && isHighEntropySecret(key, val)) {
      findings.push({
        ruleId: 'high-entropy-secret',
        title: `High-entropy secret in "${key}"`,
        severity: 'high',
        source,
        key,
        line: null,
        preview: maskSecret(val),
        remediation: `Almacena "${key}" en el Vault cifrado y referéncialo como \${vault.${key.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}}.`
      });
    }
  }

  return findings;
}

/**
 * Escanea ficheros `docker-compose.yml`, `culkibo.yaml` o `Dockerfile`.
 * @param {string} yamlOrDockerText
 * @param {{ source?: string, includeEntropy?: boolean }} [opts]
 * @returns {SecretFinding[]}
 */
function scanComposeOrYaml(yamlOrDockerText, opts = {}) {
  return scanText(yamlOrDockerText, {
    source: opts.source || 'yaml',
    includeEntropy: opts.includeEntropy !== false
  });
}

/**
 * Escanea un payload completo de despliegue o exportación (envVars, buildArgs, compose, YAML, Dockerfile, files).
 * @param {{
 *   envVars?: Record<string, any> | null,
 *   buildArgs?: Record<string, any> | null,
 *   composeYaml?: string | null,
 *   culkiboYaml?: string | null,
 *   dockerfile?: string | null,
 *   text?: string | null,
 *   files?: Array<{ path?: string, content?: string }> | null
 * }} payload
 * @param {{ mode?: 'warn' | 'block', includeEntropy?: boolean }} [opts]
 */
function scanDeploymentPayload(payload = {}, opts = {}) {
  const mode = opts.mode === 'block' ? 'block' : 'warn';
  const includeEntropy = opts.includeEntropy !== false;
  /** @type {SecretFinding[]} */
  const findings = [];

  if (payload && typeof payload === 'object') {
    if (payload.envVars) {
      findings.push(...scanEnvVars(payload.envVars, { source: 'envVars', includeEntropy }));
    }
    if (payload.buildArgs) {
      findings.push(...scanEnvVars(payload.buildArgs, { source: 'buildArgs', includeEntropy }));
    }
    if (typeof payload.composeYaml === 'string' && payload.composeYaml) {
      findings.push(...scanComposeOrYaml(payload.composeYaml, { source: 'compose', includeEntropy }));
    }
    if (typeof payload.culkiboYaml === 'string' && payload.culkiboYaml) {
      findings.push(...scanComposeOrYaml(payload.culkiboYaml, { source: 'culkibo.yaml', includeEntropy }));
    }
    if (typeof payload.dockerfile === 'string' && payload.dockerfile) {
      findings.push(...scanComposeOrYaml(payload.dockerfile, { source: 'Dockerfile', includeEntropy }));
    }
    if (typeof payload.text === 'string' && payload.text) {
      findings.push(...scanText(payload.text, { source: 'text', includeEntropy }));
    }
    if (Array.isArray(payload.files)) {
      for (const f of payload.files.slice(0, 50)) {
        if (f && typeof f.content === 'string' && f.content && findings.length < MAX_FINDINGS) {
          findings.push(...scanText(f.content, { source: String(f.path || 'file').slice(0, 120), includeEntropy }));
        }
      }
    }
  }

  const trimmed = findings.slice(0, MAX_FINDINGS);
  const summary = {
    total: trimmed.length,
    critical: trimmed.filter((f) => f.severity === 'critical').length,
    high: trimmed.filter((f) => f.severity === 'high').length,
    medium: trimmed.filter((f) => f.severity === 'medium').length,
    low: trimmed.filter((f) => f.severity === 'low').length
  };
  const blocked = mode === 'block' && (summary.critical > 0 || summary.high > 0);

  return {
    clean: trimmed.length === 0,
    blocked,
    mode,
    summary,
    findings: trimmed
  };
}

/**
 * Comprueba un payload en modo `block` y lanza un error HTTP 422 si se detectan fugas críticas/altas.
 * @param {Parameters<typeof scanDeploymentPayload>[0]} payload
 * @param {{ includeEntropy?: boolean }} [opts]
 */
function assertCleanForDeploy(payload, opts = {}) {
  const report = scanDeploymentPayload(payload, { ...opts, mode: 'block' });
  if (report.blocked) {
    /** @type {Error & { status?: number, code?: string, report?: ReturnType<typeof scanDeploymentPayload> }} */
    const err = new Error(
      `Despliegue bloqueado: se detectaron ${report.summary.critical + report.summary.high} secreto(s) en claro (${report.findings.map((f) => f.ruleId).slice(0, 5).join(', ')}). Usa \${vault.KEY} antes de continuar.`
    );
    err.status = 422;
    err.code = 'SECRET_LEAK_DETECTED';
    err.report = report;
    throw err;
  }
  return report;
}

module.exports = {
  SECRET_RULES,
  shannonEntropy,
  maskSecret,
  isSafeOrPlaceholderValue,
  isHighEntropySecret,
  scanText,
  scanEnvVars,
  scanComposeOrYaml,
  scanDeploymentPayload,
  assertCleanForDeploy
};
