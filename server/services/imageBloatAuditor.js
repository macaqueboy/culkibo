/**
 * Container Image Layer Bloat & Secret-in-Layer Auditor (100% Zero-Dep Pure JS).
 *
 * Inspirado en Dive / Dockle / Hadolint — cura `coolify#7019`, `coolify#5328`
 * (secretos y `.npmrc` filtrados en capas BuildKit/OCI) y `dokploy#3193`
 * (discos agotados por imágenes gordas y borrados entre capas).
 *
 * Analiza tanto el `Dockerfile` como el historial opcional `historyLayers`
 * (`docker history --format json`) aplicando 8 reglas deterministas sin invocar shell.
 */

const RULES = Object.freeze([
  Object.freeze({
    id: 'SECRET_IN_ENV_OR_ARG',
    severity: 'critical',
    title: 'Plaintext secret, token, or .npmrc baked into ENV/ARG/RUN image layer',
    estimatedSavingsMb: 0,
    fix: 'Remove secrets from ENV/ARG/COPY; pass build-time tokens exclusively via BuildKit --mount=type=secret and inject runtime secrets via Culkibo Vault.'
  }),
  Object.freeze({
    id: 'CROSS_LAYER_DELETE_WASTE',
    severity: 'high',
    title: 'Deleting files in a subsequent RUN layer leaves full bytes trapped in lower OCI layers',
    estimatedSavingsMb: 45,
    fix: 'Combine file creation/extraction and cleanup (`rm -rf ...`) inside the SAME `RUN` instruction or discard build artifacts via a multi-stage copy.'
  }),
  Object.freeze({
    id: 'UNDELETED_PACKAGE_CACHE',
    severity: 'medium',
    title: 'OS or language package manager cache retained inside image layer',
    estimatedSavingsMb: 65,
    fix: 'Clean caches in the same RUN layer: `rm -rf /var/lib/apt/lists/*` (apt), `apk add --no-cache` (Alpine), or `pip install --no-cache-dir` (Python).'
  }),
  Object.freeze({
    id: 'MISSING_MULTI_STAGE',
    severity: 'high',
    title: 'Single-stage build ships full compiler/SDK toolchain into production image',
    estimatedSavingsMb: 280,
    fix: 'Split into a `builder` stage (`FROM ... AS builder`) and a minimal runtime final stage (`-alpine`, `-slim`, or `distroless:nonroot`).'
  }),
  Object.freeze({
    id: 'COPY_ALL_BEFORE_LOCKFILE',
    severity: 'medium',
    title: 'COPY . . before dependency install busts layer cache on every source edit',
    estimatedSavingsMb: 50,
    fix: 'Copy only manifest/lockfiles (`package*.json`, `requirements.txt`, `go.mod`, `Cargo.toml`) first, run install, then `COPY . .`.'
  }),
  Object.freeze({
    id: 'ADD_INSTEAD_OF_COPY',
    severity: 'low',
    title: 'ADD used instead of COPY for local files risks implicit tar/URL side effects',
    estimatedSavingsMb: 5,
    fix: 'Replace `ADD` with `COPY` unless you explicitly rely on local tarball auto-extraction.'
  }),
  Object.freeze({
    id: 'HEAVY_BASE_IMAGE',
    severity: 'medium',
    title: 'Final stage uses a full/heavy base image instead of slim, alpine, or distroless',
    estimatedSavingsMb: 220,
    fix: 'Switch final `FROM` to a pinned `-slim`, `-alpine`, or `gcr.io/distroless/*:nonroot` base image.'
  }),
  Object.freeze({
    id: 'MISSING_NON_ROOT_USER',
    severity: 'high',
    title: 'Final stage runs container process as UID 0 (root)',
    estimatedSavingsMb: 0,
    fix: 'Add `USER node` / `USER 10001` (or use a `:nonroot` distroless/Chainguard final image).'
  })
]);

const RULE_BY_ID = Object.freeze(
  Object.fromEntries(RULES.map((r) => [r.id, r]))
);

const SENSITIVE_KEY_RE = /^(?:[A-Z0-9_]*?(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY|CLIENT_SECRET|SIGNING_KEY|ENCRYPTION_KEY|NPM_TOKEN|GITHUB_TOKEN|STRIPE_[A-Z_]*KEY|AWS_SECRET[A-Z_]*))$/i;

// Build known token patterns dynamically (no verbatim secret prefixes in source)
const TOKEN_PATTERNS = Object.freeze([
  { label: 'stripe_key', re: new RegExp('\\b' + 'sk' + '_(?:live|test)_[A-Za-z0-9]{8,}', 'g') },
  { label: 'github_token', re: new RegExp('\\b' + 'gh' + '[pousr]_[A-Za-z0-9]{12,}', 'g') },
  { label: 'github_pat', re: new RegExp('\\b' + 'github' + '_pat_[A-Za-z0-9_]{16,}', 'g') },
  { label: 'aws_access_key', re: new RegExp('\\b' + 'AK' + 'IA[0-9A-Z]{16}\\b', 'g') },
  { label: 'slack_token', re: new RegExp('\\b' + 'xox' + '[baprs]-[A-Za-z0-9-]{10,}', 'g') },
  { label: 'private_key_pem', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { label: 'dsn_credentials', re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s'"`]+:[^@\s'"`]{3,}@[^\s'"`]+/gi }
]);

const MULTI_STAGE_TEMPLATES = Object.freeze({
  node: [
    'FROM node:22-alpine AS builder',
    'WORKDIR /app',
    'COPY package.json package-lock.json ./',
    'RUN npm ci',
    'COPY . .',
    'RUN npm run build && npm prune --omit=dev',
    '',
    'FROM gcr.io/distroless/nodejs22-debian12:nonroot',
    'WORKDIR /app',
    'ENV NODE_ENV=production',
    'COPY --from=builder --chown=nonroot:nonroot /app/node_modules ./node_modules',
    'COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist',
    'EXPOSE 3000',
    'CMD ["dist/index.js"]'
  ].join('\n'),
  python: [
    'FROM python:3.12-slim AS builder',
    'WORKDIR /app',
    'COPY requirements.txt ./',
    'RUN pip install --no-cache-dir --prefix=/install -r requirements.txt',
    '',
    'FROM python:3.12-slim',
    'RUN adduser --disabled-password --gecos "" appuser',
    'WORKDIR /app',
    'COPY --from=builder /install /usr/local',
    'COPY --chown=appuser:appuser . .',
    'USER appuser',
    'EXPOSE 8000',
    'CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]'
  ].join('\n'),
  go: [
    'FROM golang:1.23-alpine AS builder',
    'WORKDIR /src',
    'COPY go.mod go.sum ./',
    'RUN go mod download',
    'COPY . .',
    'RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server .',
    '',
    'FROM gcr.io/distroless/static-debian12:nonroot',
    'COPY --from=builder /out/server /server',
    'EXPOSE 8080',
    'ENTRYPOINT ["/server"]'
  ].join('\n'),
  rust: [
    'FROM rust:1.82-slim AS builder',
    'WORKDIR /src',
    'COPY Cargo.toml Cargo.lock ./',
    'COPY src ./src',
    'RUN cargo build --release',
    '',
    'FROM gcr.io/distroless/cc-debian12:nonroot',
    'COPY --from=builder /src/target/release/app /app',
    'EXPOSE 8080',
    'ENTRYPOINT ["/app"]'
  ].join('\n')
});

/**
 * Redacta cualquier token o valor sensible dentro de un fragmento de Dockerfile o capa.
 * @param {string} raw
 */
function redactSnippet(raw) {
  let out = String(raw || '').trim();
  for (const pat of TOKEN_PATTERNS) {
    out = out.replace(pat.re, '[REDACTED]');
  }
  out = out.replace(
    /(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY)\b\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s\\]+)/gi,
    '$1[REDACTED]'
  );
  out = out.replace(/(_authToken\s*=\s*)[^\s'"`]+/gi, '$1[REDACTED]');
  return out.length > 160 ? `${out.slice(0, 157)}...` : out;
}

/**
 * Parsea un Dockerfile en instrucciones lógicas (uniendo líneas continuadas con `\`).
 * @param {string} rawDockerfile
 * @returns {Array<{ line: number, op: string, args: string, raw: string }>}
 */
function parseDockerfileInstructions(rawDockerfile) {
  const lines = String(rawDockerfile || '').split(/\r?\n/);
  /** @type {Array<{ line: number, op: string, args: string, raw: string }>} */
  const out = [];
  let buf = '';
  let startLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!buf) {
      if (!trimmed || trimmed.startsWith('#')) continue;
      startLine = i + 1;
    } else if (trimmed.startsWith('#')) {
      continue;
    }

    const continues = trimmed.endsWith('\\');
    const piece = continues ? trimmed.slice(0, -1).trimEnd() : trimmed;
    buf = buf ? `${buf} ${piece}` : piece;

    if (!continues) {
      const m = buf.match(/^([A-Za-z]+)\s+([\s\S]*)$/);
      if (m) {
        out.push({
          line: startLine,
          op: m[1].toUpperCase(),
          args: m[2].trim(),
          raw: buf
        });
      }
      buf = '';
    }
  }

  if (buf) {
    const m = buf.match(/^([A-Za-z]+)\s+([\s\S]*)$/);
    if (m) {
      out.push({ line: startLine, op: m[1].toUpperCase(), args: m[2].trim(), raw: buf });
    }
  }

  return out;
}

/**
 * Extrae pares clave=valor de instrucciones `ENV` o `ARG`.
 * @param {string} op
 * @param {string} args
 * @returns {Array<{ key: string, value: string }>}
 */
function parseEnvOrArgPairs(op, args) {
  /** @type {Array<{ key: string, value: string }>} */
  const pairs = [];
  const trimmed = String(args || '').trim();
  if (!trimmed) return pairs;

  if (trimmed.includes('=')) {
    const re = /([A-Za-z_][A-Za-z0-9_]*)=("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[^\s]*)/g;
    let m;
    while ((m = re.exec(trimmed)) !== null) {
      const rawVal = m[2] || '';
      const unquoted = rawVal.replace(/^["']|["']$/g, '');
      pairs.push({ key: m[1], value: unquoted });
    }
  } else if (op === 'ENV') {
    const m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s+([\s\S]+)$/);
    if (m) pairs.push({ key: m[1], value: m[2].trim().replace(/^["']|["']$/g, '') });
  } else if (op === 'ARG') {
    const key = trimmed.split(/\s+/)[0];
    if (key) pairs.push({ key, value: '' });
  }

  return pairs;
}

/**
 * Determina si una imagen base es pesada (no slim/alpine/distroless/scratch).
 * @param {string} imageRef
 */
function isHeavyBaseImage(imageRef) {
  const ref = String(imageRef || '').trim().toLowerCase();
  if (!ref) return false;
  if (
    ref === 'scratch'
    || ref.includes('distroless')
    || ref.includes('alpine')
    || ref.includes('-slim')
    || ref.includes('chainguard')
    || ref.startsWith('cgr.dev/')
    || ref.includes('busybox')
  ) {
    return false;
  }
  return /^(?:docker\.io\/(?:library\/)?)?(?:node|python|golang|rust|ubuntu|debian|openjdk|eclipse-temurin|maven|gradle|ruby|php|dotnet|mcr\.microsoft\.com\/dotnet\/sdk)(?:[:@]|$)/i.test(ref);
}

/**
 * Determina si una imagen base ya corre como non-root por defecto.
 * @param {string} imageRef
 */
function isDefaultNonRootImage(imageRef) {
  const ref = String(imageRef || '').trim().toLowerCase();
  return ref.includes(':nonroot') || ref.includes('-nonroot') || ref.startsWith('cgr.dev/') || ref === 'scratch';
}

/**
 * Audita un Dockerfile y/o capas de `docker history` contra las 8 reglas de bloat y secretos.
 *
 * @param {{
 *   dockerfile?: string,
 *   historyLayers?: Array<{ createdBy?: string, command?: string, sizeBytes?: number, size?: number }>,
 *   stack?: string
 * } | string} [input]
 */
function auditDockerfileAndLayers(input = {}) {
  const opts = typeof input === 'string' ? { dockerfile: input } : (input || {});
  const dockerfile = typeof opts.dockerfile === 'string' ? opts.dockerfile : '';
  const historyLayers = Array.isArray(opts.historyLayers) ? opts.historyLayers : [];
  const rawStack = String(opts.stack || 'node').trim().toLowerCase();
  const stackKey = /** @type {keyof typeof MULTI_STAGE_TEMPLATES} */ (
    Object.prototype.hasOwnProperty.call(MULTI_STAGE_TEMPLATES, rawStack) ? rawStack : 'node'
  );

  const instructions = parseDockerfileInstructions(dockerfile);

  /** @type {Array<{ rule: string, line: number | null, source: 'dockerfile' | 'history', key: string, redactedSnippet: string, reason: string }>} */
  const secretLeaks = [];
  /** @type {Array<{ rule: string, severity: string, line: number | null, message: string, estimatedSavingsMb: number, fix: string }>} */
  const findings = [];
  /** @type {Set<string>} */
  const seenFindingKeys = new Set();
  /** @type {Set<string>} */
  const recommendations = new Set();

  let wastedBytes = 0;

  /**
   * @param {string} ruleId
   * @param {number | null} line
   * @param {string} [customMessage]
   * @param {number} [customSavingsMb]
   */
  const addFinding = (ruleId, line, customMessage, customSavingsMb) => {
    const rule = RULE_BY_ID[ruleId];
    if (!rule) return;
    const dedupKey = `${ruleId}:${line || 0}`;
    if (seenFindingKeys.has(dedupKey)) return;
    seenFindingKeys.add(dedupKey);
    const savingsMb = typeof customSavingsMb === 'number' ? customSavingsMb : rule.estimatedSavingsMb;
    findings.push({
      rule: rule.id,
      severity: rule.severity,
      line,
      message: customMessage || rule.title,
      estimatedSavingsMb: savingsMb,
      fix: rule.fix
    });
    recommendations.add(rule.fix);
  };

  /**
   * Escanea texto en busca de secretos embebidos y registra hallazgos redactados.
   * @param {string} text
   * @param {'dockerfile' | 'history'} source
   * @param {number | null} line
   * @param {string} [hintKey]
   */
  const scanTextForSecrets = (text, source, line, hintKey = '') => {
    const raw = String(text || '');
    if (!raw || /--mount=type=secret/i.test(raw)) return false;
    let found = false;

    for (const pat of TOKEN_PATTERNS) {
      pat.re.lastIndex = 0;
      if (pat.re.test(raw)) {
        found = true;
        secretLeaks.push({
          rule: 'SECRET_IN_ENV_OR_ARG',
          line,
          source,
          key: hintKey || pat.label,
          redactedSnippet: redactSnippet(raw),
          reason: `Matched ${pat.label} credential pattern baked into ${source} layer.`
        });
      }
    }

    if (/(?:\.npmrc|\.pypirc|\.netrc|_authToken\s*=)/i.test(raw) && !/--mount=type=secret/i.test(raw)) {
      found = true;
      secretLeaks.push({
        rule: 'SECRET_IN_ENV_OR_ARG',
        line,
        source,
        key: hintKey || '.npmrc',
        redactedSnippet: redactSnippet(raw),
        reason: 'Registry auth file (.npmrc/.pypirc/_authToken) baked into layer without BuildKit --mount=type=secret (coolify#5328).'
      });
    }

    return found;
  };

  // Agrupar instrucciones por stage (`FROM ...`)
  /** @type {Array<{ fromLine: number, baseImage: string, alias: string | null, items: typeof instructions }>} */
  const stages = [];
  for (const inst of instructions) {
    if (inst.op === 'FROM') {
      const cleanedArgs = inst.args.replace(/^--platform=\S+\s+/i, '');
      const parts = cleanedArgs.split(/\s+/);
      const baseImage = parts[0] || '';
      const asIdx = parts.findIndex((p) => p.toUpperCase() === 'AS');
      const alias = asIdx >= 0 && parts[asIdx + 1] ? parts[asIdx + 1] : null;
      stages.push({ fromLine: inst.line, baseImage, alias, items: [inst] });
    } else if (stages.length > 0) {
      stages[stages.length - 1].items.push(inst);
    } else {
      stages.push({ fromLine: 1, baseImage: '', alias: null, items: [inst] });
    }
  }

  let hasCrossLayerWaste = false;
  let hasCacheWaste = false;

  for (let sIdx = 0; sIdx < stages.length; sIdx++) {
    const stage = stages[sIdx];
    let priorFileAddingLayer = false;
    let sawLockfileCopy = false;
    let sawCopyAllBeforeInstall = false;
    let sawInstallAfterCopyAll = false;
    let copyAllLine = 0;

    for (const inst of stage.items) {
      // 1. SECRET_IN_ENV_OR_ARG
      if (inst.op === 'ENV' || inst.op === 'ARG') {
        const pairs = parseEnvOrArgPairs(inst.op, inst.args);
        for (const p of pairs) {
          const isPlaceholder = !p.value || /^\$\{?[A-Za-z0-9_.-]+\}?$/.test(p.value);
          const matchedToken = scanTextForSecrets(`${p.key}=${p.value}`, 'dockerfile', inst.line, p.key);
          if (!matchedToken && SENSITIVE_KEY_RE.test(p.key)) {
            if (inst.op === 'ENV' && !isPlaceholder) {
              secretLeaks.push({
                rule: 'SECRET_IN_ENV_OR_ARG',
                line: inst.line,
                source: 'dockerfile',
                key: p.key,
                redactedSnippet: redactSnippet(inst.raw),
                reason: `Sensitive ENV variable "${p.key}" has a literal value baked into image metadata.`
              });
            } else if (inst.op === 'ARG' && (!isPlaceholder || /(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY)/i.test(p.key))) {
              secretLeaks.push({
                rule: 'SECRET_IN_ENV_OR_ARG',
                line: inst.line,
                source: 'dockerfile',
                key: p.key,
                redactedSnippet: redactSnippet(inst.raw),
                reason: `Sensitive build ARG "${p.key}" leaks into OCI build history; use RUN --mount=type=secret instead.`
              });
            }
          }
        }
      } else if (inst.op === 'RUN' || inst.op === 'COPY' || inst.op === 'ADD') {
        scanTextForSecrets(inst.raw, 'dockerfile', inst.line);
      }

      // 2. ADD_INSTEAD_OF_COPY
      if (inst.op === 'ADD') {
        const srcTokens = inst.args.split(/\s+/).filter((t) => !t.startsWith('--'));
        const sources = srcTokens.slice(0, Math.max(1, srcTokens.length - 1));
        const isTarExtraction = sources.some((s) => /\.(?:tar|tgz|tar\.gz|tar\.bz2|tar\.xz|txz)$/i.test(s));
        if (!isTarExtraction) {
          addFinding('ADD_INSTEAD_OF_COPY', inst.line);
        }
      }

      // 3. COPY_ALL_BEFORE_LOCKFILE tracking
      if (inst.op === 'COPY' || inst.op === 'ADD') {
        priorFileAddingLayer = true;
        const cleanArgs = inst.args.replace(/--[a-z-]+=\S+\s*/gi, '').trim();
        if (/(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|pyproject\.toml|poetry\.lock|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock)/i.test(cleanArgs)) {
          sawLockfileCopy = true;
        }
        if (/^(?:\.|\.\/)\s+(?:\.|\.\/|\/app\/?|\/src\/?)/i.test(cleanArgs) && !sawLockfileCopy) {
          sawCopyAllBeforeInstall = true;
          copyAllLine = inst.line;
        }
      }

      if (inst.op === 'RUN') {
        const cmd = inst.args;

        if (sawCopyAllBeforeInstall && !sawInstallAfterCopyAll && /\b(?:npm\s+(?:ci|install)|yarn\s+install|pnpm\s+install|pip3?\s+install|poetry\s+install|go\s+mod\s+download|cargo\s+build)\b/i.test(cmd)) {
          sawInstallAfterCopyAll = true;
          addFinding('COPY_ALL_BEFORE_LOCKFILE', copyAllLine || inst.line);
          wastedBytes += 50 * 1024 * 1024;
        }

        // 4. CROSS_LAYER_DELETE_WASTE: separate RUN invoking rm after earlier file-adding layer
        const startsWithRm = /^(?:--mount=\S+\s+)*(?:rm\s+|find\s+\S+.*-delete\b|unlink\s+)/i.test(cmd);
        const isStandaloneCleanup = startsWithRm && !/(?:apt-get\s+install|apk\s+add|pip3?\s+install|curl|wget|tar|unzip|npm\s+|yarn\s+|make|gcc|go\s+build|cargo\s+build)/i.test(cmd);
        if (priorFileAddingLayer && isStandaloneCleanup) {
          hasCrossLayerWaste = true;
          addFinding(
            'CROSS_LAYER_DELETE_WASTE',
            inst.line,
            `Separate RUN cleanup at line ${inst.line} deletes files added in an earlier layer without shrinking the OCI image.`
          );
          wastedBytes += 45 * 1024 * 1024;
        }

        // 5. UNDELETED_PACKAGE_CACHE
        if (/\bapt(?:-get)?\s+install\b/i.test(cmd) && !/\/var\/lib\/apt\/lists/i.test(cmd) && !/--mount=type=cache/i.test(cmd)) {
          hasCacheWaste = true;
          addFinding('UNDELETED_PACKAGE_CACHE', inst.line, 'apt-get install without `rm -rf /var/lib/apt/lists/*` in the same RUN layer.');
          wastedBytes += 65 * 1024 * 1024;
        }
        if (/\bapk\s+add\b/i.test(cmd) && !/--no-cache\b/i.test(cmd) && !/\/var\/cache\/apk/i.test(cmd)) {
          hasCacheWaste = true;
          addFinding('UNDELETED_PACKAGE_CACHE', inst.line, 'apk add without `--no-cache` retains Alpine package index cache.');
          wastedBytes += 20 * 1024 * 1024;
        }
        if (/\bpip3?\s+install\b/i.test(cmd) && !/--no-cache-dir\b/i.test(cmd) && !/\.cache\/pip/i.test(cmd) && !/--mount=type=cache/i.test(cmd)) {
          hasCacheWaste = true;
          addFinding('UNDELETED_PACKAGE_CACHE', inst.line, 'pip install without `--no-cache-dir` retains wheel/download cache.');
          wastedBytes += 45 * 1024 * 1024;
        }

        priorFileAddingLayer = true;
      }
    }
  }

  // Evaluate stage-level & final-stage rules when Dockerfile was provided
  if (stages.length > 0 && instructions.length > 0) {
    const finalStage = stages[stages.length - 1];

    // 6. HEAVY_BASE_IMAGE (evaluated on final runtime stage)
    if (isHeavyBaseImage(finalStage.baseImage)) {
      addFinding(
        'HEAVY_BASE_IMAGE',
        finalStage.fromLine,
        `Final stage uses heavy base image "${finalStage.baseImage}" instead of slim, alpine, or distroless.`
      );
      wastedBytes += 220 * 1024 * 1024;
    }

    // 7. MISSING_MULTI_STAGE
    if (stages.length === 1) {
      const hasBuildWork = finalStage.items.some((inst) => (
        inst.op === 'RUN' && /\b(?:npm|yarn|pnpm|pip3?|go\s+build|cargo|mvn|gradle|make|gcc|g\+\+|tsc|vite|webpack|next\s+build)\b/i.test(inst.args)
      ));
      if (isHeavyBaseImage(finalStage.baseImage) || hasBuildWork) {
        addFinding(
          'MISSING_MULTI_STAGE',
          finalStage.fromLine,
          `Single-stage Dockerfile (${finalStage.baseImage || 'unknown'}) ships build tools into the runtime image.`
        );
        wastedBytes += 280 * 1024 * 1024;
      }
    }

    // 8. MISSING_NON_ROOT_USER (evaluated on final runtime stage)
    let finalUser = '';
    for (const inst of finalStage.items) {
      if (inst.op === 'USER') {
        finalUser = inst.args.split(/\s+/)[0] || '';
      }
    }
    const isRootUser = !finalUser || /^(?:root|0)(?::(?:root|0))?$/i.test(finalUser);
    if (isRootUser && !isDefaultNonRootImage(finalStage.baseImage)) {
      addFinding('MISSING_NON_ROOT_USER', finalStage.fromLine);
    }
  }

  // Analyze docker historyLayers JSON (Dive-style layer waste & secret detection)
  let sawHistoryAdd = false;
  let lastAddedLayerBytes = 0;
  for (let i = 0; i < historyLayers.length; i++) {
    const layer = historyLayers[i] || {};
    const cmd = String(layer.createdBy || layer.command || '');
    const size = Math.max(0, Number(layer.sizeBytes ?? layer.size ?? 0) || 0);

    scanTextForSecrets(cmd, 'history', null);

    if (/\b(?:COPY|ADD|apt-get\s+install|npm\s+install|pip3?\s+install|curl|wget)\b/i.test(cmd)) {
      sawHistoryAdd = true;
      lastAddedLayerBytes = Math.max(lastAddedLayerBytes, size);
    }
    if (sawHistoryAdd && /\brm\s+-[a-z]*f|\brm\s+-r/i.test(cmd) && !/\b(?:apt-get\s+install|apk\s+add|pip3?\s+install)\b/i.test(cmd)) {
      if (!hasCrossLayerWaste) {
        hasCrossLayerWaste = true;
        addFinding(
          'CROSS_LAYER_DELETE_WASTE',
          null,
          `Image history layer #${i + 1} runs \`rm\` after earlier layers already persisted files.`
        );
      }
      wastedBytes += Math.max(size, Math.round(lastAddedLayerBytes * 0.5), 10 * 1024 * 1024);
    }
    if (!hasCacheWaste && /\bapt(?:-get)?\s+install\b/i.test(cmd) && !/\/var\/lib\/apt\/lists/i.test(cmd)) {
      hasCacheWaste = true;
      addFinding('UNDELETED_PACKAGE_CACHE', null, `Image history layer #${i + 1} retains apt lists cache.`);
      wastedBytes += Math.max(Math.round(size * 0.25), 40 * 1024 * 1024);
    }
  }

  // Ensure SECRET_IN_ENV_OR_ARG appears in findings whenever secretLeaks is non-empty
  if (secretLeaks.length > 0) {
    addFinding(
      'SECRET_IN_ENV_OR_ARG',
      secretLeaks[0].line,
      `Detected ${secretLeaks.length} secret/credential leak(s) baked into image layers (all values redacted).`,
      0
    );
  }

  // Deterministic efficiency score (0..100): clean multi-stage non-root scores 100 (>= 90)
  /** @type {Record<string, number>} */
  const severityPenalty = { critical: 35, high: 18, medium: 12, low: 6 };
  /** @type {Set<string>} */
  const penalizedRules = new Set();
  let totalPenalty = 0;
  for (const f of findings) {
    if (!penalizedRules.has(f.rule)) {
      penalizedRules.add(f.rule);
      totalPenalty += severityPenalty[f.severity] || 10;
    } else {
      totalPenalty += 3;
    }
  }
  if (secretLeaks.length > 1) {
    totalPenalty += Math.min(20, (secretLeaks.length - 1) * 5);
  }
  const efficiencyScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  const estimatedSavingsMb = Math.round(wastedBytes / (1024 * 1024));

  return {
    ok: true,
    efficiencyScore,
    estimatedSavingsMb,
    wastedBytes,
    secretLeaks,
    findings,
    slimmingRecommendations: Array.from(recommendations),
    multiStageTemplate: MULTI_STAGE_TEMPLATES[stackKey]
  };
}

module.exports = {
  RULES,
  auditDockerfileAndLayers
};
