/**
 * Self-Hosted AI / GPU & Local LLM Workload Orchestrator (Ollama / vLLM / llama.cpp).
 *
 * Cures:
 *  - `dokploy#1621`: Supports both modern NVIDIA CDI (`--device nvidia.com/gpu=all`) and legacy `--gpus all` + CPU fallback.
 *  - `CVE-2025-63389`: Blocks unauthenticated public `0.0.0.0` AI endpoint exposure (defaults strictly to `127.0.0.1` + Bearer proxy).
 *  - `Ollama CVE-2026-7482` (`< 0.17.1`) and `vLLM CVE-2026-22778` (CVSS 9.8 RCE) / `CVE-2026-137477` (KV-cache leak, `< 0.21.1`).
 *
 * 0 dependencias npm externas, 0 invocaciones de shell, 0 mutaciones en disco.
 */

const SAFE_MODEL_RE = /^[a-zA-Z0-9._:/@-]{1,128}$/;
const SAFE_IMAGE_RE = /^[a-zA-Z0-9._:/@-]{1,180}$/;

const QUANTIZATION_BYTES_PER_PARAM = Object.freeze({
  Q4_0: 0.56,
  Q4_K_M: 0.58,
  Q5_K_M: 0.72,
  Q6_K: 0.82,
  Q8_0: 1.06,
  FP8: 1.05,
  BF16: 2.0,
  FP16: 2.0,
  FP32: 4.0
});

const AI_RUNTIME_PRESETS = Object.freeze({
  ollama: Object.freeze({
    id: 'ollama',
    name: 'Ollama',
    image: 'ollama/ollama:0.17.4',
    minSafeVersion: '0.17.1',
    apiPort: 11434,
    bindAddress: '127.0.0.1',
    cacheMount: '/root/.ollama',
    openAiCompatiblePath: '/v1/chat/completions',
    healthPath: '/api/tags',
    defaultModel: 'llama3.2:8b'
  }),
  vllm: Object.freeze({
    id: 'vllm',
    name: 'vLLM OpenAI Server',
    image: 'vllm/vllm-openai:v0.21.2',
    minSafeVersion: '0.21.1',
    apiPort: 8000,
    bindAddress: '127.0.0.1',
    cacheMount: '/root/.cache/huggingface',
    openAiCompatiblePath: '/v1/chat/completions',
    healthPath: '/health',
    defaultModel: 'meta-llama/Llama-3.1-8B-Instruct'
  }),
  llamacpp: Object.freeze({
    id: 'llamacpp',
    name: 'llama.cpp Server',
    image: 'ghcr.io/ggml-org/llama.cpp:server-cuda-b5120',
    minSafeVersion: null,
    apiPort: 8080,
    bindAddress: '127.0.0.1',
    cacheMount: '/models',
    openAiCompatiblePath: '/v1/chat/completions',
    healthPath: '/health',
    defaultModel: 'llama-3.2-8b-instruct-q4_k_m.gguf'
  })
});

/** @param {number} n */
function round2(n) {
  return Math.round(Math.max(0, Number(n) || 0) * 100) / 100;
}

/**
 * Compara dos versiones semver `major.minor.patch`.
 * Devuelve `< 0` si `a < b`, `0` si iguales, `> 0` si `a > b`.
 * @param {string} a
 * @param {string} b
 */
function compareSemver(a, b) {
  const pa = String(a).replace(/^v/i, '').split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b).replace(/^v/i, '').split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Estima la VRAM requerida (pesos + KV-cache + overhead CUDA/runtime) antes de desplegar un LLM.
 *
 * @param {{
 *   paramsB?: number,
 *   quantization?: string,
 *   contextLen?: number,
 *   batchSize?: number,
 *   availableVramGb?: number | null
 * }} [opts]
 */
function estimateVram(opts = {}) {
  const paramsB = Math.max(0.5, Math.min(1000, Number(opts.paramsB ?? 7) || 7));
  const rawQuant = String(opts.quantization || 'Q4_K_M').trim().toUpperCase();
  const quantKey = Object.prototype.hasOwnProperty.call(QUANTIZATION_BYTES_PER_PARAM, rawQuant)
    ? /** @type {keyof typeof QUANTIZATION_BYTES_PER_PARAM} */ (rawQuant)
    : 'Q4_K_M';
  const bytesPerParam = QUANTIZATION_BYTES_PER_PARAM[quantKey];
  const contextLen = Math.max(512, Math.min(262144, Math.round(Number(opts.contextLen ?? 8192) || 8192)));
  const batchSize = Math.max(1, Math.min(128, Math.round(Number(opts.batchSize ?? 1) || 1)));

  const weightsGb = round2(paramsB * bytesPerParam);
  const kvCacheGb = round2((contextLen / 4096) * batchSize * (0.25 + paramsB * 0.045));
  const overheadGb = round2(Math.max(0.8, weightsGb * 0.12));
  const totalRequiredGb = round2(weightsGb + kvCacheGb + overheadGb);

  const hasAvail = opts.availableVramGb !== null && opts.availableVramGb !== undefined && Number.isFinite(Number(opts.availableVramGb));
  const availableVramGb = hasAvail ? Math.max(0, Number(opts.availableVramGb)) : null;
  const fits = availableVramGb !== null ? totalRequiredGb <= availableVramGb : null;
  const headroomGb = availableVramGb !== null ? round2(availableVramGb - totalRequiredGb) : null;

  return {
    ok: true,
    paramsB,
    quantization: quantKey,
    contextLen,
    batchSize,
    availableVramGb,
    weightsGb,
    kvCacheGb,
    overheadGb,
    totalRequiredGb,
    fits,
    headroomGb
  };
}

/**
 * Audita la imagen y el enlace de red de un runtime AI/LLM contra CVEs 2025–2026
 * (`CVE-2025-63389`, `Ollama CVE-2026-7482`, `vLLM CVE-2026-22778` & `CVE-2026-137477`).
 *
 * @param {{
 *   runtime?: string,
 *   imageTag?: string,
 *   bindAddress?: string,
 *   authProxyEnabled?: boolean
 * }} [opts]
 */
function auditAiImageSecurity(opts = {}) {
  const runtime = String(opts.runtime || 'ollama').trim().toLowerCase();
  const preset = AI_RUNTIME_PRESETS[/** @type {keyof typeof AI_RUNTIME_PRESETS} */ (runtime)] || AI_RUNTIME_PRESETS.ollama;
  const imageTag = String(opts.imageTag || preset.image).trim();
  const bindAddress = String(opts.bindAddress || '127.0.0.1').trim();
  const authProxyEnabled = opts.authProxyEnabled !== undefined ? Boolean(opts.authProxyEnabled) : true;

  /** @type {string[]} */
  const blockers = [];
  /** @type {string[]} */
  const warnings = [];
  /** @type {Array<{ id: string, severity: string, summary: string }>} */
  const cves = [];

  const isPublicBind = bindAddress === '0.0.0.0' || bindAddress === '::' || bindAddress === '*';
  if (isPublicBind && !authProxyEnabled) {
    blockers.push(
      `PUBLIC_AI_ENDPOINT_BLOCKED: Binding ${runtime} on ${bindAddress}:${preset.apiPort} without Bearer auth proxy exposes unauthenticated LLM inference/model pull (CVE-2025-63389). Bind to 127.0.0.1 or enable Caddy Bearer auth.`
    );
    cves.push({
      id: 'CVE-2025-63389',
      severity: 'critical',
      summary: 'Unauthenticated public exposure of local LLM runtime API (0.0.0.0:11434/8000).'
    });
  } else if (isPublicBind && authProxyEnabled) {
    warnings.push(`Runtime bound to ${bindAddress}; verify Caddy Bearer auth + IP allowlist protect port ${preset.apiPort}.`);
  }

  // Extraer semver de la etiqueta de imagen (p. ej. ollama/ollama:0.16.0 o vllm/vllm-openai:v0.19.0)
  const tagPart = imageTag.includes(':') ? imageTag.slice(imageTag.lastIndexOf(':') + 1) : '';
  const semverMatch = tagPart.match(/v?(\d+\.\d+\.\d+)/i);
  const parsedVersion = semverMatch ? semverMatch[1] : null;

  if (!tagPart || tagPart.toLowerCase() === 'latest') {
    warnings.push(`UNPINNED_AI_IMAGE_TAG: Image "${imageTag}" uses an unpinned tag; pin to "${preset.image}".`);
  }

  if (runtime === 'ollama' && parsedVersion && compareSemver(parsedVersion, '0.17.1') < 0) {
    blockers.push(`VULNERABLE_OLLAMA_IMAGE: ollama ${parsedVersion} < 0.17.1 is affected by CVE-2026-7482. Pin to ${AI_RUNTIME_PRESETS.ollama.image}.`);
    cves.push({
      id: 'CVE-2026-7482',
      severity: 'high',
      summary: 'Ollama < 0.17.1 remote crash / model-handler vulnerability.'
    });
  }

  if (runtime === 'vllm' && parsedVersion && compareSemver(parsedVersion, '0.21.1') < 0) {
    blockers.push(`VULNERABLE_VLLM_IMAGE: vLLM ${parsedVersion} < 0.21.1 is affected by CVE-2026-22778 (CVSS 9.8 RCE) & CVE-2026-137477 (KV-cache leak). Pin to ${AI_RUNTIME_PRESETS.vllm.image}.`);
    cves.push(
      {
        id: 'CVE-2026-22778',
        severity: 'critical',
        summary: 'vLLM < 0.21.1 critical CVSS 9.8 RCE vulnerability.'
      },
      {
        id: 'CVE-2026-137477',
        severity: 'high',
        summary: 'vLLM < 0.21.1 cross-request KV-cache information leak.'
      }
    );
  }

  return {
    safe: blockers.length === 0,
    runtime,
    imageTag,
    parsedVersion,
    bindAddress,
    authProxyEnabled,
    blockers,
    warnings,
    cves
  };
}

/**
 * Construye una especificación Docker segura (cero shell) para Ollama / vLLM / llama.cpp
 * con soporte NVIDIA CDI (`--device nvidia.com/gpu=all`), legacy `--gpus all` (`dokploy#1621`),
 * y CPU; falla en cerrado ante VRAM insuficiente o exposición pública sin autenticación.
 *
 * @param {{
 *   runtime?: 'ollama' | 'vllm' | 'llamacpp' | string,
 *   model?: string,
 *   paramsB?: number,
 *   quantization?: string,
 *   contextLen?: number,
 *   batchSize?: number,
 *   availableVramGb?: number | null,
 *   gpuMode?: 'cdi' | 'legacy' | 'cpu',
 *   bindAddress?: string,
 *   authProxyEnabled?: boolean,
 *   imageTag?: string,
 *   allowVulnerableImage?: boolean
 * }} [opts]
 */
function buildAiWorkloadSpec(opts = {}) {
  const runtimeKey = String(opts.runtime || 'ollama').trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(AI_RUNTIME_PRESETS, runtimeKey)) {
    const err = new Error(`AI runtime no soportado: "${runtimeKey}" (usa ollama, vllm o llamacpp)`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  const preset = AI_RUNTIME_PRESETS[/** @type {keyof typeof AI_RUNTIME_PRESETS} */ (runtimeKey)];

  const model = String(opts.model || preset.defaultModel).trim();
  if (!SAFE_MODEL_RE.test(model) || model.includes('..')) {
    const err = new Error(`Identificador de modelo AI inválido: "${model.slice(0, 80)}"`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }

  const imageTag = String(opts.imageTag || preset.image).trim();
  if (!SAFE_IMAGE_RE.test(imageTag) || imageTag.includes('..')) {
    const err = new Error(`Imagen Docker AI inválida: "${imageTag.slice(0, 80)}"`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }

  const rawGpuMode = String(opts.gpuMode || 'cdi').trim().toLowerCase();
  if (!['cdi', 'legacy', 'cpu'].includes(rawGpuMode)) {
    const err = new Error(`gpuMode inválido: "${rawGpuMode}" (usa cdi, legacy o cpu)`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  const gpuMode = /** @type {'cdi' | 'legacy' | 'cpu'} */ (rawGpuMode);
  const bindAddress = String(opts.bindAddress || preset.bindAddress).trim();
  if (!/^(?:127\.0\.0\.1|0\.0\.0\.0|::1|::|10\.88\.0\.\d{1,3})$/.test(bindAddress)) {
    const err = new Error(`bindAddress inválido para workload AI: "${bindAddress.slice(0, 60)}"`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  const authProxyEnabled = opts.authProxyEnabled !== undefined ? Boolean(opts.authProxyEnabled) : true;

  const vram = estimateVram({
    paramsB: opts.paramsB ?? 8,
    quantization: opts.quantization || 'Q4_K_M',
    contextLen: opts.contextLen ?? 8192,
    batchSize: opts.batchSize ?? 1,
    availableVramGb: opts.availableVramGb !== undefined ? opts.availableVramGb : 16
  });

  const security = auditAiImageSecurity({
    runtime: runtimeKey,
    imageTag,
    bindAddress,
    authProxyEnabled
  });

  // Fail-closed: rechazar exposición pública sin autenticación (CVE-2025-63389)
  if (security.blockers.some((b) => b.startsWith('PUBLIC_AI_ENDPOINT_BLOCKED'))) {
    const err = new Error(security.blockers.find((b) => b.startsWith('PUBLIC_AI_ENDPOINT_BLOCKED')));
    /** @type {any} */ (err).status = 400;
    /** @type {any} */ (err).code = 'PUBLIC_AI_ENDPOINT_BLOCKED';
    /** @type {any} */ (err).security = security;
    throw err;
  }

  // Fail-closed: rechazar desbordamiento de VRAM en modo GPU
  if (gpuMode !== 'cpu' && vram.fits === false) {
    const err = new Error(
      `VRAM_INSUFFICIENT: Model "${model}" (${vram.paramsB}B ${vram.quantization}, ctx=${vram.contextLen}) requires ${vram.totalRequiredGb} GB VRAM > ${vram.availableVramGb} GB available.`
    );
    /** @type {any} */ (err).status = 400;
    /** @type {any} */ (err).code = 'VRAM_INSUFFICIENT';
    /** @type {any} */ (err).vram = vram;
    throw err;
  }

  // Fail-closed: bloquear imágenes vulnerables conocidas salvo override explícito
  if (!security.safe && !opts.allowVulnerableImage) {
    const err = new Error(security.blockers[0] || 'AI image failed CVE security audit');
    /** @type {any} */ (err).status = 400;
    /** @type {any} */ (err).code = 'VULNERABLE_AI_IMAGE';
    /** @type {any} */ (err).security = security;
    throw err;
  }

  const volumeName = `culkibo_ai_${runtimeKey}_cache`;
  const containerName = `culkibo_ai_${runtimeKey}`;

  /** @type {string[]} */
  const gpuFlags = gpuMode === 'cdi'
    ? ['--device', 'nvidia.com/gpu=all']
    : (gpuMode === 'legacy' ? ['--gpus', 'all'] : []);

  /** @type {string[]} */
  const dockerArgs = [
    'run', '-d',
    '--name', containerName,
    '--restart', 'unless-stopped',
    '--stop-timeout', '30',
    '--log-driver', 'json-file',
    '--log-opt', 'max-size=10m',
    '--log-opt', 'max-file=3',
    ...gpuFlags,
    '-p', `${bindAddress}:${preset.apiPort}:${preset.apiPort}`,
    '-v', `${volumeName}:${preset.cacheMount}`
  ];

  if (runtimeKey === 'ollama') {
    dockerArgs.push('-e', `OLLAMA_HOST=0.0.0.0:${preset.apiPort}`, imageTag);
  } else if (runtimeKey === 'vllm') {
    dockerArgs.push(imageTag, '--model', model, '--max-model-len', String(vram.contextLen), '--port', String(preset.apiPort));
  } else {
    dockerArgs.push(imageTag, '--model', `/models/${model}`, '--ctx-size', String(vram.contextLen), '--port', String(preset.apiPort), '--host', '0.0.0.0');
  }

  return {
    ok: true,
    runtime: runtimeKey,
    model,
    imageTag,
    gpuMode,
    bindAddress,
    apiPort: preset.apiPort,
    openAiCompatiblePath: preset.openAiCompatiblePath,
    vram,
    security,
    zeroShell: true,
    dockerArgs,
    volumeMount: {
      volumeName,
      containerPath: preset.cacheMount
    },
    caddyProxyGuard: {
      enabled: authProxyEnabled,
      upstream: `${bindAddress === '0.0.0.0' ? '127.0.0.1' : bindAddress}:${preset.apiPort}`,
      requireBearerToken: true,
      rateLimitPerMinute: 60
    }
  };
}

class AiWorkloadService {
  getPresets() {
    return {
      ok: true,
      presets: Object.values(AI_RUNTIME_PRESETS),
      quantizations: Object.keys(QUANTIZATION_BYTES_PER_PARAM)
    };
  }

  /** @param {any} opts */
  estimateVram(opts) {
    return estimateVram(opts);
  }

  /** @param {any} opts */
  auditAiImageSecurity(opts) {
    return auditAiImageSecurity(opts);
  }

  /** @param {any} opts */
  buildAiWorkloadSpec(opts) {
    return buildAiWorkloadSpec(opts);
  }
}

const instance = /** @type {any} */ (new AiWorkloadService());
instance.AiWorkloadService = AiWorkloadService;
instance.AI_RUNTIME_PRESETS = AI_RUNTIME_PRESETS;
instance.QUANTIZATION_BYTES_PER_PARAM = QUANTIZATION_BYTES_PER_PARAM;
instance.estimateVram = estimateVram;
instance.auditAiImageSecurity = auditAiImageSecurity;
instance.buildAiWorkloadSpec = buildAiWorkloadSpec;
module.exports = instance;
