/**
 * Multi-Arch (`amd64` / `arm64`) OCI Manifest & Build Matrix Planner (100% Zero-Dep).
 *
 * Previene crashes `exec format error` al desplegar imágenes Apple Silicon (`arm64`) en
 * VPS `x86_64` (o viceversa), advierte sobre políticas de registros OCI estrictos ante
 * manifiestos de atestación BuildKit, y enruta compilaciones a builders nativos de la flota
 * antes de recurrir a emulación QEMU (devolviendo arreglos `argv` 100% `shell: false`).
 */

const SUPPORTED_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64']);

/**
 * Normaliza aliases de arquitectura CPU (`x86_64`/`x64` → `amd64`, `aarch64`/`arm64/v8` → `arm64`).
 * @param {string | null | undefined} rawArch
 * @returns {string}
 */
function normalizeArch(rawArch) {
  const s = String(rawArch || '').trim().toLowerCase();
  if (!s) return '';
  const stripped = s.includes('/') ? s.split('/').slice(1).join('/') : s;
  if (stripped === 'x86_64' || stripped === 'x64' || stripped === 'amd64' || stripped === 'x86-64') {
    return 'amd64';
  }
  if (stripped === 'aarch64' || stripped === 'arm64' || stripped === 'arm64/v8' || stripped === 'arm64v8') {
    return 'arm64';
  }
  if (stripped === 'arm/v7' || stripped === 'armv7l' || stripped === 'arm') {
    return 'arm/v7';
  }
  return stripped;
}

/**
 * Normaliza una plataforma OCI completa (`linux/x86_64` → `linux/amd64`, `aarch64` → `linux/arm64`).
 * @param {string | null | undefined} rawPlatform
 * @param {string} [defaultOs]
 * @returns {string}
 */
function normalizePlatform(rawPlatform, defaultOs = 'linux') {
  const s = String(rawPlatform || '').trim().toLowerCase();
  if (!s) return '';
  if (s.includes('/')) {
    const [osPart, ...rest] = s.split('/');
    const arch = normalizeArch(rest.join('/'));
    return arch ? `${osPart || defaultOs}/${arch}` : '';
  }
  const arch = normalizeArch(s);
  return arch ? `${defaultOs}/${arch}` : '';
}

/**
 * Verifica compatibilidad de arquitectura entre una imagen/manifiesto OCI y el host destino,
 * detectando `EXEC_FORMAT_MISMATCH` antes del despliegue.
 *
 * @param {{
 *   imageArch?: string,
 *   imageOs?: string,
 *   manifestPlatforms?: string[],
 *   hostArch?: string,
 *   strictOciRegistry?: boolean,
 *   includeAttestations?: boolean
 * }} [input]
 */
function verifyManifestCompatibility(input = {}) {
  const opts = input || {};
  const imageOs = String(opts.imageOs || 'linux').trim().toLowerCase() || 'linux';
  const rawHost = opts.hostArch || process.arch || 'amd64';
  const hostArch = normalizeArch(rawHost) || 'amd64';
  const hostPlatform = `linux/${hostArch}`;

  /** @type {Set<string>} */
  const availableSet = new Set();
  if (Array.isArray(opts.manifestPlatforms)) {
    for (const p of opts.manifestPlatforms) {
      const norm = normalizePlatform(p, imageOs);
      if (norm) availableSet.add(norm);
    }
  }
  if (opts.imageArch) {
    const normSingle = normalizePlatform(opts.imageArch, imageOs);
    if (normSingle) availableSet.add(normSingle);
  }

  const availablePlatforms = Array.from(availableSet);
  const targetPlatform = `${imageOs}/${hostArch}`;
  const compatible = availablePlatforms.includes(targetPlatform) || availablePlatforms.includes(hostPlatform);

  /** @type {string[]} */
  const warnings = [];
  if (opts.strictOciRegistry && opts.includeAttestations !== false) {
    warnings.push(
      'Strict OCI registry mode with BuildKit attestations enabled can fail with `blob unknown` on `unknown/unknown` attestation manifests; pass `--provenance=false --sbom=false` or enable OCI v1.1 referrers.'
    );
  }
  if (availablePlatforms.length === 1) {
    warnings.push(
      `Single-architecture image (${availablePlatforms[0]}) is not portable across mixed amd64/arm64 VPS fleets; consider publishing a multi-arch OCI manifest index.`
    );
  }

  const code = compatible ? 'COMPATIBLE' : 'EXEC_FORMAT_MISMATCH';
  const remediation = compatible
    ? 'Image manifest satisfies target host architecture; safe to pull and start.'
    : `Host requires ${targetPlatform}, but manifest only provides [${availablePlatforms.join(', ') || 'none'}]. Rebuild with \`docker buildx build --platform linux/amd64,linux/arm64 --push\` to eliminate exec format error.`;

  return {
    ok: true,
    compatible,
    code,
    hostPlatform: targetPlatform,
    availablePlatforms,
    warnings,
    remediation
  };
}

/**
 * Planifica una matriz de compilación multi-arch enrutando cada plataforma a builders
 * nativos de la flota antes de caer en QEMU, emitiendo comandos `argv` sin shell.
 *
 * @param {{
 *   targetPlatforms?: string[],
 *   builders?: Array<{ name?: string, id?: string, arch?: string, platforms?: string[], online?: boolean, endpoint?: string }>,
 *   preferNativeOverQemu?: boolean,
 *   imageTag?: string
 * }} [input]
 */
function planBuildMatrix(input = {}) {
  const opts = input || {};
  const rawTargets = Array.isArray(opts.targetPlatforms) && opts.targetPlatforms.length > 0
    ? opts.targetPlatforms
    : [...SUPPORTED_PLATFORMS];

  const normalizedTargets = Array.from(
    new Set(rawTargets.map((p) => normalizePlatform(p, 'linux')).filter(Boolean))
  );
  const preferNativeOverQemu = opts.preferNativeOverQemu !== undefined
    ? Boolean(opts.preferNativeOverQemu)
    : true;
  const imageTag = String(opts.imageTag || 'app:latest').trim() || 'app:latest';

  const onlineBuilders = (Array.isArray(opts.builders) ? opts.builders : [])
    .filter((b) => b && typeof b === 'object' && b.online !== false)
    .map((b, idx) => {
      /** @type {Set<string>} */
      const archSet = new Set();
      if (b.arch) {
        const a = normalizeArch(b.arch);
        if (a) archSet.add(a);
      }
      if (Array.isArray(b.platforms)) {
        for (const p of b.platforms) {
          const a = normalizeArch(p);
          if (a) archSet.add(a);
        }
      }
      return {
        name: String(b.name || b.id || `builder-${idx + 1}`),
        arches: archSet,
        endpoint: b.endpoint ? String(b.endpoint) : null
      };
    });

  /** @type {Array<{ platform: string, arch: string, strategy: 'native' | 'qemu', builder: string, endpoint: string | null, usesQemu: boolean }>} */
  const assignments = [];
  /** @type {string[]} */
  const qemuPlatforms = [];

  for (const platform of normalizedTargets) {
    const arch = normalizeArch(platform);
    const nativeMatch = preferNativeOverQemu
      ? onlineBuilders.find((b) => b.arches.has(arch))
      : null;

    if (nativeMatch) {
      assignments.push({
        platform,
        arch,
        strategy: 'native',
        builder: nativeMatch.name,
        endpoint: nativeMatch.endpoint,
        usesQemu: false
      });
    } else {
      const fallback = onlineBuilders[0] || null;
      qemuPlatforms.push(platform);
      assignments.push({
        platform,
        arch,
        strategy: 'qemu',
        builder: fallback ? fallback.name : 'local-buildx-qemu',
        endpoint: fallback ? fallback.endpoint : null,
        usesQemu: true
      });
    }
  }

  const usesQemu = qemuPlatforms.length > 0;
  const qemuWarning = usesQemu
    ? `Platform(s) [${qemuPlatforms.join(', ')}] have no matching native fleet builder and will fall back to slower QEMU user-mode emulation.`
    : null;

  const buildxArgv = [
    'docker', 'buildx', 'build',
    '--platform', normalizedTargets.join(','),
    '-t', imageTag,
    '--push',
    '.'
  ];

  const manifestCreateArgv = [
    'docker', 'manifest', 'create',
    imageTag,
    ...normalizedTargets.map((p) => `${imageTag}-${normalizeArch(p)}`)
  ];

  return {
    ok: true,
    imageTag,
    targetPlatforms: normalizedTargets,
    assignments,
    usesQemu,
    qemuWarning,
    buildxArgv,
    manifestCreateArgv
  };
}

module.exports = {
  SUPPORTED_PLATFORMS,
  normalizeArch,
  normalizePlatform,
  verifyManifestCompatibility,
  planBuildMatrix
};
