'use strict';

/**
 * Culkibo Zero-Dep Declarative Policy-as-Code Deployment Admission Engine (Kyverno / OPA-Lite).
 *
 * Evaluates 10 CIS / Pod Security Standards (PSS) rules BEFORE container creation:
 *  1. `no_privileged`              — Blocks `privileged: true`
 *  2. `no_docker_sock_mount`       — Blocks mounting `docker.sock` / `containerd.sock`
 *  3. `no_host_root_mount`         — Blocks mounting `/`, `/etc`, `/proc`, `/sys`, `/root`, `/boot`, `/dev`, `/var/run` (cures Coolify `<=beta.420.6` `- /:/host:rw`)
 *  4. `no_dangerous_caps`          — Blocks `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `SYS_MODULE`, `DAC_OVERRIDE`, `ALL` (`coolify#8847`)
 *  5. `no_latest_tag`              — Blocks `:latest` or untagged/undigested images
 *  6. `require_non_root_uid`       — Blocks UID `0` / `root` / omitted user
 *  7. `require_resource_limits`    — Requires positive `memoryLimitMb` & `cpuLimit`
 *  8. `require_healthcheck`        — Requires `healthcheck` or `healthcheckPath`
 *  9. `require_signed_attestation` — Requires verified SLSA v1.1 Ed25519 attestation
 * 10. `no_public_db_or_panel_bind` — Blocks `0.0.0.0` / `::` exposure on sensitive ports (`3000`, `5432`, `3306`, `6379`, `27017`, `11434` — cures `dokploy#2661`)
 *
 * Persists active policy atomically (`0o600`) in isolated `CULKIBO_DATA_DIR/data/admission-policies.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SENSITIVE_PUBLIC_PORTS = Object.freeze([3000, 5432, 3306, 6379, 27017, 11434]);
const DANGEROUS_CAPABILITIES = Object.freeze([
  'SYS_ADMIN',
  'SYS_PTRACE',
  'NET_ADMIN',
  'SYS_MODULE',
  'DAC_OVERRIDE',
  'ALL'
]);
const SENSITIVE_HOST_PATHS = Object.freeze([
  '/',
  '/etc',
  '/proc',
  '/sys',
  '/root',
  '/boot',
  '/dev',
  '/var/run'
]);

const ADMISSION_RULES = Object.freeze([
  {
    id: 'no_privileged',
    title: 'Disallow privileged containers',
    severity: 'critical',
    standard: 'CIS-5.4 / PSS-Baseline',
    description: 'Prevents containers from running with full host kernel capabilities (privileged: true).'
  },
  {
    id: 'no_docker_sock_mount',
    title: 'Disallow Docker/containerd socket mounts',
    severity: 'critical',
    standard: 'CIS-5.31 / PSS-Baseline',
    description: 'Blocks bind-mounting docker.sock or containerd.sock into workload containers.'
  },
  {
    id: 'no_host_root_mount',
    title: 'Disallow host root & sensitive OS path mounts',
    severity: 'critical',
    standard: 'CIS-5.5 / PSS-Baseline',
    description: 'Blocks bind mounts of /, /etc, /proc, /sys, /root, /boot, /dev, and /var/run (cures Coolify - /:/host:rw).'
  },
  {
    id: 'no_dangerous_caps',
    title: 'Disallow dangerous Linux capabilities',
    severity: 'critical',
    standard: 'CIS-5.3 / PSS-Baseline',
    description: 'Blocks SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_MODULE, DAC_OVERRIDE, and ALL.'
  },
  {
    id: 'no_latest_tag',
    title: 'Disallow mutable :latest or untagged images',
    severity: 'high',
    standard: 'SLSA-Build / PSS-Restricted',
    description: 'Requires pinned version tags or immutable @sha256 digests for reproducible deployments.'
  },
  {
    id: 'require_non_root_uid',
    title: 'Require non-root container UID',
    severity: 'high',
    standard: 'CIS-4.1 / PSS-Restricted',
    description: 'Requires an explicit non-root user/UID (blocks 0, root, 0:0, or omitted user).'
  },
  {
    id: 'require_resource_limits',
    title: 'Require explicit CPU and memory limits',
    severity: 'medium',
    standard: 'CIS-5.10 / CIS-5.11',
    description: 'Requires positive memoryLimitMb and cpuLimit to prevent noisy-neighbor VPS OOM outages.'
  },
  {
    id: 'require_healthcheck',
    title: 'Require container healthcheck',
    severity: 'medium',
    standard: 'CIS-4.6 / Zero-Downtime',
    description: 'Requires a healthcheck command or HTTP healthcheckPath for atomic blue-green cutovers.'
  },
  {
    id: 'require_signed_attestation',
    title: 'Require verified SLSA v1.1 Ed25519 attestation',
    severity: 'high',
    standard: 'SLSA-v1.1 / SOC2-CC7.1',
    description: 'Requires cryptographically verified release provenance before production admission.'
  },
  {
    id: 'no_public_db_or_panel_bind',
    title: 'Disallow public 0.0.0.0/:: bind on DB & sensitive ports',
    severity: 'critical',
    standard: 'CIS-5.13 / dokploy#2661',
    description: 'Prevents accidental UFW-bypassing public exposure of ports 3000, 5432, 3306, 6379, 27017, and 11434.'
  }
]);

const ALL_RULE_IDS = ADMISSION_RULES.map((r) => r.id);
const ALLOWED_MODES = new Set(['enforce', 'audit', 'off']);

/**
 * Builds a complete 10-rule mode map from a list of enforced rule IDs.
 * @param {string[]} enforcedIds
 * @returns {Record<string, 'enforce' | 'audit' | 'off'>}
 */
function buildRuleMap(enforcedIds) {
  const set = new Set(enforcedIds);
  /** @type {Record<string, 'enforce' | 'audit' | 'off'>} */
  const out = {};
  for (const id of ALL_RULE_IDS) {
    out[id] = set.has(id) ? 'enforce' : 'audit';
  }
  return out;
}

const POLICY_PRESETS = Object.freeze({
  baseline: Object.freeze({
    name: 'baseline',
    label: 'Baseline (CIS/PSS Critical Guardrails)',
    description: 'Enforces the 5 critical host-escape & public-bind rules; audits best-practice rules.',
    rules: Object.freeze(buildRuleMap([
      'no_privileged',
      'no_docker_sock_mount',
      'no_host_root_mount',
      'no_dangerous_caps',
      'no_public_db_or_panel_bind'
    ]))
  }),
  restricted: Object.freeze({
    name: 'restricted',
    label: 'Restricted (Production Hardened)',
    description: 'Enforces 9 rules including pinned tags, non-root UID, resource caps & healthchecks; audits SLSA attestation.',
    rules: Object.freeze(buildRuleMap([
      'no_privileged',
      'no_docker_sock_mount',
      'no_host_root_mount',
      'no_dangerous_caps',
      'no_public_db_or_panel_bind',
      'no_latest_tag',
      'require_non_root_uid',
      'require_resource_limits',
      'require_healthcheck'
    ]))
  }),
  'soc2-strict': Object.freeze({
    name: 'soc2-strict',
    label: 'SOC 2 Strict (All 10 Rules Enforced)',
    description: 'Enforces ALL 10 CIS/PSS/SLSA rules including cryptographically verified SLSA v1.1 attestation.',
    rules: Object.freeze(buildRuleMap(ALL_RULE_IDS))
  })
});

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode.
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
 * Normalizes a POSIX host mount path cleanly (`///etc/` -> `/etc`).
 * @param {string} rawPath
 * @returns {string}
 */
function normalizeHostPath(rawPath) {
  let clean = String(rawPath || '').trim().replace(/\\/g, '/');
  clean = clean.replace(/\/+/g, '/');
  if (clean.length > 1 && clean.endsWith('/')) clean = clean.slice(0, -1);
  return clean;
}

/**
 * Extracts normalized `{ source, target, raw }` mount entries from `spec.mounts` & `spec.volumes`.
 * @param {any} spec
 * @returns {Array<{ source: string, target: string, raw: string }>}
 */
function extractMounts(spec) {
  const combined = [
    ...(Array.isArray(spec.mounts) ? spec.mounts : []),
    ...(Array.isArray(spec.volumes) ? spec.volumes : [])
  ];
  /** @type {Array<{ source: string, target: string, raw: string }>} */
  const out = [];
  for (const item of combined) {
    if (typeof item === 'string') {
      const trimmed = item.trim().replace(/^-\s+/, '');
      if (!trimmed) continue;
      // Handle Windows drive prefix gracefully while splitting POSIX `source:target[:mode]`
      const parts = trimmed.split(':');
      const source = parts[0] || '';
      const target = parts[1] || '';
      out.push({ source: normalizeHostPath(source), target: normalizeHostPath(target), raw: trimmed });
    } else if (item && typeof item === 'object') {
      const source = normalizeHostPath(item.source || item.hostPath || item.src || '');
      const target = normalizeHostPath(item.target || item.containerPath || item.dest || '');
      out.push({ source, target, raw: `${source}:${target}` });
    }
  }
  return out;
}

/**
 * Checks whether a host path matches `/` or any sensitive host OS directory.
 * @param {string} normSource
 * @returns {boolean}
 */
function isSensitiveHostPath(normSource) {
  if (!normSource || !normSource.startsWith('/')) return false;
  if (normSource === '/') return true;
  for (const bad of SENSITIVE_HOST_PATHS) {
    if (bad === '/') continue;
    if (normSource === bad || normSource.startsWith(`${bad}/`)) return true;
  }
  return false;
}

/**
 * Checks if a container image reference uses `:latest` or lacks an explicit tag/digest.
 * @param {any} rawImage
 * @returns {{ ok: boolean, detail: string }}
 */
function checkPinnedImageTag(rawImage) {
  const img = String(rawImage || '').trim();
  if (!img) return { ok: false, detail: 'Missing container image reference' };
  if (/@sha256:[0-9a-f]{64}$/i.test(img)) return { ok: true, detail: 'Pinned by sha256 digest' };
  const lastSlash = img.lastIndexOf('/');
  const lastColon = img.lastIndexOf(':');
  if (lastColon <= lastSlash) {
    return { ok: false, detail: `Image "${img}" omits an explicit tag or @sha256 digest (implicitly resolves to :latest)` };
  }
  const tag = img.slice(lastColon + 1).toLowerCase();
  if (!tag || tag === 'latest') {
    return { ok: false, detail: `Image "${img}" uses mutable ":latest" tag` };
  }
  return { ok: true, detail: `Pinned tag ":${tag}"` };
}

/**
 * Extracts public-bound port bindings from `spec.bindAddress`, `spec.port`, `spec.ports`, `spec.portBindings`.
 * @param {any} spec
 * @returns {Array<{ hostIp: string, port: number, raw: string }>}
 */
function extractSensitivePublicBindings(spec) {
  /** @type {Array<{ hostIp: string, port: number, raw: string }>} */
  const violations = [];
  const sensitiveSet = new Set(SENSITIVE_PUBLIC_PORTS);
  const isPublicIp = (/** @type {string} */ ip) => {
    const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    return clean === '0.0.0.0' || clean === '::' || clean === '*' || clean === '0:0:0:0:0:0:0:0';
  };

  // 1. Top-level bindAddress + port / containerPort
  if (spec.bindAddress && isPublicIp(spec.bindAddress)) {
    const topPort = Number(spec.port || spec.hostPort || spec.containerPort);
    if (Number.isInteger(topPort) && sensitiveSet.has(topPort)) {
      violations.push({ hostIp: String(spec.bindAddress), port: topPort, raw: `${spec.bindAddress}:${topPort}` });
    }
  }

  // 2. ports[] / portBindings[] entries (`0.0.0.0:5432:5432`, `[::]:3000:3000`, or `{ hostIp, hostPort, containerPort }`)
  const portList = [
    ...(Array.isArray(spec.ports) ? spec.ports : []),
    ...(Array.isArray(spec.portBindings) ? spec.portBindings : [])
  ];
  for (const entry of portList) {
    if (typeof entry === 'string') {
      const s = entry.trim();
      const v6Match = /^\[([^\]]+)\]:(\d+)(?::(\d+))?/.exec(s);
      if (v6Match) {
        const hostIp = v6Match[1];
        const p1 = Number(v6Match[2]);
        const p2 = v6Match[3] ? Number(v6Match[3]) : p1;
        if (isPublicIp(hostIp) && (sensitiveSet.has(p1) || sensitiveSet.has(p2))) {
          violations.push({ hostIp, port: sensitiveSet.has(p1) ? p1 : p2, raw: s });
        }
        continue;
      }
      const parts = s.split(':');
      if (parts.length >= 2) {
        const hostIp = parts[0];
        const p1 = Number(parts[1].replace(/\/(?:tcp|udp)$/i, ''));
        const p2 = parts[2] ? Number(parts[2].replace(/\/(?:tcp|udp)$/i, '')) : p1;
        if (isPublicIp(hostIp) && (sensitiveSet.has(p1) || sensitiveSet.has(p2))) {
          violations.push({ hostIp, port: sensitiveSet.has(p1) ? p1 : p2, raw: s });
        }
      }
    } else if (entry && typeof entry === 'object') {
      const hostIp = String(entry.hostIp || entry.bindAddress || '').trim();
      const p1 = Number(entry.hostPort || entry.port);
      const p2 = Number(entry.containerPort || p1);
      if (isPublicIp(hostIp) && (sensitiveSet.has(p1) || sensitiveSet.has(p2))) {
        violations.push({ hostIp, port: sensitiveSet.has(p1) ? p1 : p2, raw: `${hostIp}:${p1}` });
      }
    }
  }

  return violations;
}

/**
 * Evaluates a deployment specification against all 10 CIS/PSS admission rules.
 *
 * @param {Record<string, any>} spec
 * @param {{
 *   policy?: { preset?: string, rules?: Record<string, 'enforce' | 'audit' | 'off'> } | null,
 *   preset?: string | null
 * }} [opts]
 */
function evaluateSpec(spec, opts = {}) {
  const input = spec && typeof spec === 'object' ? spec : {};
  const presetKey = (opts.preset && opts.preset in POLICY_PRESETS)
    ? String(opts.preset)
    : ((opts.policy && opts.policy.preset && opts.policy.preset in POLICY_PRESETS)
      ? String(opts.policy.preset)
      : 'baseline');
  const basePreset = POLICY_PRESETS[/** @type {'baseline' | 'restricted' | 'soc2-strict'} */ (presetKey)];
  /** @type {Record<string, 'enforce' | 'audit' | 'off'>} */
  const ruleModes = { ...basePreset.rules };
  if (opts.policy && opts.policy.rules && typeof opts.policy.rules === 'object' && !opts.preset) {
    for (const [k, v] of Object.entries(opts.policy.rules)) {
      if (k in ruleModes && ALLOWED_MODES.has(String(v))) {
        ruleModes[k] = /** @type {'enforce' | 'audit' | 'off'} */ (v);
      }
    }
  }

  const mounts = extractMounts(input);
  const rawCaps = Array.isArray(input.capAdd)
    ? input.capAdd
    : (Array.isArray(input.cap_add) ? input.cap_add : (Array.isArray(input.capabilities) ? input.capabilities : []));
  const normalizedCaps = rawCaps.map((c) => String(c || '').trim().toUpperCase().replace(/^CAP_/, ''));

  /** @type {Record<string, { passed: boolean, message: string }>} */
  const checks = {};

  // 1. no_privileged
  checks.no_privileged = input.privileged === true
    ? { passed: false, message: 'Container requests privileged: true (full host kernel access)' }
    : { passed: true, message: 'Container is unprivileged' };

  // 2. no_docker_sock_mount
  const sockMount = mounts.find((m) => /(?:docker|containerd)\.sock/i.test(m.source) || /(?:docker|containerd)\.sock/i.test(m.target));
  checks.no_docker_sock_mount = sockMount
    ? { passed: false, message: `Container mounts host container runtime socket (${sockMount.raw})` }
    : { passed: true, message: 'No docker.sock or containerd.sock bind mounts' };

  // 3. no_host_root_mount
  const hostRootMount = mounts.find((m) => isSensitiveHostPath(m.source));
  checks.no_host_root_mount = hostRootMount
    ? { passed: false, message: `Sensitive host filesystem path mounted into container (${hostRootMount.raw})` }
    : { passed: true, message: 'No sensitive host OS directory mounts' };

  // 4. no_dangerous_caps
  const badCaps = normalizedCaps.filter((c) => DANGEROUS_CAPABILITIES.includes(/** @type {any} */ (c)));
  checks.no_dangerous_caps = badCaps.length > 0
    ? { passed: false, message: `Dangerous Linux capabilities requested: ${badCaps.join(', ')}` }
    : { passed: true, message: 'No dangerous Linux capabilities added' };

  // 5. no_latest_tag
  const imgCheck = checkPinnedImageTag(input.image);
  checks.no_latest_tag = { passed: imgCheck.ok, message: imgCheck.detail };

  // 6. require_non_root_uid
  const rawUser = input.user !== undefined ? input.user : (input.uid !== undefined ? input.uid : input.runAsUser);
  const userStr = rawUser === undefined || rawUser === null ? '' : String(rawUser).trim().toLowerCase();
  const isRootOrMissing = !userStr || userStr === '0' || userStr === 'root' || userStr.startsWith('0:') || userStr.startsWith('root:');
  checks.require_non_root_uid = isRootOrMissing
    ? { passed: false, message: userStr ? `Container configured to run as root ("${userStr}")` : 'Container omits explicit non-root user/UID' }
    : { passed: true, message: `Explicit non-root user configured ("${userStr}")` };

  // 7. require_resource_limits
  const memMb = Number(input.memoryLimitMb ?? input.memoryMb ?? input.resources?.memoryLimitMb ?? input.resources?.memoryMb);
  const cpuLim = Number(input.cpuLimit ?? input.cpus ?? input.resources?.cpuLimit ?? input.resources?.cpus);
  const hasLimits = Number.isFinite(memMb) && memMb > 0 && Number.isFinite(cpuLim) && cpuLim > 0;
  checks.require_resource_limits = hasLimits
    ? { passed: true, message: `Resource caps set (${memMb} MB RAM, ${cpuLim} CPUs)` }
    : { passed: false, message: 'Missing positive memoryLimitMb and/or cpuLimit resource caps' };

  // 8. require_healthcheck
  const hasHealth = Boolean(
    (typeof input.healthcheck === 'string' && input.healthcheck.trim()) ||
    (input.healthcheck && typeof input.healthcheck === 'object') ||
    (typeof input.healthcheckPath === 'string' && input.healthcheckPath.trim()) ||
    (typeof input.healthPath === 'string' && input.healthPath.trim())
  );
  checks.require_healthcheck = hasHealth
    ? { passed: true, message: 'Healthcheck configured' }
    : { passed: false, message: 'Missing container healthcheck / healthcheckPath' };

  // 9. require_signed_attestation
  const hasAttestation = Boolean(
    input.attestationVerified === true ||
    input.signedAttestation === true ||
    (input.slsaAttestation && input.slsaAttestation.valid === true)
  );
  checks.require_signed_attestation = hasAttestation
    ? { passed: true, message: 'SLSA v1.1 Ed25519 attestation verified' }
    : { passed: false, message: 'Release lacks verified SLSA v1.1 Ed25519 attestation' };

  // 10. no_public_db_or_panel_bind
  const publicBinds = extractSensitivePublicBindings(input);
  checks.no_public_db_or_panel_bind = publicBinds.length > 0
    ? { passed: false, message: `Public 0.0.0.0/:: bind on sensitive DB/panel port(s): ${publicBinds.map((b) => b.raw).join(', ')}` }
    : { passed: true, message: 'No sensitive DB/panel ports exposed on 0.0.0.0/::' };

  /** @type {Array<any>} */
  const enforcedViolations = [];
  /** @type {Array<any>} */
  const auditWarnings = [];
  /** @type {Array<any>} */
  const passedRules = [];

  for (const rule of ADMISSION_RULES) {
    const mode = ruleModes[rule.id] || 'audit';
    const res = checks[rule.id];
    const item = {
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      standard: rule.standard,
      mode,
      message: res.message
    };
    if (mode === 'off' || res.passed) {
      passedRules.push(item);
    } else if (mode === 'enforce') {
      enforcedViolations.push(item);
    } else {
      auditWarnings.push(item);
    }
  }

  const allowed = enforcedViolations.length === 0;
  const decision = !allowed ? 'DENY' : (auditWarnings.length > 0 ? 'AUDIT_WARN' : 'ALLOW');
  const score = Math.round((passedRules.length / ADMISSION_RULES.length) * 100);

  return {
    ok: true,
    allowed,
    decision,
    preset: presetKey,
    score,
    totalRules: ADMISSION_RULES.length,
    enforcedViolations,
    auditWarnings,
    passedRules,
    evaluatedAt: new Date().toISOString()
  };
}

class AdmissionPolicyService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
  }

  /** @returns {string} */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'admission-policies.json');
  }

  /** Returns the active persisted admission policy (defaults to `baseline` preset). */
  getPolicy() {
    const p = this.getStoreFilePath();
    if (fs.existsSync(p)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (parsed && parsed.rules && typeof parsed.rules === 'object') {
          const preset = (parsed.preset && parsed.preset in POLICY_PRESETS) ? parsed.preset : 'baseline';
          return {
            preset,
            rules: { ...POLICY_PRESETS[/** @type {'baseline' | 'restricted' | 'soc2-strict'} */ (preset)].rules, ...parsed.rules },
            updatedAt: parsed.updatedAt || null,
            presets: Object.keys(POLICY_PRESETS),
            catalog: ADMISSION_RULES
          };
        }
      } catch (e) {}
    }
    return {
      preset: 'baseline',
      rules: { ...POLICY_PRESETS.baseline.rules },
      updatedAt: null,
      presets: Object.keys(POLICY_PRESETS),
      catalog: ADMISSION_RULES
    };
  }

  /**
   * Applies one of the built-in presets (`baseline`, `restricted`, `soc2-strict`) atomically.
   * @param {string} presetName
   */
  applyPreset(presetName) {
    const key = String(presetName || '').trim().toLowerCase();
    if (!(key in POLICY_PRESETS)) {
      const err = /** @type {any} */ (new Error(`Unknown admission policy preset "${presetName}". Valid: ${Object.keys(POLICY_PRESETS).join(', ')}`));
      err.code = 'INVALID_PRESET';
      err.status = 400;
      throw err;
    }
    return this.updatePolicy({
      preset: key,
      rules: { ...POLICY_PRESETS[/** @type {'baseline' | 'restricted' | 'soc2-strict'} */ (key)].rules }
    });
  }

  /**
   * Updates active admission policy preset and/or individual rule modes (`enforce` | `audit` | `off`).
   * @param {{ preset?: string, rules?: Record<string, string> }} patch
   */
  updatePolicy(patch = {}) {
    const current = this.getPolicy();
    let nextPreset = current.preset;
    /** @type {Record<string, 'enforce' | 'audit' | 'off'>} */
    let nextRules = { ...current.rules };

    if (patch.preset !== undefined) {
      const key = String(patch.preset || '').trim().toLowerCase();
      if (!(key in POLICY_PRESETS)) {
        const err = /** @type {any} */ (new Error(`Unknown admission policy preset "${patch.preset}"`));
        err.code = 'INVALID_PRESET';
        err.status = 400;
        throw err;
      }
      nextPreset = key;
      nextRules = { ...POLICY_PRESETS[/** @type {'baseline' | 'restricted' | 'soc2-strict'} */ (key)].rules };
    }

    if (patch.rules && typeof patch.rules === 'object') {
      for (const [ruleId, modeRaw] of Object.entries(patch.rules)) {
        if (!(ruleId in nextRules)) continue;
        const mode = String(modeRaw || '').trim().toLowerCase();
        if (!ALLOWED_MODES.has(mode)) {
          const err = /** @type {any} */ (new Error(`Invalid rule mode "${modeRaw}" for "${ruleId}" (expected enforce|audit|off)`));
          err.code = 'INVALID_RULE_MODE';
          err.status = 400;
          throw err;
        }
        nextRules[ruleId] = /** @type {'enforce' | 'audit' | 'off'} */ (mode);
      }
    }

    const updatedAt = new Date().toISOString();
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, preset: nextPreset, rules: nextRules, updatedAt }, null, 2) + '\n'
    );

    return {
      ok: true,
      preset: nextPreset,
      rules: nextRules,
      updatedAt,
      presets: Object.keys(POLICY_PRESETS),
      catalog: ADMISSION_RULES
    };
  }

  /**
   * Evaluates a deployment spec against the active persisted policy (or explicit `policy`/`preset` override).
   * @param {Record<string, any>} spec
   * @param {{ policy?: any, preset?: string | null }} [opts]
   */
  evaluateDeployment(spec, opts = {}) {
    const activePolicy = opts.policy || this.getPolicy();
    return evaluateSpec(spec, {
      policy: activePolicy,
      preset: opts.preset || null
    });
  }
}

const defaultAdmissionPolicyService = new AdmissionPolicyService();

const exported = Object.assign(defaultAdmissionPolicyService, {
  AdmissionPolicyService,
  ADMISSION_RULES,
  POLICY_PRESETS,
  evaluateSpec,
  SENSITIVE_PUBLIC_PORTS,
  DANGEROUS_CAPABILITIES,
  SENSITIVE_HOST_PATHS
});

module.exports = exported;
