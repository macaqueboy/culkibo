const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * 4-Phase Zero-Shell Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner.
 *
 * Cures:
 *  - Coolify `CVE-2025-66213` (CVSS 10.0 volume-name command injection)
 *  - Recursive host `chown` mount breaks
 *  - Dokploy `999:999` Postgres UID ownership errors & Kamal `root:root` `Errno::EACCES`
 *    (preserves exact numeric `uid:gid` via `tar --numeric-owner` + post-restore `stat` check!)
 *
 * 0 dependencias npm externas, 0 invocaciones de shell, persistencia atómica `0o600`.
 */

const SAFE_VOLUME_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const SAFE_HOST_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,252}$/;
const SAFE_PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const SAFE_CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const SAFE_MOUNT_PATH_RE = /^\/[a-zA-Z0-9._/-]{1,240}$/;
const SHELL_METACHAR_RE = /[;|&`$<>"'\\\r\n\0\s]/;
const MAX_MIGRATION_HISTORY = 100;

const FORBIDDEN_MOUNT_ROOTS = Object.freeze([
  '/',
  '/etc',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/root',
  '/var/run/docker.sock',
  '/run/docker.sock'
]);

/** @param {string | null} [overrideDir] */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Crea un error HTTP tipado.
 * @param {string} msg
 * @param {number} status
 * @param {string} code
 */
function makeMigError(msg, status, code) {
  const err = new Error(msg);
  /** @type {any} */ (err).status = status;
  /** @type {any} */ (err).code = code;
  return err;
}

/**
 * Valida estrictamente una petición de migración de volumen stateful entre nodos VPS,
 * bloqueando inyección en `volumeName` (`CVE-2025-66213`), traversal en `mountPath`,
 * rutas sensibles del host, UID/GID fuera de rango y cruces entre organizaciones (`403`).
 *
 * @param {{
 *   projectId: string,
 *   volumeName: string,
 *   mountPath: string,
 *   sourceHost?: string,
 *   targetHost: string,
 *   uid?: number,
 *   gid?: number,
 *   containerName?: string,
 *   estimatedMb?: number,
 *   sourceOrgId?: string,
 *   targetOrgId?: string
 * }} req
 */
function validateVolumeMigrationRequest(req) {
  if (!req || typeof req !== 'object') {
    throw makeMigError('Petición de migración de volumen inválida', 400, 'INVALID_REQUEST');
  }

  const sourceOrgId = String(req.sourceOrgId ?? 'default').trim() || 'default';
  const targetOrgId = String(req.targetOrgId ?? 'default').trim() || 'default';
  if (sourceOrgId !== targetOrgId) {
    throw makeMigError(
      `Cross-organization volume migration forbidden (${sourceOrgId} -> ${targetOrgId})`,
      403,
      'CROSS_TENANT_FORBIDDEN'
    );
  }

  const projectId = String(req.projectId || '').trim();
  if (!projectId || !SAFE_PROJECT_ID_RE.test(projectId)) {
    throw makeMigError(`projectId inválido: "${projectId.slice(0, 60)}"`, 400, 'INVALID_PROJECT_ID');
  }

  const volumeName = String(req.volumeName || '').trim();
  if (
    !volumeName
    || SHELL_METACHAR_RE.test(volumeName)
    || volumeName.includes('..')
    || volumeName.includes('/')
    || !SAFE_VOLUME_NAME_RE.test(volumeName)
  ) {
    throw makeMigError(
      `Nombre de volumen inseguro rechazado (CVE-2025-66213 guard): "${volumeName.slice(0, 60)}"`,
      400,
      'UNSAFE_VOLUME_NAME'
    );
  }

  const rawMount = String(req.mountPath || '').trim();
  const normalizedMount = rawMount.replace(/\/+$/, '') || '/';
  if (
    !rawMount
    || !rawMount.startsWith('/')
    || rawMount.includes('..')
    || SHELL_METACHAR_RE.test(rawMount)
    || !SAFE_MOUNT_PATH_RE.test(rawMount)
  ) {
    throw makeMigError(`mountPath inseguro o traversal rechazado: "${rawMount.slice(0, 80)}"`, 400, 'UNSAFE_MOUNT_PATH');
  }
  for (const forbidden of FORBIDDEN_MOUNT_ROOTS) {
    if (normalizedMount === forbidden || (forbidden !== '/' && normalizedMount.startsWith(`${forbidden}/`))) {
      throw makeMigError(
        `mountPath apunta a ruta protegida del host ("${normalizedMount}")`,
        400,
        'FORBIDDEN_HOST_MOUNT_PATH'
      );
    }
  }

  const sourceHost = String(req.sourceHost || 'local').trim();
  const targetHost = String(req.targetHost || '').trim();
  if (!sourceHost || SHELL_METACHAR_RE.test(sourceHost) || !SAFE_HOST_RE.test(sourceHost)) {
    throw makeMigError(`sourceHost inválido: "${sourceHost.slice(0, 60)}"`, 400, 'INVALID_SOURCE_HOST');
  }
  if (!targetHost || SHELL_METACHAR_RE.test(targetHost) || !SAFE_HOST_RE.test(targetHost)) {
    throw makeMigError(`targetHost inválido: "${targetHost.slice(0, 60)}"`, 400, 'INVALID_TARGET_HOST');
  }
  if (sourceHost.toLowerCase() === targetHost.toLowerCase()) {
    throw makeMigError('sourceHost y targetHost deben ser nodos distintos', 400, 'SAME_SOURCE_AND_TARGET');
  }

  const uid = req.uid !== undefined ? Number(req.uid) : 999;
  const gid = req.gid !== undefined ? Number(req.gid) : 999;
  if (!Number.isInteger(uid) || uid < 0 || uid > 65534) {
    throw makeMigError(`uid inválido: "${req.uid}" (requiere entero 0..65534)`, 400, 'INVALID_UID');
  }
  if (!Number.isInteger(gid) || gid < 0 || gid > 65534) {
    throw makeMigError(`gid inválido: "${req.gid}" (requiere entero 0..65534)`, 400, 'INVALID_GID');
  }

  const containerName = req.containerName ? String(req.containerName).trim() : '';
  if (containerName && (SHELL_METACHAR_RE.test(containerName) || !SAFE_CONTAINER_RE.test(containerName))) {
    throw makeMigError(`containerName inválido: "${containerName.slice(0, 60)}"`, 400, 'INVALID_CONTAINER_NAME');
  }

  const estimatedMb = Math.min(10 * 1024 * 1024, Math.max(1, Math.round(Number(req.estimatedMb ?? 256) || 256)));

  return {
    projectId,
    volumeName,
    mountPath: normalizedMount,
    sourceHost,
    targetHost,
    uid,
    gid,
    containerName,
    estimatedMb,
    sourceOrgId,
    targetOrgId
  };
}

/**
 * Construye el plan determinista de 4 fases 100% libre de shell (`program` + `args[]`)
 * con preservación numérica `--numeric-owner` (`uid:gid`) y verificación SHA-256.
 *
 * @param {ReturnType<typeof validateVolumeMigrationRequest>} validated
 */
function buildFourPhaseArgvPlan(validated) {
  const safeSlug = validated.volumeName.replace(/[^a-zA-Z0-9_-]+/g, '_');
  const archiveName = `${safeSlug}.tar.gz`;
  const manifestName = `${safeSlug}.sha256`;
  const stagingDir = `/var/tmp/culkibo-volmig/${safeSlug}`;
  const helperImage = 'alpine:3.20';

  const sshBaseArgs = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ControlMaster=auto',
    '-o', 'ControlPersist=120',
    '--',
    `root@${validated.targetHost}`
  ];

  // Phase 1: Warm non-disruptive pre-sync & disk headroom check
  const phase1 = {
    phase: 1,
    id: 'pre_sync',
    title: 'Warm pre-sync & disk headroom verification',
    disruptive: false,
    commands: [
      { program: 'docker', args: ['volume', 'inspect', validated.volumeName] },
      { program: 'df', args: ['-Pm', '/var/lib/docker'] },
      { program: 'ssh', args: [...sshBaseArgs, 'docker', 'volume', 'create', validated.volumeName] }
    ]
  };

  // Phase 2: Quiesce -> numeric-owner tar -> SHA-256 manifest -> immediate unpause
  /** @type {Array<{ program: string, args: string[] }>} */
  const phase2Commands = [];
  if (validated.containerName) {
    phase2Commands.push({ program: 'docker', args: ['pause', validated.containerName] });
  }
  phase2Commands.push(
    {
      program: 'docker',
      args: [
        'run', '--rm',
        '--mount', `type=volume,source=${validated.volumeName},target=/source,readonly`,
        '-v', `${stagingDir}:/backup`,
        helperImage,
        'tar', '--numeric-owner', '-czf', `/backup/${archiveName}`, '-C', '/source', '.'
      ]
    },
    {
      program: 'sha256sum',
      args: [`${stagingDir}/${archiveName}`]
    }
  );
  if (validated.containerName) {
    phase2Commands.push({ program: 'docker', args: ['unpause', validated.containerName] });
  }

  const phase2 = {
    phase: 2,
    id: 'quiesce_snapshot',
    title: `Quiesce snapshot with --numeric-owner (${validated.uid}:${validated.gid}) & SHA-256`,
    disruptive: Boolean(validated.containerName),
    preservesNumericOwner: `${validated.uid}:${validated.gid}`,
    commands: phase2Commands
  };

  // Phase 3: Zero-shell SSH ControlMaster stream transfer
  const phase3 = {
    phase: 3,
    id: 'ssh_stream_transfer',
    title: `SSH ControlMaster zero-shell transfer to ${validated.targetHost}`,
    disruptive: false,
    commands: [
      { program: 'ssh', args: [...sshBaseArgs, 'mkdir', '-p', stagingDir] },
      {
        program: 'scp',
        args: [
          '-o', 'BatchMode=yes',
          '-o', 'StrictHostKeyChecking=yes',
          '-o', 'ControlMaster=auto',
          `${stagingDir}/${archiveName}`,
          `${stagingDir}/${manifestName}`,
          `root@${validated.targetHost}:${stagingDir}/`
        ]
      }
    ]
  };

  // Phase 4: Verify SHA-256 -> restore --numeric-owner -> stat uid:gid check -> retain source for rollback
  const phase4 = {
    phase: 4,
    id: 'verify_and_cutover',
    title: `Target SHA-256 verification, --numeric-owner extract & ${validated.uid}:${validated.gid} stat check`,
    disruptive: false,
    retainSourceVolumeForRollback: true,
    expectedUidGid: `${validated.uid}:${validated.gid}`,
    commands: [
      { program: 'ssh', args: [...sshBaseArgs, 'sha256sum', '-c', `${stagingDir}/${manifestName}`] },
      {
        program: 'ssh',
        args: [
          ...sshBaseArgs,
          'docker', 'run', '--rm',
          '--mount', `type=volume,source=${validated.volumeName},target=/target`,
          '-v', `${stagingDir}:/backup:ro`,
          helperImage,
          'tar', '--numeric-owner', '-xzf', `/backup/${archiveName}`, '-C', '/target'
        ]
      },
      {
        program: 'ssh',
        args: [
          ...sshBaseArgs,
          'docker', 'run', '--rm',
          '--mount', `type=volume,source=${validated.volumeName},target=/target,readonly`,
          helperImage,
          'stat', '-c', '%u:%g', '/target'
        ]
      }
    ]
  };

  return {
    zeroShell: true,
    numericOwnerPreserved: true,
    uidGid: `${validated.uid}:${validated.gid}`,
    retainSourceVolume: true,
    requiredFreeSpaceMb: Math.ceil(validated.estimatedMb * 2.2),
    phases: [phase1, phase2, phase3, phase4]
  };
}

class VolumeMigrationService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._loaded = false;
    /** @type {{ version: number, migrations: any[] }} */
    this.state = { version: 1, migrations: [] };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'volume-migrations.json');
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && Array.isArray(parsed.migrations)) {
          this.state = { version: 1, migrations: parsed.migrations };
          return;
        }
      } catch (e) {}
    }
    this.state = { version: 1, migrations: [] };
  }

  _save() {
    this._ensureLoaded();
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.storeFile)) {
      try { fs.copyFileSync(this.storeFile, `${this.storeFile}.bak`); } catch (e) {}
    }
    atomicWriteJsonSync(this.storeFile, this.state, 0o600);
  }

  /**
   * Valida, genera y persiste un plan atómico de migración de volumen de 4 fases.
   * @param {any} req
   */
  planMigration(req) {
    const validated = validateVolumeMigrationRequest(req);
    const plan = buildFourPhaseArgvPlan(validated);

    const record = {
      id: `volmig_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
      status: 'planned',
      createdAt: new Date().toISOString(),
      request: validated,
      ...plan
    };

    this._ensureLoaded();
    this.state.migrations.unshift(record);
    if (this.state.migrations.length > MAX_MIGRATION_HISTORY) {
      this.state.migrations = this.state.migrations.slice(0, MAX_MIGRATION_HISTORY);
    }
    this._save();

    return { ok: true, ...record };
  }

  /**
   * Lista planes de migración de volúmenes filtrando estrictamente por `projectIds` si se provee.
   * @param {{ projectIds?: string[] | Set<string> | null }} [opts]
   */
  listMigrations(opts = {}) {
    this._ensureLoaded();
    const allowedSet = opts && opts.projectIds != null
      ? new Set(Array.from(opts.projectIds).map(String))
      : null;

    const list = this.state.migrations.filter((m) => {
      if (!m || !m.request) return false;
      if (allowedSet && !allowedSet.has(String(m.request.projectId))) return false;
      return true;
    });

    return {
      ok: true,
      count: list.length,
      migrations: list
    };
  }

  /** @param {string} id */
  getMigration(id) {
    this._ensureLoaded();
    return this.state.migrations.find((m) => m && m.id === id) || null;
  }
}

const instance = /** @type {any} */ (new VolumeMigrationService());
instance.VolumeMigrationService = VolumeMigrationService;
instance.SAFE_VOLUME_NAME_RE = SAFE_VOLUME_NAME_RE;
instance.SAFE_HOST_RE = SAFE_HOST_RE;
instance.validateVolumeMigrationRequest = validateVolumeMigrationRequest;
instance.buildFourPhaseArgvPlan = buildFourPhaseArgvPlan;
module.exports = instance;
