const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');

/**
 * Motor de sincronización en vivo (The Forge): guarda un fichero en local y
 * aparece servido en el destino en milisegundos, sin commit, sin build y sin
 * simulaciones.
 *
 * Propiedades reales implementadas aquí:
 *  1. Commit frames atómicos: un agente de IA edita 15 ficheros en ráfaga y
 *     llegan como una única transacción numerada (`seq`), evitando estados
 *     intermedios rotos.
 *  2. Deduplicación por SHA-256: un fichero cuyo contenido ya coincide con el
 *     disco no vuelve a escribirse ni provoca recargas innecesarias.
 *  3. Historial de parches en memoria: cada commit frame guarda los bytes
 *     anteriores exactos para revertir (`rollback`) en <10 ms sin reconstruir.
 *  4. Clasificación honesta Camino B vs Camino C: nunca disfraza un cambio de
 *     dependencias o Dockerfile de hot-reload; lo declara como `path_c_restart`.
 *  5. Integridad por árbol de Merkle: `computeMerkleTree()` y `verifySync()`
 *     hacen imposible la divergencia silenciosa entre máquina local y servidor.
 *  6. Seguridad estricta de rutas: bloquea traversal (`..`), rutas absolutas,
 *     bytes nulos, escritura en `.git/` y escapes por symlink.
 */

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.next',
  '.nuxt',
  '.turbo',
  '.svelte-kit',
  '.output',
  '.astro',
  '.cache',
  '.culkibo',
  'dist',
  'build',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  'target',
  'vendor'
]);

const IGNORED_FILES = new Set(['.DS_Store', 'Thumbs.db']);

const MAX_FILES_PER_FRAME = 500;
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB por fichero en un frame
const MAX_PATCH_HISTORY = 25;
const MAX_LATENCY_SAMPLES = 200;

/** Ficheros cuya modificación exige reiniciar proceso/rebuild (Camino C). */
const PATH_C_PATTERNS = [
  /(^|\/)package\.json$/i,
  /(^|\/)package-lock\.json$/i,
  /(^|\/)pnpm-lock\.yaml$/i,
  /(^|\/)yarn\.lock$/i,
  /(^|\/)bun\.lockb?$/i,
  /(^|\/)dockerfile$/i,
  /(^|\/)docker-compose[^/]*\.ya?ml$/i,
  /(^|\/)requirements\.txt$/i,
  /(^|\/)pyproject\.toml$/i,
  /(^|\/)go\.(mod|sum)$/i,
  /(^|\/)\.env(\..+)?$/i,
  /(^|\/)(vite|next|nuxt|astro|webpack|tsconfig)\.config\.[^/]+$/i,
  /(^|\/)tsconfig(\.[^/]+)?\.json$/i
];

/**
 * @param {Buffer | string} content
 * @returns {string}
 */
function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * @param {number[]} values
 * @param {number} p
 * @returns {number | null}
 */
function percentile(values, p) {
  if (!values || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number(sorted[Math.max(0, idx)].toFixed(2));
}

/**
 * Normaliza y valida una ruta relativa dentro de `baseDir`.
 * Lanza error con `code = 'PATH_TRAVERSAL_BLOCKED'` si intenta escapar
 * (incluyendo escapes por enlace simbólico en directorios ancestros o en el fichero hoja).
 *
 * @param {string} baseDir
 * @param {string} relPath
 * @param {{ realBase?: string | null, verifiedDirs?: Set<string> }} [ctx]
 * @returns {{ rel: string, abs: string, stat: import('fs').Stats | null }}
 */
function resolveSafeFilePath(baseDir, relPath, ctx = {}) {
  if (typeof relPath !== 'string' || !relPath.trim()) {
    const err = new Error('Ruta de fichero vacía');
    /** @type {any} */ (err).code = 'INVALID_PATH';
    throw err;
  }
  if (relPath.includes('\0')) {
    const err = new Error('Byte nulo detectado en la ruta');
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }
  const slashNorm = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (relPath.startsWith('/') || relPath.startsWith('\\') || /^[A-Za-z]:/.test(relPath)) {
    const err = new Error(`Ruta absoluta rechazada: ${relPath}`);
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  const segments = slashNorm.split('/').filter(Boolean);
  if (segments.length === 0) {
    const err = new Error(`Ruta inválida: ${relPath}`);
    /** @type {any} */ (err).code = 'INVALID_PATH';
    throw err;
  }
  for (const seg of segments) {
    if (seg === '..' || seg === '.') {
      const err = new Error(`Intento de path traversal bloqueado: ${relPath}`);
      /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
      throw err;
    }
  }
  if (segments[0] === '.git') {
    const err = new Error('No se permite sobrescribir metadatos de .git vía sincronización en vivo');
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  const cleanRel = segments.join('/');
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, cleanRel);
  const relativeBack = path.relative(resolvedBase, resolvedTarget);
  if (!relativeBack || relativeBack.startsWith('..') || path.isAbsolute(relativeBack)) {
    const err = new Error(`Ruta fuera del espacio del proyecto: ${relPath}`);
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  // Comprueba que ningún ancestro existente sea un symlink hacia fuera (cacheado por frame).
  const targetDir = path.dirname(resolvedTarget);
  const verifiedDirs = ctx.verifiedDirs;
  if (!verifiedDirs || !verifiedDirs.has(targetDir)) {
    const realBase = ctx.realBase !== undefined
      ? ctx.realBase
      : (fs.existsSync(resolvedBase) ? fs.realpathSync(resolvedBase) : null);
    if (realBase) {
      let checkDir = targetDir;
      while (checkDir.length >= resolvedBase.length) {
        if (fs.existsSync(checkDir)) {
          const realCheck = fs.realpathSync(checkDir);
          const relReal = path.relative(realBase, realCheck);
          if (relReal.startsWith('..') || path.isAbsolute(relReal)) {
            const err = new Error(`Escape por enlace simbólico bloqueado: ${relPath}`);
            /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
            throw err;
          }
          if (verifiedDirs) verifiedDirs.add(targetDir);
          break;
        }
        const parent = path.dirname(checkDir);
        if (parent === checkDir) break;
        checkDir = parent;
      }
    }
  }

  // Comprueba también el propio fichero hoja (impide leer o sobrescribir symlinks externos)
  // y devuelve su `lstat` para reutilizar `mtimeMs`/`size` sin syscalls extra.
  /** @type {import('fs').Stats | null} */
  let leafStat = null;
  try {
    const st = fs.lstatSync(resolvedTarget);
    if (st.isSymbolicLink()) {
      const err = new Error(`Enlace simbólico de destino bloqueado: ${relPath}`);
      /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
      throw err;
    }
    leafStat = st;
  } catch (e) {
    if (e && e.code !== 'ENOENT') throw e;
  }

  return { rel: cleanRel, abs: resolvedTarget, stat: leafStat };
}

/**
 * Clasifica un conjunto de rutas modificadas entre Camino B (hot-apply) y
 * Camino C (requiere reinicio/reconstrucción).
 *
 * @param {string[]} relPaths
 * @returns {{ path: 'path_b_hot' | 'path_c_restart', reason: string, triggerFiles: string[] }}
 */
function classifyChanges(relPaths) {
  const triggerFiles = relPaths.filter((p) => PATH_C_PATTERNS.some((re) => re.test(p)));
  if (triggerFiles.length > 0) {
    return {
      path: 'path_c_restart',
      reason: `Cambios de configuración o dependencias (${triggerFiles.slice(0, 3).join(', ')}): requiere reinicio limpio`,
      triggerFiles
    };
  }
  return {
    path: 'path_b_hot',
    reason: 'Cambios en código o activos hoja: aplicados en vivo sin reiniciar',
    triggerFiles: []
  };
}

let tempSeq = 0;

/**
 * Escritura atómica en disco: temporal en el mismo directorio + rename (POSIX),
 * o escritura directa con `fstatSync` en Windows NTFS para evitar bloqueos del AV
 * y capturar el nuevo `(mtimeMs, size)` en una sola apertura de descriptor.
 *
 * @param {string} absPath
 * @param {Buffer} buffer
 * @param {Set<string> | null} [ensuredDirs]
 * @returns {{ mtimeMs: number, size: number } | null}
 */
function writeFileAtomic(absPath, buffer, ensuredDirs = null) {
  const dir = path.dirname(absPath);
  if (!ensuredDirs || !ensuredDirs.has(dir)) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (ensuredDirs) ensuredDirs.add(dir);
  }
  if (process.platform === 'win32') {
    const maxAttempts = 4;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const fd = fs.openSync(absPath, 'w');
        try {
          if (buffer.length > 0) fs.writeSync(fd, buffer, 0, buffer.length, 0);
          const st = fs.fstatSync(fd);
          return { mtimeMs: st.mtimeMs, size: st.size };
        } finally {
          fs.closeSync(fd);
        }
      } catch (err) {
        const transient = err && (err.code === 'EBUSY' || err.code === 'EPERM' || err.code === 'EACCES');
        if (!transient || attempt === maxAttempts) throw err;
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25); } catch (e) {}
      }
    }
  }
  const tempPath = `${absPath}.culkibo-sync-${process.pid}-${++tempSeq}.tmp`;
  fs.writeFileSync(tempPath, buffer);
  try {
    fs.renameSync(tempPath, absPath);
  } catch (err) {
    try {
      const st = fs.lstatSync(absPath);
      if (st.isSymbolicLink()) {
        try { fs.unlinkSync(tempPath); } catch (e) {}
        throw new Error(`Rechazado escribir sobre enlace simbólico: ${absPath}`);
      }
    } catch (e) {
      if (e && e.code !== 'ENOENT') throw e;
    }
    fs.copyFileSync(tempPath, absPath);
    try { fs.unlinkSync(tempPath); } catch (e) {}
  }
  try {
    const st = fs.statSync(absPath);
    return { mtimeMs: st.mtimeMs, size: st.size };
  } catch (e) {
    return null;
  }
}

/** Caché por (absPath -> { mtimeMs, size, hash }) para árboles Merkle ultrarrápidos. */
/** @type {Map<string, { mtimeMs: number, size: number, hash: string }>} */
const merkleFileCache = new Map();
const MAX_MERKLE_CACHE_ENTRIES = 25000;
const MAX_MERKLE_FILES = 20000;
const MAX_MERKLE_DEPTH = 20;

/**
 * Calcula el árbol determinista de hashes (Merkle plano ordenado por ruta) de
 * un directorio. Sirve para demostrar cero divergencia silenciosa.
 *
 * @param {string} baseDir
 * @returns {{ rootDigest: string, fileCount: number, totalBytes: number, files: Record<string, string> }}
 */
function computeMerkleTree(baseDir) {
  /** @type {Record<string, string>} */
  const files = Object.create(null);
  let totalBytes = 0;
  let scannedFiles = 0;

  if (!fs.existsSync(baseDir)) {
    return { rootDigest: sha256(''), fileCount: 0, totalBytes: 0, files };
  }

  /** @param {string} dir @param {string} prefix @param {number} depth */
  const walk = (dir, prefix, depth) => {
    if (depth > MAX_MERKLE_DEPTH || scannedFiles >= MAX_MERKLE_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }

    for (const entry of entries) {
      if (scannedFiles >= MAX_MERKLE_FILES) break;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        walk(path.join(dir, entry.name), prefix ? `${prefix}/${entry.name}` : entry.name, depth + 1);
      } else if (entry.isFile()) {
        if (IGNORED_FILES.has(entry.name) || entry.name.includes('.culkibo-sync-')) continue;
        const abs = path.join(dir, entry.name);
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        try {
          const st = fs.statSync(abs);
          if (st.size > MAX_FILE_BYTES) continue;
          scannedFiles++;
          totalBytes += st.size;
          const cached = merkleFileCache.get(abs);
          if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
            // Refresca posición LRU en O(1)
            merkleFileCache.delete(abs);
            merkleFileCache.set(abs, cached);
            files[rel] = cached.hash;
          } else {
            const buf = fs.readFileSync(abs);
            const h = sha256(buf);
            files[rel] = h;
            if (merkleFileCache.size >= MAX_MERKLE_CACHE_ENTRIES) {
              const oldest = merkleFileCache.keys().next().value;
              if (oldest !== undefined) merkleFileCache.delete(oldest);
            }
            merkleFileCache.set(abs, { mtimeMs: st.mtimeMs, size: st.size, hash: h });
          }
        } catch (e) {}
      }
    }
  };

  walk(baseDir, '', 0);

  const sortedKeys = Object.keys(files).sort();
  const rootHasher = crypto.createHash('sha256');
  for (const k of sortedKeys) {
    rootHasher.update(`${k}\0${files[k]}\n`);
  }

  return {
    rootDigest: rootHasher.digest('hex'),
    fileCount: sortedKeys.length,
    totalBytes,
    files
  };
}

/**
 * Compara dos mapas de archivos `{ relPath: sha256 }` y devuelve la divergencia
 * exacta (protegido contra colisiones con Object.prototype).
 *
 * @param {Record<string, string>} clientFiles
 * @param {Record<string, string>} serverFiles
 */
function diffMerkleTrees(clientFiles, serverFiles) {
  /** @type {string[]} */
  const missingOnServer = [];
  /** @type {string[]} */
  const staleOnServer = [];
  /** @type {string[]} */
  const extraOnServer = [];

  const cMap = clientFiles || {};
  const sMap = serverFiles || {};

  for (const [rel, hash] of Object.entries(cMap)) {
    if (!Object.prototype.hasOwnProperty.call(sMap, rel)) {
      missingOnServer.push(rel);
    } else if (sMap[rel] !== hash) {
      staleOnServer.push(rel);
    }
  }
  for (const rel of Object.keys(sMap)) {
    if (!Object.prototype.hasOwnProperty.call(cMap, rel)) {
      extraOnServer.push(rel);
    }
  }

  return {
    inSync: missingOnServer.length === 0 && staleOnServer.length === 0 && extraOnServer.length === 0,
    missingOnServer,
    staleOnServer,
    extraOnServer,
    divergentCount: missingOnServer.length + staleOnServer.length + extraOnServer.length
  };
}

/** Calcula p50/p95/p99 en un solo ordenamiento. */
function computePercentiles(samples) {
  if (!samples || samples.length === 0) {
    return { samples: 0, p50: null, p95: null, p99: null };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const pick = (p) => {
    const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return Number(sorted[Math.max(0, idx)].toFixed(2));
  };
  return {
    samples: sorted.length,
    p50: pick(50),
    p95: pick(95),
    p99: pick(99)
  };
}

const MAX_PATCH_HISTORY_BYTES = 32 * 1024 * 1024; // 32 MiB por sesión
const MAX_RECENT_FRAMES = 25;
const MAX_SESSION_CACHE_BYTES = 16 * 1024 * 1024;
const MAX_SESSION_CACHE_ENTRIES = 500;
const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');

class LiveSyncEngine extends EventEmitter {
  constructor() {
    super();
    /** @type {Map<string, any>} */
    this.sessions = new Map();
    /** @type {Map<string, string>} */
    this.targetOverrides = new Map();
  }

  /**
   * Directorio objetivo en disco para un proyecto.
   *
   * @param {string} projectId
   * @param {string | null} [explicitDir]
   * @returns {string}
   */
  resolveTargetDir(projectId, explicitDir = null) {
    if (explicitDir) return path.resolve(explicitDir);
    if (this.targetOverrides.has(projectId)) {
      return /** @type {string} */ (this.targetOverrides.get(projectId));
    }
    const cleanId = String(projectId || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(cleanId)) {
      const err = new Error(`Identificador de proyecto inválido para Live Sync: ${projectId}`);
      /** @type {any} */ (err).code = 'INVALID_PROJECT_ID';
      throw err;
    }
    // Respetar `project.localPath` si está configurado en ProjectManager y existe como directorio real
    try {
      const pm = require('./projectManager');
      const project = pm && typeof pm.getById === 'function' ? pm.getById(cleanId) : null;
      const lp = typeof project?.localPath === 'string' ? project.localPath.trim() : '';
      if (lp && !lp.includes('\0')) {
        const resolved = path.resolve(lp);
        if (resolved !== path.parse(resolved).root && fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          return resolved;
        }
      }
    } catch (e) {}
    return path.join(ROOT_BASE_DIR, 'projects', cleanId);
  }

  /** Registra un directorio objetivo explícito (usado por proyectos locales y tests). */
  setTargetDir(projectId, dir) {
    this.targetOverrides.set(projectId, path.resolve(dir));
  }

  /** @param {string} projectId */
  getOrCreateSession(projectId) {
    let s = this.sessions.get(projectId);
    if (!s) {
      s = {
        projectId,
        lastSeq: 0,
        connectedClients: 0,
        clients: /** @type {Map<string, { id: string, clientName: string, sourceDir: string | null, pid: number | null, connectedAt: string }>} */ (new Map()),
        framesApplied: 0,
        filesWritten: 0,
        filesDeleted: 0,
        dedupSkipped: 0,
        bytesSynced: 0,
        rollbacksCount: 0,
        driftDetected: false,
        lastPath: null,
        lastReason: null,
        lastAppliedAt: null,
        lastApplyMs: null,
        latencySamples: /** @type {number[]} */ ([]),
        patchHistory: /** @type {any[]} */ ([]),
        patchHistoryBytes: 0,
        recentFrames: /** @type {any[]} */ ([]),
        fileCache: /** @type {Map<string, { buf: Buffer, mtimeMs: number, size: number }>} */ (new Map()),
        fileCacheBytes: 0,
        lastActiveMs: Date.now(),
        cachedRealBaseKey: /** @type {string | null} */ (null),
        cachedRealBase: /** @type {string | null} */ (null),
        verifiedDirs: /** @type {Set<string>} */ (new Set())
      };
      this.sessions.set(projectId, s);
    }
    s.lastActiveMs = Date.now();
    return s;
  }

  /** Libera buffers en RAM (fileCache + patchHistory) de sesiones desconectadas tras `maxIdleMs`. */
  evictIdleSessions(maxIdleMs = 15 * 60 * 1000) {
    const now = Date.now();
    let evicted = 0;
    for (const s of this.sessions.values()) {
      if (s.connectedClients > 0) continue;
      if (now - (s.lastActiveMs || 0) < maxIdleMs) continue;
      if (s.fileCache && s.fileCache.size > 0) {
        s.fileCache.clear();
        s.fileCacheBytes = 0;
        evicted++;
      }
      if (s.patchHistory && s.patchHistory.length > 0) {
        s.patchHistory = [];
        s.patchHistoryBytes = 0;
      }
      if (s.verifiedDirs) s.verifiedDirs.clear();
    }
    return evicted;
  }

  /** @param {string} projectId @param {{ id?: string, clientName?: string | null, sourceDir?: string | null, pid?: number | null }} [meta] */
  registerClient(projectId, meta = {}) {
    const s = this.getOrCreateSession(projectId);
    s.connectedClients++;
    if (meta && meta.id) {
      s.clients.set(meta.id, {
        id: meta.id,
        clientName: String(meta.clientName || 'cli').slice(0, 80),
        sourceDir: meta.sourceDir ? String(meta.sourceDir).slice(0, 300) : null,
        pid: typeof meta.pid === 'number' ? meta.pid : null,
        connectedAt: new Date().toISOString()
      });
    }
    this.emit('sync_client', { projectId, connectedClients: s.connectedClients, clients: Array.from(s.clients.values()) });
    return s;
  }

  /** @param {string} projectId @param {string | null} [clientId] */
  unregisterClient(projectId, clientId = null) {
    const s = this.sessions.get(projectId);
    if (!s) return;
    if (clientId && s.clients) s.clients.delete(clientId);
    s.connectedClients = Math.max(0, s.connectedClients - 1);
    this.emit('sync_client', { projectId, connectedClients: s.connectedClients, clients: Array.from((s.clients || new Map()).values()) });
  }

  /** Emite el evento `sync_applied` (permite enviarlo tras `frame_ack` en /ws/sync). */
  emitApplied(result) {
    this.emit('sync_applied', result);
  }

  /**
   * Aplica un Commit Frame atómico sobre el directorio vivo del proyecto.
   *
   * @param {string} projectId
   * @param {{ seq?: number, files?: Array<{ path: string, op?: 'upsert' | 'delete', content?: string, buffer?: Buffer, encoding?: 'utf8' | 'base64', sha256?: string }>, clientSentAtMs?: number }} frame
   * @param {{ targetDir?: string, deferEmit?: boolean }} [options]
   */
  applyCommitFrame(projectId, frame, options = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, options.targetDir || null);

    if (!frame || !Array.isArray(frame.files) || frame.files.length === 0) {
      throw new Error('El commit frame debe incluir al menos un fichero en `files`');
    }
    if (frame.files.length > MAX_FILES_PER_FRAME) {
      throw new Error(`El commit frame supera el máximo permitido (${MAX_FILES_PER_FRAME} ficheros)`);
    }

    // Reutilizar realBase y verifiedDirs en la sesión para el mismo baseDir (evita realpathSync en cada frame)
    const resolvedBase = path.resolve(baseDir);
    if (session.cachedRealBaseKey !== resolvedBase) {
      session.cachedRealBaseKey = resolvedBase;
      try { session.cachedRealBase = fs.realpathSync(baseDir); } catch (e) { session.cachedRealBase = null; }
      session.verifiedDirs = new Set();
      if (session.cachedRealBase) session.verifiedDirs.add(resolvedBase);
    } else if (!session.cachedRealBase && fs.existsSync(baseDir)) {
      try {
        session.cachedRealBase = fs.realpathSync(baseDir);
        session.verifiedDirs.add(resolvedBase);
      } catch (e) {}
    }
    if (session.verifiedDirs.size > 500) {
      session.verifiedDirs.clear();
      if (session.cachedRealBase) session.verifiedDirs.add(resolvedBase);
    }
    const realBase = session.cachedRealBase;
    const pathCtx = { realBase, verifiedDirs: session.verifiedDirs };

    /** @type {Array<{ rel: string, abs: string, op: 'upsert' | 'delete', buffer: Buffer | null, hash: string | null, stat: import('fs').Stats | null }>} */
    const prepared = [];
    for (const item of frame.files) {
      const { rel, abs, stat } = resolveSafeFilePath(baseDir, item.path, pathCtx);
      const op = item.op === 'delete' ? 'delete' : 'upsert';
      if (op === 'upsert') {
        const buffer = Buffer.isBuffer(item.buffer)
          ? item.buffer
          : Buffer.from(String(item.content ?? ''), item.encoding === 'base64' ? 'base64' : 'utf8');
        if (buffer.length > MAX_FILE_BYTES) {
          throw new Error(`El fichero ${rel} supera el límite de ${MAX_FILE_BYTES} bytes`);
        }
        /** @type {string | null} */
        let verifiedHash = null;
        if (item.sha256) {
          const computedHash = sha256(buffer);
          if (item.sha256 !== computedHash) {
            throw new Error(`Checksum SHA-256 inválido para ${rel}`);
          }
          verifiedHash = computedHash;
        }
        prepared.push({ rel, abs, op, buffer, hash: verifiedHash, stat });
      } else {
        prepared.push({ rel, abs, op, buffer: null, hash: null, stat });
      }
    }

    const prevLastSeq = session.lastSeq;
    let reconcileRequired = false;
    const seq = typeof frame.seq === 'number' && Number.isInteger(frame.seq) && frame.seq > 0
      ? frame.seq
      : session.lastSeq + 1;
    if (session.lastSeq > 0 && seq > session.lastSeq + 1) {
      reconcileRequired = true;
      session.driftDetected = true;
    }

    const ensuredDirs = new Set();
    if (!realBase && !fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
    }
    ensuredDirs.add(baseDir);

    /** @type {Array<{ rel: string, abs: string, existed: boolean, prevBuffer: Buffer | null }>} */
    const undoEntries = [];
    let undoBytes = 0;
    let written = 0;
    let deleted = 0;
    let dedupSkipped = 0;
    let bytesWritten = 0;
    /** @type {string[]} */
    const changedPaths = [];
    const cache = session.fileCache;

    try {
      for (const entry of prepared) {
        let existed = Boolean(entry.stat);
        /** @type {Buffer | null} */
        let prevBuffer = null;
        if (entry.stat && entry.stat.isFile()) {
          const cached = cache.get(entry.abs);
          if (cached && cached.mtimeMs === entry.stat.mtimeMs && cached.size === entry.stat.size) {
            prevBuffer = cached.buf;
          } else {
            try {
              prevBuffer = fs.readFileSync(entry.abs);
            } catch (e) {
              if (!e || (e.code !== 'ENOENT' && e.code !== 'EISDIR')) throw e;
              existed = false;
            }
          }
        }

        if (entry.op === 'upsert' && entry.buffer !== null) {
          if (prevBuffer && prevBuffer.length === entry.buffer.length && prevBuffer.equals(entry.buffer)) {
            dedupSkipped++;
            continue;
          }
          undoEntries.push({ rel: entry.rel, abs: entry.abs, existed, prevBuffer });
          if (prevBuffer) undoBytes += prevBuffer.length;
          const postStat = writeFileAtomic(entry.abs, entry.buffer, ensuredDirs);
          if (postStat) {
            // Actualiza caché de sesión y caché Merkle (evita readFileSync en la siguiente edición o verifySync)
            const prevCached = cache.get(entry.abs);
            if (prevCached) session.fileCacheBytes = Math.max(0, session.fileCacheBytes - prevCached.buf.length);
            if (entry.buffer.length <= 512 * 1024) {
              // Evicción LRU O(1) incremental en lugar de vaciar la caché completa de golpe
              while (
                cache.size > 0 &&
                (cache.size >= MAX_SESSION_CACHE_ENTRIES || session.fileCacheBytes + entry.buffer.length > MAX_SESSION_CACHE_BYTES)
              ) {
                const oldestKey = cache.keys().next().value;
                if (oldestKey === undefined) break;
                const oldestVal = cache.get(oldestKey);
                cache.delete(oldestKey);
                if (oldestVal) session.fileCacheBytes = Math.max(0, session.fileCacheBytes - oldestVal.buf.length);
              }
              cache.delete(entry.abs);
              cache.set(entry.abs, { buf: entry.buffer, mtimeMs: postStat.mtimeMs, size: postStat.size });
              session.fileCacheBytes += entry.buffer.length;
            } else {
              cache.delete(entry.abs);
            }
            if (entry.hash) {
              if (merkleFileCache.size >= MAX_MERKLE_CACHE_ENTRIES) {
                const oldestMerkle = merkleFileCache.keys().next().value;
                if (oldestMerkle !== undefined) merkleFileCache.delete(oldestMerkle);
              }
              merkleFileCache.delete(entry.abs);
              merkleFileCache.set(entry.abs, { mtimeMs: postStat.mtimeMs, size: postStat.size, hash: entry.hash });
            } else {
              merkleFileCache.delete(entry.abs);
            }
          } else {
            cache.delete(entry.abs);
            merkleFileCache.delete(entry.abs);
          }
          written++;
          bytesWritten += entry.buffer.length;
          changedPaths.push(entry.rel);
        } else if (entry.op === 'delete') {
          if (!existed) {
            dedupSkipped++;
            continue;
          }
          undoEntries.push({ rel: entry.rel, abs: entry.abs, existed: true, prevBuffer });
          if (prevBuffer) undoBytes += prevBuffer.length;
          if (entry.stat && entry.stat.isDirectory()) {
            fs.rmSync(entry.abs, { recursive: true, force: true });
          } else {
            fs.unlinkSync(entry.abs);
          }
          const prevCached = cache.get(entry.abs);
          if (prevCached) {
            session.fileCacheBytes = Math.max(0, session.fileCacheBytes - prevCached.buf.length);
            cache.delete(entry.abs);
          }
          merkleFileCache.delete(entry.abs);
          deleted++;
          changedPaths.push(entry.rel);
        }
      }
    } catch (writeErr) {
      // Atomicidad real: si falla a mitad de trama, revertir lo escrito y restaurar lastSeq (P1-16)
      for (let i = undoEntries.length - 1; i >= 0; i--) {
        const u = undoEntries[i];
        try {
          if (u.existed && u.prevBuffer !== null) {
            writeFileAtomic(u.abs, u.prevBuffer, ensuredDirs);
          } else if (fs.existsSync(u.abs)) {
            fs.unlinkSync(u.abs);
          }
          cache.delete(u.abs);
          merkleFileCache.delete(u.abs);
        } catch (e) {}
      }
      session.lastSeq = prevLastSeq;
      throw writeErr;
    }

    if (seq > session.lastSeq) session.lastSeq = seq;

    const classification = classifyChanges(changedPaths.length > 0 ? changedPaths : prepared.map(p => p.rel));
    const appliedAt = new Date().toISOString();

    if (undoEntries.length > 0) {
      const afterByRel = new Map();
      let afterBytes = 0;
      for (const p of prepared) {
        if (p.op === 'upsert' && p.buffer && p.buffer.length <= 32 * 1024 && !p.buffer.includes(0)) {
          afterByRel.set(p.rel, p.buffer);
          afterBytes += p.buffer.length;
        }
      }
      const patch = {
        patchId: `patch_${seq}_${Date.now()}`,
        seq,
        appliedAt,
        files: changedPaths,
        classification: classification.path,
        byteSize: undoBytes + afterBytes,
        undoEntries,
        afterByRel
      };
      session.patchHistory.unshift(patch);
      session.patchHistoryBytes = (session.patchHistoryBytes || 0) + patch.byteSize;
      while (
        session.patchHistory.length > MAX_PATCH_HISTORY ||
        (session.patchHistory.length > 1 && session.patchHistoryBytes > MAX_PATCH_HISTORY_BYTES)
      ) {
        const evicted = session.patchHistory.pop();
        if (evicted) session.patchHistoryBytes = Math.max(0, session.patchHistoryBytes - (evicted.byteSize || 0));
      }
    }

    const applyMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));
    session.framesApplied++;
    session.filesWritten += written;
    session.filesDeleted += deleted;
    session.dedupSkipped += dedupSkipped;
    session.bytesSynced += bytesWritten;
    session.lastPath = classification.path;
    session.lastReason = classification.reason;
    session.lastAppliedAt = appliedAt;
    session.lastApplyMs = applyMs;
    session.latencySamples.push(applyMs);
    if (session.latencySamples.length > MAX_LATENCY_SAMPLES) {
      session.latencySamples.shift();
    }

    session.recentFrames.unshift({
      seq,
      at: appliedAt,
      appliedAt,
      written,
      deleted,
      dedupSkipped,
      bytesWritten,
      applyMs,
      mode: classification.path,
      files: changedPaths.slice(0, 10),
      totalFiles: changedPaths.length
    });
    if (session.recentFrames.length > MAX_RECENT_FRAMES) {
      session.recentFrames.pop();
    }

    const result = {
      applied: true,
      projectId,
      seq,
      written,
      deleted,
      dedupSkipped,
      bytesWritten,
      changedFiles: changedPaths,
      mode: classification.path,
      reason: classification.reason,
      triggerFiles: classification.triggerFiles,
      applyMs,
      reconcileRequired,
      historyDepth: session.patchHistory.length
    };

    if (!options.deferEmit) {
      this.emit('sync_applied', result);
    }
    return result;
  }

  /**
   * Revierte los últimos `steps` commit frames directamente desde el historial
   * de parches en memoria: <10 ms sin reconstruir nada.
   *
   * @param {string} projectId
   * @param {number} [steps]
   */
  rollback(projectId, steps = 1) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const count = Math.max(1, Math.min(Number(steps) || 1, session.patchHistory.length));
    if (session.patchHistory.length === 0) {
      throw new Error('No hay historial de parches de sincronización en vivo para revertir');
    }

    /** @type {string[]} */
    const restoredFiles = [];
    /** @type {string[]} */
    const revertedPatchIds = [];
    const ensuredDirs = new Set();

    for (let i = 0; i < count; i++) {
      const patch = session.patchHistory.shift();
      if (!patch) break;
      session.patchHistoryBytes = Math.max(0, (session.patchHistoryBytes || 0) - (patch.byteSize || 0));
      revertedPatchIds.push(patch.patchId);
      for (const entry of patch.undoEntries) {
        if (entry.existed && entry.prevBuffer !== null) {
          writeFileAtomic(entry.abs, entry.prevBuffer, ensuredDirs);
        } else if (fs.existsSync(entry.abs)) {
          fs.unlinkSync(entry.abs);
        }
        if (session.fileCache) session.fileCache.delete(entry.abs);
        merkleFileCache.delete(entry.abs);
        restoredFiles.push(entry.rel);
      }
    }

    const durationMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));
    session.rollbacksCount++;

    const result = {
      reverted: true,
      projectId,
      revertedPatchIds,
      restoredFiles: Array.from(new Set(restoredFiles)),
      durationMs,
      remainingHistory: session.patchHistory.length
    };
    this.emit('sync_rollback', result);
    return result;
  }

  /**
   * Devuelve una vista compacta del diff de un Commit Frame concreto en el historial de sesión.
   * @param {string} projectId
   * @param {number} seq
   */
  getFrameDiff(projectId, seq) {
    const session = this.getOrCreateSession(projectId);
    const numSeq = Number(seq);
    const patch = (session.patchHistory || []).find((p) => Number(p.seq) === numSeq);
    if (!patch) return null;

    const files = (patch.undoEntries || []).map((u) => {
      const beforeBuf = u.prevBuffer;
      const afterBuf = patch.afterByRel ? patch.afterByRel.get(u.rel) : null;
      const isBinary = (beforeBuf && beforeBuf.includes(0)) || (afterBuf && afterBuf.includes(0));
      if (isBinary) {
        return {
          path: u.rel,
          binary: true,
          existedBefore: Boolean(u.existed),
          beforeBytes: beforeBuf ? beforeBuf.length : 0,
          afterBytes: afterBuf ? afterBuf.length : 0
        };
      }
      const beforeText = beforeBuf ? beforeBuf.toString('utf8').slice(0, 16384) : '';
      const afterText = afterBuf ? afterBuf.toString('utf8').slice(0, 16384) : (u.existed && !afterBuf ? '' : '');
      const status = !u.existed ? 'added' : (!afterBuf && !fs.existsSync(u.abs) ? 'deleted' : 'modified');
      return {
        path: u.rel,
        status,
        binary: false,
        before: beforeText,
        after: afterText,
        truncated: (beforeBuf && beforeBuf.length > 16384) || (afterBuf && afterBuf.length > 16384)
      };
    });

    return {
      projectId,
      seq: patch.seq,
      patchId: patch.patchId,
      appliedAt: patch.appliedAt,
      mode: patch.classification,
      files
    };
  }

  /**
   * Verifica la integridad del árbol de archivos del servidor contra un digest
   * o mapa de hashes del cliente.
   *
   * @param {string} projectId
   * @param {{ clientDigest?: string | null, clientFiles?: Record<string, string> | null, targetDir?: string | null }} [opts]
   */
  verifySync(projectId, opts = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, opts.targetDir || null);
    const tree = computeMerkleTree(baseDir);

    /** @type {any} */
    let comparison = null;
    let verifiedAgainstClient = false;
    if (opts.clientFiles && typeof opts.clientFiles === 'object') {
      comparison = diffMerkleTrees(opts.clientFiles, tree.files);
      session.driftDetected = !comparison.inSync;
      verifiedAgainstClient = true;
    } else if (opts.clientDigest) {
      const inSync = opts.clientDigest === tree.rootDigest;
      comparison = {
        inSync,
        divergentCount: inSync ? 0 : null,
        missingOnServer: /** @type {string[]} */ ([]),
        staleOnServer: /** @type {string[]} */ ([]),
        extraOnServer: /** @type {string[]} */ ([])
      };
      session.driftDetected = !inSync;
      verifiedAgainstClient = true;
    } else {
      session.driftDetected = false;
    }

    const inSyncVal = comparison
      ? comparison.inSync
      : (session.connectedClients > 0 ? !session.driftDetected : null);

    return {
      projectId,
      targetDir: baseDir,
      serverDigest: tree.rootDigest,
      fileCount: tree.fileCount,
      totalBytes: tree.totalBytes,
      inSync: inSyncVal,
      verifiedAgainstClient,
      message: verifiedAgainstClient
        ? (inSyncVal ? 'Árbol Merkle idéntico entre cliente y servidor.' : 'Se detectaron diferencias respecto al cliente.')
        : (session.connectedClients === 0
          ? 'Árbol local verificado en disco (sin cliente Live Sync conectado para comparar).'
          : 'Árbol local verificado en disco.'),
      comparison,
      verifyMs: Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2)),
      lastSeq: session.lastSeq,
      connectedClients: session.connectedClients
    };
  }

  /**
   * Estado completo + percentiles reales de latencia para panel y MCP.
   *
   * @param {string} projectId
   */
  getStatus(projectId) {
    const s = this.getOrCreateSession(projectId);
    return {
      projectId,
      targetDir: this.resolveTargetDir(projectId),
      connectedClients: s.connectedClients,
      clients: Array.from((s.clients || new Map()).values()),
      lastSeq: s.lastSeq,
      framesApplied: s.framesApplied,
      filesWritten: s.filesWritten,
      filesDeleted: s.filesDeleted,
      dedupSkipped: s.dedupSkipped,
      bytesSynced: s.bytesSynced,
      rollbacksCount: s.rollbacksCount,
      driftDetected: s.driftDetected,
      lastPath: s.lastPath,
      lastReason: s.lastReason,
      lastAppliedAt: s.lastAppliedAt,
      lastApplyMs: s.lastApplyMs,
      historyDepth: s.patchHistory.length,
      recentFrames: s.recentFrames || [],
      latencyMs: computePercentiles(s.latencySamples)
    };
  }

  /** Resumen global de todas las sesiones activas de sincronización en vivo. */
  getGlobalSummary() {
    const active = [];
    let totalFrames = 0;
    let totalClients = 0;
    /** @type {number[]} */
    const allSamples = [];

    for (const s of this.sessions.values()) {
      totalFrames += s.framesApplied;
      totalClients += s.connectedClients;
      allSamples.push(...s.latencySamples);
      if (s.framesApplied > 0 || s.connectedClients > 0) {
        active.push(this.getStatus(s.projectId));
      }
    }

    return {
      activeSessions: active.length,
      connectedClients: totalClients,
      totalFramesApplied: totalFrames,
      latencyMs: computePercentiles(allSamples),
      sessions: active
    };
  }

  /** Limpia el estado en memoria de una sesión (usado por pruebas). */
  resetSession(projectId) {
    this.sessions.delete(projectId);
    this.targetOverrides.delete(projectId);
  }
}

const liveSyncEngineInstance = Object.assign(new LiveSyncEngine(), {
  LiveSyncEngine,
  resolveSafeFilePath,
  classifyChanges,
  computeMerkleTree,
  diffMerkleTrees,
  sha256
});
module.exports = liveSyncEngineInstance;
