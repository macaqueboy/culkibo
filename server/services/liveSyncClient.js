const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const WebSocket = require('ws');
const {
  computeMerkleTree,
  diffMerkleTrees,
  sha256,
  sha256FileSync,
  FRAME_MAGIC_RAW,
  FRAME_MAGIC_BROTLI,
  FRAME_MAGIC_GZIP,
  MAX_CHUNKED_FILE_BYTES
} = require('./liveSyncEngine');

/**
 * Cliente real de sincronización en vivo (máquina local -> daemon de Culkibo).
 *
 * Acumula cambios de disco en una ventana corta de quiescencia (`quiescenceMs`)
 * para enviarlos como un único Commit Frame atómico sobre un WebSocket
 * persistente autenticado, con compresión adaptativa (Brotli/Gzip),
 * encabezados optimistas `baseSha256`, verificación Merkle delta y auto-reconexión.
 */

const IGNORED_SEGMENT_RE = /(^|[\\/])(\.git|node_modules|\.next|\.nuxt|\.turbo|\.svelte-kit|\.output|\.astro|\.cache|\.culkibo|dist|build|coverage|__pycache__|\.venv|venv|target|vendor)([\\/]|$)/;
const EDITOR_SWAP_RE = /(^|[\\/])(\.#[^\\/]+|#[^\\/]+#|~\$[^\\/]+|\.DS_Store|Thumbs\.db|4913)$|(\.(swp|swo|swx|tmp|bak|orig)|~)$/i;
const INCOMPRESSIBLE_EXT_RE = /\.(png|jpe?g|webp|gif|avif|ico|woff2?|mp4|webm|mp3|ogg|zip|gz|br|zst|7z|rar|pdf|wasm)$/i;
const MAX_CLIENT_FILE_BYTES = 10 * 1024 * 1024;
const CLIENT_CHUNK_PART_BYTES = 1024 * 1024; // 1 MiB por trozo para archivos >10 MiB
const CHUNK_MAX_FILES = 250;
const CHUNK_MAX_BYTES = 8 * 1024 * 1024;
const COMPRESSION_MIN_BYTES = 512;
const COMPRESSION_MAX_RATIO = 0.85; // Debe ahorrar >= 15% respecto a trama cruda 0x01
const MAX_STAT_CACHE_ENTRIES = 10000;
const FRESH_TREE_MAX_AGE_MS = 2000;

/** @type {typeof import('zlib') | null} */
let _zlib = null;
function getZlib() {
  if (!_zlib) _zlib = require('zlib');
  return _zlib;
}

/**
 * Compila un patrón glob simple de `.culkiboignore` (sin dependencias externas).
 * @param {string} rawLine
 * @returns {{ negated: boolean, dirOnly: boolean, anchored: boolean, regex: RegExp } | null}
 */
function compileIgnoreRule(rawLine) {
  let line = rawLine.trim();
  if (!line || line.startsWith('#')) return null;
  let negated = false;
  if (line.startsWith('!')) {
    negated = true;
    line = line.slice(1).trim();
    if (!line) return null;
  }
  const dirOnly = line.endsWith('/');
  if (dirOnly) line = line.replace(/\/+$/, '');
  const anchored = line.startsWith('/') || line.includes('/');
  if (line.startsWith('/')) line = line.slice(1);
  if (!line) return null;

  // Escapar metacaracteres regex excepto *, ? y /
  let reStr = '';
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '*') {
      if (line[i + 1] === '*') {
        if (line[i + 2] === '/') {
          reStr += '(?:.*/)?';
          i += 2;
        } else {
          reStr += '.*';
          i += 1;
        }
      } else {
        reStr += '[^/]*';
      }
    } else if (ch === '?') {
      reStr += '[^/]';
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      reStr += `\\${ch}`;
    } else {
      reStr += ch;
    }
  }

  const pattern = anchored
    ? (dirOnly ? `^${reStr}/.*$` : `^${reStr}(?:/.*)?$`)
    : (dirOnly ? `(?:^|/)${reStr}/.*$` : `(?:^|/)${reStr}(?:/.*)?$`);

  return { negated, dirOnly, anchored, regex: new RegExp(pattern) };
}

/**
 * Lee y parsea `.culkiboignore` si existe en `sourceDir` (0 impacto si no existe).
 * @param {string} sourceDir
 */
function loadCulkiboIgnore(sourceDir) {
  const ignorePath = path.join(sourceDir, '.culkiboignore');
  try {
    const st = fs.lstatSync(ignorePath);
    if (!st.isFile() || st.isSymbolicLink() || st.size > 256 * 1024) return [];
    const content = fs.readFileSync(ignorePath, 'utf8');
    /** @type {Array<{ negated: boolean, dirOnly: boolean, anchored: boolean, regex: RegExp }>} */
    const rules = [];
    for (const line of content.split(/\r?\n/)) {
      const compiled = compileIgnoreRule(line);
      if (compiled) rules.push(compiled);
    }
    return rules;
  } catch (e) {
    return [];
  }
}

/**
 * Detecta si un bloque de ficheros es mayoritariamente binario/incompresible (>70% bytes).
 * @param {Array<{ path: string, op?: string, buf?: Buffer }>} entries
 */
function isMostlyIncompressible(entries) {
  let totalBytes = 0;
  let incompressibleBytes = 0;
  for (const e of entries) {
    if (e.op === 'delete' || !e.buf || e.buf.length === 0) continue;
    totalBytes += e.buf.length;
    if (INCOMPRESSIBLE_EXT_RE.test(e.path)) {
      incompressibleBytes += e.buf.length;
      continue;
    }
    const probeLen = Math.min(512, e.buf.length);
    if (e.buf.subarray(0, probeLen).includes(0)) {
      incompressibleBytes += e.buf.length;
    }
  }
  return totalBytes > 0 && (incompressibleBytes / totalBytes) > 0.7;
}

class LiveSyncClient extends EventEmitter {
  /**
   * @param {{
   *   projectId: string,
   *   sourceDir: string,
   *   wsUrl?: string,
   *   serverUrl?: string,
   *   token?: string | null,
   *   ticket?: string | null,
   *   quiescenceMs?: number,
   *   autoWatch?: boolean,
   *   autoReconnect?: boolean,
   *   clientName?: string,
   *   targetDir?: string | null,
   *   compression?: 'auto' | 'br' | 'gzip' | 'none'
   * }} options
   */
  constructor(options) {
    super();
    this.projectId = options.projectId;
    this.sourceDir = path.resolve(options.sourceDir);
    this.wsUrl = options.wsUrl || options.serverUrl || 'ws://127.0.0.1:3030/ws/sync';
    this.token = options.token || null;
    this.ticket = /** @type {any} */ (options).ticket || null;
    this.quiescenceMs = typeof options.quiescenceMs === 'number' ? options.quiescenceMs : 12;
    this.autoWatch = options.autoWatch !== false;
    this.autoReconnect = options.autoReconnect !== false;
    this.clientName = options.clientName || os.hostname();
    this.targetDir = options.targetDir || null;
    this.compression = options.compression === 'none' || options.compression === 'br' || options.compression === 'gzip'
      ? options.compression
      : 'auto';

    /** @type {any} */
    this.ws = null;
    /** @type {any} */
    this.watcher = null;
    /** @type {any} */
    this.nativeWatcher = null;
    this.seq = 0;
    /** @type {string | null} */
    this.clientId = null;
    this.connected = false;
    this.closed = false;
    this._reconnectAttempt = 0;
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._reconnectTimer = null;
    this._reconciling = false;
    /** @type {Array<{ resolve: (v: any) => void, reject: (e: any) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._verifyWaiters = [];
    /** @type {Array<{ resolve: (v: any) => void, reject: (e: any) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._fileHistoryWaiters = [];
    /** @type {Array<{ resolve: (v: any) => void, reject: (e: any) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._rollbackFileWaiters = [];
    /** @type {Map<string, { resolve: (v: any) => void, reject: (e: any) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._chunkWaiters = new Map();
    this._chunkReqSeq = 0;
    this.chunkedUploadSupported = false;

    /** @type {Map<string, 'upsert' | 'delete'>} */
    this.pending = new Map();
    /** @type {Map<string, string>} */
    this.lastSentHashes = new Map();
    /** Caché de stat `(mtimeMs, ctimeMs, size, sha256)` para evitar lecturas duplicadas en Windows ReadDirectoryChangesW. */
    /** @type {Map<string, { mtimeMs: number, ctimeMs: number, size: number, sha256: string }>} */
    this._statCache = new Map();
    /** Reglas compiladas de `.culkiboignore` (vacío si no existe). */
    this._ignoreRules = loadCulkiboIgnore(this.sourceDir);
    /** @type {any} */
    this.initialLocalTree = null;
    this.initialLocalTreeAt = 0;
    this._initialTreeHasFiles = false;
    this.initialInSync = false;
    this.binaryFramesSupported = false;
    /** @type {string[]} */
    this.supportedCodecs = [];
    this.wireStats = {
      rawBytes: 0,
      wireBytes: 0,
      savedBytes: 0,
      compressedFrames: 0,
      rawFrames: 0
    };
    /** @type {ReturnType<typeof setTimeout> | null} */
    this.coalesceTimer = null;
    /** @type {ReturnType<typeof setImmediate> | null} */
    this._imm = null;
    this.lastFlushAt = 0;
    /** @type {string | null} */
    this.lastFlushedRel = null;
    this.batchStartAt = 0;
    /** @type {ReturnType<typeof setInterval> | null} */
    this.pingTimer = null;
    this._flushing = false;
    /** @type {Promise<any> | null} */
    this._activeFlushPromise = null;
    /** @type {Map<number, { resolve: (v: any) => void, reject: (e: any) => void, sentAtNs: bigint }>} */
    this.inflight = new Map();
  }

  /** Recarga `.culkiboignore` desde disco (sin impacto si no existe). */
  reloadIgnoreRules() {
    this._ignoreRules = loadCulkiboIgnore(this.sourceDir);
    return this._ignoreRules.length;
  }

  /**
   * Comprueba si una ruta relativa debe ignorarse (reglas internas + `.culkiboignore`).
   * @param {string} relPath
   */
  isIgnored(relPath) {
    if (!relPath) return true;
    const rel = String(relPath).replace(/\\/g, '/').replace(/^\/+/, '');
    if (!rel || rel.startsWith('..') || IGNORED_SEGMENT_RE.test(rel) || EDITOR_SWAP_RE.test(rel) || rel.includes('.culkibo-sync-')) {
      return true;
    }
    if (!this._ignoreRules || this._ignoreRules.length === 0) return false;
    let ignored = false;
    for (const rule of this._ignoreRules) {
      if (rule.regex.test(rel)) {
        ignored = !rule.negated;
      }
    }
    return ignored;
  }

  /** Calcula el árbol Merkle local aplicando `.culkiboignore` sólo cuando existen reglas. */
  _computeLocalTree() {
    const tree = computeMerkleTree(this.sourceDir);
    if (!this._ignoreRules || this._ignoreRules.length === 0) return tree;
    /** @type {Record<string, string>} */
    const filtered = Object.create(null);
    const keys = Object.keys(tree.files).sort();
    const hasher = crypto.createHash('sha256');
    let fileCount = 0;
    for (const k of keys) {
      if (this.isIgnored(k)) continue;
      filtered[k] = tree.files[k];
      hasher.update(`${k}\0${filtered[k]}\n`);
      fileCount++;
    }
    return {
      rootDigest: hasher.digest('hex'),
      fileCount,
      totalBytes: tree.totalBytes,
      files: filtered
    };
  }

  /** Selecciona el códec de compresión negociado con el servidor (`br` | `gzip` | null). */
  _selectCodec() {
    if (this.compression === 'none' || !Array.isArray(this.supportedCodecs) || this.supportedCodecs.length === 0) {
      return null;
    }
    if (this.compression === 'br') {
      return this.supportedCodecs.includes('br') ? 'br' : null;
    }
    if (this.compression === 'gzip') {
      return this.supportedCodecs.includes('gzip') ? 'gzip' : null;
    }
    if (this.supportedCodecs.includes('br')) return 'br';
    if (this.supportedCodecs.includes('gzip')) return 'gzip';
    return null;
  }

  /** Conecta el WebSocket persistente, realiza handshake Merkle y arranca el watcher. */
  async start() {
    this.closed = false;
    this.reloadIgnoreRules();
    await this.connect();

    if (this.autoWatch) {
      // En Windows y macOS `fs.watch({ recursive: true })` usa directamente
      // ReadDirectoryChangesW / FSEvents sin la latencia ni la supresión por
      // granularidad de `mtimeMs` de chokidar. En Linux caemos a chokidar (carga perezosa).
      if (process.platform === 'win32' || process.platform === 'darwin') {
        this.nativeWatcher = fs.watch(this.sourceDir, { recursive: true }, (_eventType, filename) => {
          if (!filename) return;
          const rel = String(filename).split(path.sep).join('/');
          if (rel === '.culkiboignore') this.reloadIgnoreRules();
          if (this.isIgnored(rel)) return;
          // Sin fs.statSync en el camino caliente: flushNow resuelve ENOENT/EISDIR/symlink al leer.
          this._enqueueRel(rel, 'upsert');
        });
        this.nativeWatcher.on('error', (err) => this.emit('error', err));
      } else {
        const chokidar = require('chokidar');
        this.watcher = chokidar.watch(this.sourceDir, {
          ignored: (filePath) => {
            const rel = path.relative(this.sourceDir, filePath).split(path.sep).join('/');
            if (!rel) return false;
            return this.isIgnored(rel);
          },
          persistent: true,
          ignoreInitial: true,
          followSymlinks: false,
          awaitWriteFinish: false
        });

        this.watcher.on('add', (abs) => this.enqueue(abs, 'upsert'));
        this.watcher.on('change', (abs) => this.enqueue(abs, 'upsert'));
        this.watcher.on('unlink', (abs) => this.enqueue(abs, 'delete'));
        this.watcher.on('error', (err) => this.emit('error', err));

        await new Promise((resolve) => {
          this.watcher.once('ready', () => resolve(undefined));
        });
      }
    }

    return { connected: true, projectId: this.projectId, sourceDir: this.sourceDir };
  }

  connect() {
    return new Promise((resolve, reject) => {
      /** @type {Record<string, string>} */
      const headers = {};
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      const protocols = this.ticket && !this.token
        ? ['culkibo.v1', `culkibo-ticket.${this.ticket}`]
        : ['culkibo.v1'];

      const ws = new WebSocket(this.wsUrl, protocols, { headers, perMessageDeflate: false });
      this.ws = ws;
      let authFatal = false;
      /** @type {any} */ (ws)._alive = true;
      ws.on('pong', () => { /** @type {any} */ (ws)._alive = true; });
      ws.on('unexpected-response', (_req, res) => {
        if (res && (res.statusCode === 401 || res.statusCode === 403)) {
          authFatal = true;
        }
      });

      let handshakeDone = false;
      const handshakeTimer = setTimeout(() => {
        if (!handshakeDone) {
          handshakeDone = true;
          try { ws.terminate(); } catch (e) {}
          reject(new Error('Tiempo de espera agotado esperando hello_ack de sincronización en vivo'));
        }
      }, 10000);
      if (handshakeTimer.unref) handshakeTimer.unref();

      const finishConnect = (err, val) => {
        if (handshakeDone) return;
        handshakeDone = true;
        clearTimeout(handshakeTimer);
        if (err) reject(err);
        else resolve(val);
      };

      ws.on('error', (err) => {
        if (!handshakeDone) {
          finishConnect(err, null);
        } else {
          this.emit('sync_error', err);
        }
      });

      ws.once('open', () => {
        if (ws._socket && typeof ws._socket.setNoDelay === 'function') {
          ws._socket.setNoDelay(true);
        }

        const localTree = this._computeLocalTree();
        this.initialLocalTree = localTree;
        this.initialLocalTreeAt = Date.now();
        this._initialTreeHasFiles = true;
        const offeredCodecs = this.compression === 'none' ? [] : ['br', 'gzip'];
        ws.send(JSON.stringify({
          type: 'hello',
          projectId: this.projectId,
          targetDir: this.targetDir,
          clientName: this.clientName,
          sourceDir: this.sourceDir,
          pid: process.pid,
          clientDigest: localTree.rootDigest,
          fileCount: localTree.fileCount,
          protocolVersion: 2,
          codecs: offeredCodecs,
          compressionAccepted: offeredCodecs
        }));

        if (this.pingTimer) {
          clearInterval(this.pingTimer);
          this.pingTimer = null;
        }
        this.pingTimer = setInterval(() => {
          if (ws.readyState !== 1) return;
          if (/** @type {any} */ (ws)._alive === false) {
            try { ws.terminate(); } catch (e) {}
            return;
          }
          /** @type {any} */ (ws)._alive = false;
          try { ws.ping(); } catch (e) {}
        }, 15000);
        if (this.pingTimer.unref) this.pingTimer.unref();
      });

      ws.on('message', (raw) => {
        let msg;
        try {
          msg = JSON.parse(raw.toString());
        } catch (e) {
          return;
        }

        if (msg.type === 'hello_ack') {
          this.connected = true;
          this._reconnectAttempt = 0;
          this.seq = msg.lastSeq || 0;
          this.clientId = msg.clientId || null;
          this.initialInSync = Boolean(msg.inSync);
          this.binaryFramesSupported = Boolean(msg.binaryFramesSupported);
          this.chunkedUploadSupported = Boolean(msg.chunkedUploadSupported);
          const advertised = Array.isArray(msg.codecs)
            ? msg.codecs
            : (Array.isArray(msg.compressionSupported) ? msg.compressionSupported : []);
          this.supportedCodecs = advertised.map((c) => String(c).toLowerCase());
          if (this.initialInSync && this.initialLocalTree) {
            this.lastSentHashes.clear();
            for (const [k, v] of Object.entries(this.initialLocalTree.files)) {
              this.lastSentHashes.set(k, v);
            }
            this.initialLocalTree = { rootDigest: this.initialLocalTree.rootDigest, fileCount: this.initialLocalTree.fileCount, files: {} };
            this._initialTreeHasFiles = false;
          }
          this.emit('ready', msg);
          finishConnect(null, msg);
          return;
        }

        if (msg.type === 'frame_ack') {
          const waiter = this.inflight.get(msg.seq);
          if (waiter) {
            this.inflight.delete(msg.seq);
            const rttMs = Number((Number(process.hrtime.bigint() - waiter.sentAtNs) / 1e6).toFixed(2));
            waiter.resolve({ ...msg, rttMs });
          }
          this.emit('frame_ack', msg);
          if (msg.reconcileRequired && !this._reconciling) {
            this.reconcileDelta().catch((err) => this.emit('sync_error', err));
          }
          return;
        }

        if (msg.type === 'verify_ack') {
          const waiter = this._verifyWaiters.shift();
          if (waiter) {
            clearTimeout(waiter.timer);
            waiter.resolve(msg);
          }
          this.emit('verify_ack', msg);
          return;
        }

        if (msg.type === 'rollback_notice') {
          if (Array.isArray(msg.restoredFiles)) {
            for (const f of msg.restoredFiles) {
              const rel = String(f);
              this.lastSentHashes.delete(rel);
              this._statCache.delete(path.join(this.sourceDir, rel));
            }
          }
          this.emit('rollback_notice', msg);
          return;
        }

        if (msg.type === 'conflict_notice') {
          this.emit('conflict_notice', msg);
          this.emit('sync_conflict', msg);
          return;
        }

        if (msg.type === 'file_history_ack') {
          const waiter = this._fileHistoryWaiters.shift();
          if (waiter) {
            clearTimeout(waiter.timer);
            waiter.resolve(msg);
          }
          this.emit('file_history_ack', msg);
          return;
        }

        if (msg.type === 'rollback_file_ack') {
          if (Array.isArray(msg.restoredFiles)) {
            for (const f of msg.restoredFiles) {
              const rel = String(f);
              this.lastSentHashes.delete(rel);
              this._statCache.delete(path.join(this.sourceDir, rel));
            }
          } else if (msg.filePath) {
            const rel = String(msg.filePath);
            this.lastSentHashes.delete(rel);
            this._statCache.delete(path.join(this.sourceDir, rel));
          }
          const waiter = this._rollbackFileWaiters.shift();
          if (waiter) {
            clearTimeout(waiter.timer);
            waiter.resolve(msg);
          }
          this.emit('rollback_file_ack', msg);
          return;
        }

        if (msg.type === 'chunk_ack') {
          const reqId = msg.reqId ? String(msg.reqId) : null;
          if (reqId && this._chunkWaiters.has(reqId)) {
            const waiter = this._chunkWaiters.get(reqId);
            this._chunkWaiters.delete(reqId);
            if (waiter) {
              clearTimeout(waiter.timer);
              waiter.resolve(msg);
            }
          }
          this.emit('chunk_ack', msg);
          return;
        }

        if (msg.type === 'error') {
          const err = new Error(msg.error || 'Error en sincronización en vivo');
          /** @type {any} */ (err).code = msg.code || 'SYNC_ERROR';
          if (msg.reqId && this._chunkWaiters.has(String(msg.reqId))) {
            const waiter = this._chunkWaiters.get(String(msg.reqId));
            this._chunkWaiters.delete(String(msg.reqId));
            if (waiter) {
              clearTimeout(waiter.timer);
              waiter.reject(err);
            }
          } else if (msg.seq && this.inflight.has(msg.seq)) {
            const waiter = this.inflight.get(msg.seq);
            this.inflight.delete(msg.seq);
            waiter && waiter.reject(err);
          } else if (!handshakeDone) {
            finishConnect(err, null);
          } else {
            this.emit('sync_error', err);
          }
        }
      });

      ws.on('close', (code) => {
        this.connected = false;
        if (!handshakeDone) {
          finishConnect(new Error('Conexión cerrada antes de completar hello_ack'), null);
        }
        if (this.pingTimer) {
          clearInterval(this.pingTimer);
          this.pingTimer = null;
        }
        for (const [, waiter] of this.inflight) {
          waiter.reject(new Error('Conexión de sincronización cerrada'));
        }
        this.inflight.clear();
        for (const [, waiter] of this._chunkWaiters) {
          clearTimeout(waiter.timer);
          waiter.reject(new Error('Conexión de sincronización cerrada'));
        }
        this._chunkWaiters.clear();
        for (const queue of [this._verifyWaiters, this._fileHistoryWaiters, this._rollbackFileWaiters]) {
          while (queue.length) {
            const w = queue.shift();
            if (w) {
              clearTimeout(w.timer);
              w.reject(new Error('Conexión de sincronización cerrada'));
            }
          }
        }
        this.emit('close', code);
        if (code === 4001 || authFatal) {
          this.emit('auth_revoked', { code: code || 401 });
          return;
        }
        if (!this.closed && this.autoReconnect) {
          this._scheduleReconnect();
        }
      });
    });
  }

  /** Reconexión automática con backoff exponencial (500ms → 15s + jitter) y reconciliación Merkle delta al reconectar. */
  _scheduleReconnect() {
    if (this.closed || this._reconnectTimer) return;
    const baseMs = Math.min(15000, Math.round(500 * Math.pow(2, this._reconnectAttempt)));
    const jitter = 0.75 + Math.random() * 0.5;
    const delayMs = Math.max(250, Math.round(baseMs * jitter));
    this._reconnectAttempt = Math.min(this._reconnectAttempt + 1, 6);
    this.emit('reconnecting', { attempt: this._reconnectAttempt, delayMs });
    this._reconnectTimer = setTimeout(async () => {
      this._reconnectTimer = null;
      if (this.closed) return;
      try {
        await this.connect();
        this.emit('reconnected', { projectId: this.projectId });
        if (!this.initialInSync) {
          await this.reconcileDelta().catch(() => this.reconcileFull().catch(() => {}));
        }
        if (this.pending.size > 0) {
          await this.flushNow().catch(() => {});
        }
      } catch (err) {
        this.emit('sync_error', err);
        if (!this.closed && this.autoReconnect) this._scheduleReconnect();
      }
    }, delayMs);
    if (this._reconnectTimer.unref) this._reconnectTimer.unref();
  }

  /** Pide al servidor la diferencia Merkle exacta enviando sólo rutas+hashes y recibe `verify_ack`. */
  verifyWithServer(localFiles) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this._verifyWaiters.findIndex((w) => w.timer === timer);
        if (idx !== -1) this._verifyWaiters.splice(idx, 1);
        reject(new Error('Tiempo de espera agotado en verificación Merkle'));
      }, 15000);
      if (timer.unref) timer.unref();
      this._verifyWaiters.push({ resolve, reject, timer });
      this.ws.send(JSON.stringify({
        type: 'verify',
        projectId: this.projectId,
        targetDir: this.targetDir,
        clientFiles: localFiles
      }));
    });
  }

  /** Consulta al servidor el historial time-travel de un fichero vía `/ws/sync`. */
  requestFileHistory(filePath) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this._fileHistoryWaiters.findIndex((w) => w.timer === timer);
        if (idx !== -1) this._fileHistoryWaiters.splice(idx, 1);
        reject(new Error('Tiempo de espera agotado consultando historial de fichero'));
      }, 10000);
      if (timer.unref) timer.unref();
      this._fileHistoryWaiters.push({ resolve, reject, timer });
      this.ws.send(JSON.stringify({
        type: 'file_history',
        projectId: this.projectId,
        targetDir: this.targetDir,
        path: filePath
      }));
    });
  }

  /** Solicita al servidor el rollback quirúrgico de un único fichero vía `/ws/sync`. */
  requestRollbackFile(filePath, seq, opts = {}) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this._rollbackFileWaiters.findIndex((w) => w.timer === timer);
        if (idx !== -1) this._rollbackFileWaiters.splice(idx, 1);
        reject(new Error('Tiempo de espera agotado en rollback de fichero'));
      }, 10000);
      if (timer.unref) timer.unref();
      this._rollbackFileWaiters.push({ resolve, reject, timer });
      this.ws.send(JSON.stringify({
        type: 'rollback_file',
        projectId: this.projectId,
        targetDir: this.targetDir,
        path: filePath,
        seq,
        mode: opts && opts.mode === 'before' ? 'before' : 'to'
      }));
    });
  }

  /**
   * Lee un archivo con reintentos cortos ante EBUSY/EPERM transitorios de editores en Windows (sin seguir symlinks)
   * y caché de stat `(mtimeMs, ctimeMs, size, sha256)` para evitar lecturas/hashes duplicados en ráfagas dobles.
   *
   * @param {string} abs
   * @param {{ skipIfUnchangedHash?: string | null }} [opts]
   */
  async _readFileSafe(abs, opts = {}) {
    for (let attempt = 1; attempt <= 4; attempt++) {
      try {
        const st = fs.lstatSync(abs);
        if (st.isSymbolicLink()) return { kind: 'symlink' };
        if (st.isDirectory()) return { kind: 'dir' };
        if (!st.isFile()) return { kind: 'dir' };
        if (st.size > MAX_CLIENT_FILE_BYTES) {
          if (st.size <= MAX_CHUNKED_FILE_BYTES) {
            const cachedLarge = this._statCache.get(abs);
            if (
              cachedLarge &&
              cachedLarge.mtimeMs === st.mtimeMs &&
              cachedLarge.ctimeMs === st.ctimeMs &&
              cachedLarge.size === st.size &&
              opts.skipIfUnchangedHash &&
              cachedLarge.sha256 === opts.skipIfUnchangedHash
            ) {
              return { kind: 'unchanged', sha256: cachedLarge.sha256, mtimeMs: st.mtimeMs, size: st.size };
            }
            return { kind: 'chunked', size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs };
          }
          return { kind: 'too_large', size: st.size };
        }
        const cached = this._statCache.get(abs);
        if (
          cached &&
          cached.mtimeMs === st.mtimeMs &&
          cached.ctimeMs === st.ctimeMs &&
          cached.size === st.size
        ) {
          if (opts.skipIfUnchangedHash && cached.sha256 === opts.skipIfUnchangedHash) {
            return { kind: 'unchanged', sha256: cached.sha256, mtimeMs: st.mtimeMs, size: st.size };
          }
        }
        const buffer = fs.readFileSync(abs);
        const hash = sha256(buffer);
        if (this._statCache.size >= MAX_STAT_CACHE_ENTRIES && !this._statCache.has(abs)) {
          const oldest = this._statCache.keys().next().value;
          if (oldest !== undefined) this._statCache.delete(oldest);
        }
        this._statCache.delete(abs);
        this._statCache.set(abs, { mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, size: st.size, sha256: hash });
        return { kind: 'file', buffer, sha256: hash, mtimeMs: st.mtimeMs, size: st.size };
      } catch (e) {
        if (e && e.code === 'ENOENT') {
          this._statCache.delete(abs);
          return { kind: 'missing' };
        }
        if (e && (e.code === 'EBUSY' || e.code === 'EPERM' || e.code === 'EACCES') && attempt < 4) {
          await new Promise((r) => setTimeout(r, 25 * attempt));
          continue;
        }
        return { kind: 'error', error: e };
      }
    }
    return { kind: 'error' };
  }

  /** Envía un array de ficheros troceado en lotes seguros (<=250 ficheros y <=8 MiB por Commit Frame). */
  async sendChunked(files) {
    /** @type {any} */
    let lastAck = null;
    let framesSent = 0;
    /** @type {typeof files} */
    let batch = [];
    let batchBytes = 0;

    for (const f of files) {
      const fSize = f.buffer ? f.buffer.length : 0;
      if (batch.length > 0 && (batch.length >= CHUNK_MAX_FILES || batchBytes + fSize > CHUNK_MAX_BYTES)) {
        lastAck = await this.sendFrame(batch);
        framesSent++;
        batch = [];
        batchBytes = 0;
      }
      batch.push(f);
      batchBytes += fSize;
    }
    if (batch.length > 0) {
      lastAck = await this.sendFrame(batch);
      framesSent++;
    }
    return { lastAck, framesSent };
  }

  /** @param {string} absPath @param {'upsert' | 'delete'} op */
  enqueue(absPath, op) {
    const rel = path.relative(this.sourceDir, absPath).split(path.sep).join('/');
    if (rel === '.culkiboignore') this.reloadIgnoreRules();
    if (this.isIgnored(rel)) return;
    this._enqueueRel(rel, op);
  }

  /**
   * Coalescencia adaptativa en dos fases (drenaje IOCP/FSEvents vía `setImmediate`):
   * - Una edición individual sale tras el drenaje de eventos del SO (`~0.01 ms`,
   *   evitando el tick de 15.6 ms de `setTimeout` en Windows).
   * - En cuanto llegan >=2 archivos (ráfaga de agente IA), escala a `quiescenceMs`
   *   (tope 50 ms) para compactar toda la ráfaga en 1 único Commit Frame atómico.
   * @param {string} rel
   * @param {'upsert' | 'delete'} op
   */
  _enqueueRel(rel, op) {
    if (this.pending.size === 0) this.batchStartAt = Date.now();
    this.pending.set(rel, op);

    if (this.coalesceTimer) {
      clearTimeout(this.coalesceTimer);
      this.coalesceTimer = null;
    }
    if (this._imm) {
      clearImmediate(this._imm);
      this._imm = null;
    }

    const now = Date.now();
    const elapsed = now - this.batchStartAt;

    if (elapsed >= 50) {
      this._imm = setImmediate(() => {
        this._imm = null;
        this.lastFlushAt = Date.now();
        this.flushNow().catch((err) => this.emit('sync_error', err));
      });
      return;
    }

    // Fase 1: 1 archivo aislado (o nueva edición del mismo archivo) -> setImmediate (~0.01 ms)
    if (this.pending.size === 1 && (rel === this.lastFlushedRel || (now - this.lastFlushAt) > 30)) {
      this._imm = setImmediate(() => {
        this._imm = null;
        if (this.pending.size === 0) return;
        if (this.pending.size === 1) {
          this.lastFlushAt = Date.now();
          this.lastFlushedRel = rel;
          this.flushNow().catch((err) => this.emit('sync_error', err));
        } else {
          // Llegó una ráfaga multi-fichero en el mismo poll del SO -> compactar en 1 Commit Frame
          this.lastFlushedRel = null;
          this.coalesceTimer = setTimeout(() => {
            this.coalesceTimer = null;
            this.lastFlushAt = Date.now();
            this.flushNow().catch((err) => this.emit('sync_error', err));
          }, this.quiescenceMs);
        }
      });
      return;
    }

    // Fase 2: ráfaga multi-fichero -> ventana de quiescencia para 1 Commit Frame atómico
    this.lastFlushedRel = null;
    this.coalesceTimer = setTimeout(() => {
      this.coalesceTimer = null;
      this.lastFlushAt = Date.now();
      this.flushNow().catch((err) => this.emit('sync_error', err));
    }, this.quiescenceMs);
  }

  /**
   * Recorre recursivamente un subdirectorio relativo (sin seguir symlinks) para expandir
   * eventos de directorio renombrado/copiado en Windows ReadDirectoryChangesW / macOS FSEvents.
   * @param {string} relDir
   * @returns {string[]}
   */
  _walkDirRel(relDir) {
    /** @type {string[]} */
    const found = [];
    const maxWalkFiles = 2000;
    const walk = (absDir, prefix, depth) => {
      if (depth > 20 || found.length >= maxWalkFiles) return;
      let entries;
      try {
        entries = fs.readdirSync(absDir, { withFileTypes: true });
      } catch (e) {
        return;
      }
      for (const entry of entries) {
        if (found.length >= maxWalkFiles) break;
        if (entry.isSymbolicLink()) continue;
        const childRel = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (this.isIgnored(childRel)) continue;
        const childAbs = path.join(absDir, entry.name);
        if (entry.isDirectory()) {
          walk(childAbs, childRel, depth + 1);
        } else if (entry.isFile()) {
          found.push(childRel);
        }
      }
    };
    const startAbs = path.join(this.sourceDir, relDir);
    walk(startAbs, relDir, 0);
    return found;
  }

  /**
   * Detecta renombres que sólo cambian mayúsculas/minúsculas (p. ej. `App.tsx` -> `app.tsx`
   * en NTFS/APFS) comprobando `readdirSync` para eliminar la ruta antigua en servidores Linux.
   * @param {string} rel
   * @param {string} abs
   * @returns {string[]}
   */
  _detectCaseRenameOldKeys(rel, abs) {
    const lowerRel = rel.toLowerCase();
    /** @type {string[]} */
    const oldKeys = [];
    for (const tracked of this.lastSentHashes.keys()) {
      if (tracked !== rel && tracked.toLowerCase() === lowerRel) {
        oldKeys.push(tracked);
      }
    }
    if (oldKeys.length === 0) return oldKeys;
    try {
      const entries = new Set(fs.readdirSync(path.dirname(abs)));
      return oldKeys.filter((oldRel) => !entries.has(path.posix.basename(oldRel)));
    } catch (e) {
      return oldKeys;
    }
  }

  /** Envía un mensaje de protocolo de carga troceada y espera su `chunk_ack`. */
  _sendChunkRpc(payload, timeoutMs = 30000) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    const reqId = `chkreq_${++this._chunkReqSeq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._chunkWaiters.delete(reqId);
        reject(new Error(`Tiempo de espera agotado en carga troceada (${payload.type})`));
      }, timeoutMs);
      if (timer.unref) timer.unref();
      this._chunkWaiters.set(reqId, { resolve, reject, timer });
      this.ws.send(JSON.stringify({
        ...payload,
        reqId,
        projectId: this.projectId,
        targetDir: this.targetDir
      }));
    });
  }

  /**
   * Transfiere un archivo grande (>10 MiB hasta 100 MiB) mediante troceado secuencial
   * (`chunk_start` -> `chunk_part` -> `chunk_commit`) con verificación SHA-256 en destino.
   * Confirma `lastSentHashes` ÚNICAMENTE tras el ACK del commit.
   *
   * @param {string} rel
   * @param {string} abs
   * @param {number} size
   */
  async sendLargeFileChunked(rel, abs, size) {
    const fileSha = sha256FileSync(abs);
    const prevHash = this.lastSentHashes.get(rel);
    if (prevHash === fileSha) {
      return { skipped: true, sha256: fileSha };
    }

    const startAck = await this._sendChunkRpc({
      type: 'chunk_start',
      path: rel,
      totalBytes: size,
      sha256: fileSha,
      ...(prevHash ? { baseSha256: prevHash } : {})
    });
    const uploadId = startAck.uploadId;
    const partSize = Math.min(CLIENT_CHUNK_PART_BYTES, Number(startAck.maxChunkBytes) || CLIENT_CHUNK_PART_BYTES);

    let fd = -1;
    try {
      fd = fs.openSync(abs, 'r');
      const buf = Buffer.allocUnsafe(partSize);
      let index = 0;
      let bytesRead = 0;
      while ((bytesRead = fs.readSync(fd, buf, 0, partSize, null)) > 0) {
        const slice = bytesRead === partSize ? buf : buf.subarray(0, bytesRead);
        await this._sendChunkRpc({
          type: 'chunk_part',
          uploadId,
          index,
          encoding: 'base64',
          data: slice.toString('base64')
        });
        index++;
      }
      fs.closeSync(fd);
      fd = -1;

      const commitAck = await this._sendChunkRpc({
        type: 'chunk_commit',
        uploadId
      });
      this.lastSentHashes.set(rel, fileSha);
      try {
        const st = fs.lstatSync(abs);
        this._statCache.set(abs, { mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, size: st.size, sha256: fileSha });
      } catch (e) {}
      this.emit('frame_ack', commitAck);
      return commitAck;
    } catch (err) {
      if (fd !== -1) {
        try { fs.closeSync(fd); } catch (e) {}
      }
      try {
        if (this.ws && this.ws.readyState === 1) {
          await this._sendChunkRpc({ type: 'chunk_abort', uploadId }, 5000).catch(() => {});
        }
      } catch (e) {}
      throw err;
    }
  }

  /** Envía inmediatamente todos los ficheros acumulados (serializado y confirmando hashes solo tras ACK). */
  async flushNow() {
    if (this._flushing && this._activeFlushPromise) {
      await this._activeFlushPromise.catch(() => {});
      if (this.pending.size === 0) return null;
    }
    if (!this.ws || this.ws.readyState !== 1 || this.pending.size === 0) return null;

    this._flushing = true;
    const run = (async () => {
      let lastAck = null;
      while (this.ws && this.ws.readyState === 1 && this.pending.size > 0) {
        const batch = Array.from(this.pending.entries());
        this.pending.clear();

        /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string, baseSha256?: string }>} */
        const files = [];
        /** @type {Array<{ rel: string, op: 'upsert' | 'delete', hash?: string }>} */
        const pendingHashCommits = [];
        /** @type {Array<{ rel: string, abs: string, size: number }>} */
        const largeFiles = [];
        const queuedOps = new Set();

        /** @param {string} rel @param {'upsert' | 'delete'} op */
        const processEntry = async (rel, op) => {
          const prevHash = this.lastSentHashes.get(rel);
          const abs = path.join(this.sourceDir, rel);
          if (op === 'delete') {
            this._statCache.delete(abs);
            const prefix = `${rel}/`;
            for (const tracked of Array.from(this.lastSentHashes.keys())) {
              if (tracked.startsWith(prefix)) {
                this._statCache.delete(path.join(this.sourceDir, tracked));
                pendingHashCommits.push({ rel: tracked, op: 'delete' });
              }
            }
            if (!queuedOps.has(`delete:${rel}`)) {
              queuedOps.add(`delete:${rel}`);
              pendingHashCommits.push({ rel, op: 'delete' });
              files.push({ path: rel, op: 'delete', ...(prevHash ? { baseSha256: prevHash } : {}) });
            }
            return;
          }

          const res = await this._readFileSafe(abs, { skipIfUnchangedHash: prevHash || null });
          if (res.kind === 'unchanged') return;

          if (res.kind === 'dir') {
            // Windows/macOS fs.watch emite sólo el directorio en renombres/copias: expandir todos sus hijos
            const children = this._walkDirRel(rel);
            for (const childRel of children) {
              await processEntry(childRel, 'upsert');
            }
            return;
          }

          if (res.kind === 'file' && res.buffer) {
            const h = res.sha256 || sha256(res.buffer);
            // Detectar renombres sólo de capitalización (App.tsx -> app.tsx) y emitir delete antes del upsert
            const oldCaseKeys = this._detectCaseRenameOldKeys(rel, abs);
            for (const oldRel of oldCaseKeys) {
              const oldPrev = this.lastSentHashes.get(oldRel);
              this._statCache.delete(path.join(this.sourceDir, oldRel));
              if (!queuedOps.has(`delete:${oldRel}`)) {
                queuedOps.add(`delete:${oldRel}`);
                pendingHashCommits.push({ rel: oldRel, op: 'delete' });
                files.push({ path: oldRel, op: 'delete', ...(oldPrev ? { baseSha256: oldPrev } : {}) });
              }
            }
            if (prevHash === h && oldCaseKeys.length === 0) return;
            if (!queuedOps.has(`upsert:${rel}`)) {
              queuedOps.add(`upsert:${rel}`);
              pendingHashCommits.push({ rel, op: 'upsert', hash: h });
              files.push({
                path: rel,
                op: 'upsert',
                buffer: res.buffer,
                sha256: h,
                ...(prevHash ? { baseSha256: prevHash } : {})
              });
            }
          } else if (res.kind === 'chunked' && typeof res.size === 'number') {
            if (this.chunkedUploadSupported) {
              largeFiles.push({ rel, abs, size: res.size });
            } else {
              this.emit('file_skipped', { path: rel, size: res.size, limit: MAX_CLIENT_FILE_BYTES });
            }
          } else if (res.kind === 'missing') {
            // Si era un directorio borrado en Windows/macOS, purgar también los hijos de lastSentHashes
            const prefix = `${rel}/`;
            for (const tracked of Array.from(this.lastSentHashes.keys())) {
              if (tracked.startsWith(prefix)) {
                this._statCache.delete(path.join(this.sourceDir, tracked));
                pendingHashCommits.push({ rel: tracked, op: 'delete' });
              }
            }
            if (!queuedOps.has(`delete:${rel}`)) {
              queuedOps.add(`delete:${rel}`);
              pendingHashCommits.push({ rel, op: 'delete' });
              files.push({ path: rel, op: 'delete', ...(prevHash ? { baseSha256: prevHash } : {}) });
            }
          } else if (res.kind === 'too_large') {
            this.emit('file_skipped', { path: rel, size: res.size, limit: MAX_CHUNKED_FILE_BYTES });
          }
        };

        for (const [rel, op] of batch) {
          await processEntry(rel, op);
        }

        if (files.length === 0 && largeFiles.length === 0) continue;
        try {
          if (files.length > 0) {
            const res = await this.sendChunked(files);
            lastAck = res.lastAck;
            for (const c of pendingHashCommits) {
              if (c.op === 'delete') this.lastSentHashes.delete(c.rel);
              else if (c.hash) this.lastSentHashes.set(c.rel, c.hash);
            }
          }
          for (const lf of largeFiles) {
            lastAck = await this.sendLargeFileChunked(lf.rel, lf.abs, lf.size);
          }
        } catch (err) {
          // Re-encolar cambios no confirmados sin sobrescribir cambios más recientes
          for (const [rel, op] of batch) {
            if (!this.pending.has(rel)) this.pending.set(rel, op);
          }
          throw err;
        }
      }
      return lastAck;
    })();

    this._activeFlushPromise = run;
    try {
      return await run;
    } finally {
      this._flushing = false;
      this._activeFlushPromise = null;
    }
  }

  /**
   * Codifica un Commit Frame como trama binaria adaptativa:
   * - `0x01`: `[1B 0x01][4B metaLen][JSON meta][buffers]` (bypass instantáneo <512 B, incompresibles o servidores antiguos)
   * - `0x02`: `[1B 0x02][4B rawLen][brotli([4B metaLen][JSON meta][buffers])]` (>=512 B y ahorro >=15%)
   * - `0x03`: `[1B 0x03][4B rawLen][gzip([4B metaLen][JSON meta][buffers])]` (>=512 B y ahorro >=15%)
   *
   * @param {number} seq
   * @param {Array<{ path: string, op?: 'upsert' | 'delete', buffer?: Buffer, content?: string, encoding?: 'utf8' | 'base64', sha256?: string, baseSha256?: string }>} files
   * @param {{ forceCodec?: 'br' | 'gzip' | 'none' }} [options]
   */
  encodeBinaryFrame(seq, files, options = {}) {
    /** @type {Buffer[]} */
    const chunks = [];
    /** @type {Array<{ path: string, op: string, buf?: Buffer }>} */
    const probeEntries = [];
    const metaFiles = files.map((f) => {
      if (f.op === 'delete') {
        return {
          path: f.path,
          op: 'delete',
          ...(f.baseSha256 ? { baseSha256: f.baseSha256 } : {})
        };
      }
      const buf = Buffer.isBuffer(f.buffer)
        ? f.buffer
        : Buffer.from(String(f.content ?? ''), f.encoding === 'base64' ? 'base64' : 'utf8');
      chunks.push(buf);
      probeEntries.push({ path: f.path, op: 'upsert', buf });
      return {
        path: f.path,
        op: 'upsert',
        byteLength: buf.length,
        sha256: f.sha256,
        ...(f.baseSha256 ? { baseSha256: f.baseSha256 } : {})
      };
    });
    const metaBuf = Buffer.from(JSON.stringify({
      type: 'frame',
      projectId: this.projectId,
      targetDir: this.targetDir,
      seq,
      files: metaFiles
    }), 'utf8');

    const metaLenPrefix = Buffer.allocUnsafe(4);
    metaLenPrefix.writeUInt32BE(metaBuf.length, 0);
    const rawBody = Buffer.concat([metaLenPrefix, metaBuf, ...chunks]);
    const rawWireLen = 1 + rawBody.length;

    const codec = options && options.forceCodec !== undefined
      ? (options.forceCodec === 'none' ? null : options.forceCodec)
      : this._selectCodec();

    if (codec && rawBody.length >= COMPRESSION_MIN_BYTES && !isMostlyIncompressible(probeEntries)) {
      try {
        const z = getZlib();
        const compressed = codec === 'br'
          ? z.brotliCompressSync(rawBody, {
            params: {
              [z.constants.BROTLI_PARAM_MODE]: z.constants.BROTLI_MODE_TEXT,
              [z.constants.BROTLI_PARAM_QUALITY]: rawBody.length > 128 * 1024 ? 4 : 1
            }
          })
          : z.gzipSync(rawBody, { level: 1 });

        const compressedWireLen = 5 + compressed.length;
        if (compressedWireLen <= Math.floor(rawWireLen * COMPRESSION_MAX_RATIO)) {
          const prefix = Buffer.allocUnsafe(5);
          prefix[0] = codec === 'br' ? FRAME_MAGIC_BROTLI : FRAME_MAGIC_GZIP;
          prefix.writeUInt32BE(rawBody.length, 1);
          this.wireStats.rawBytes += rawWireLen;
          this.wireStats.wireBytes += compressedWireLen;
          this.wireStats.savedBytes += (rawWireLen - compressedWireLen);
          this.wireStats.compressedFrames++;
          return Buffer.concat([prefix, compressed]);
        }
      } catch (e) {
        // Fallback silencioso a 0x01 crudo ante cualquier fallo de compresión
      }
    }

    const rawPrefix = Buffer.allocUnsafe(1);
    rawPrefix[0] = FRAME_MAGIC_RAW;
    this.wireStats.rawBytes += rawWireLen;
    this.wireStats.wireBytes += rawWireLen;
    this.wireStats.rawFrames++;
    return Buffer.concat([rawPrefix, rawBody]);
  }

  /**
   * Envía un array de ficheros directamente como Commit Frame y espera el ACK.
   *
   * @param {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, encoding?: 'base64' | 'utf8', content?: string, sha256?: string, baseSha256?: string }>} files
   */
  sendFrame(files) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    const seq = ++this.seq;
    const sentAtNs = process.hrtime.bigint();

    return new Promise((resolve, reject) => {
      this.inflight.set(seq, { resolve, reject, sentAtNs });
      if (this.binaryFramesSupported) {
        const payload = this.encodeBinaryFrame(seq, files);
        this.ws.send(payload);
      } else {
        const jsonFiles = files.map((f) => {
          if (f.op === 'delete') {
            return {
              path: f.path,
              op: 'delete',
              ...(f.baseSha256 ? { baseSha256: f.baseSha256 } : {})
            };
          }
          if (Buffer.isBuffer(f.buffer)) {
            return {
              path: f.path,
              op: 'upsert',
              encoding: 'base64',
              content: f.buffer.toString('base64'),
              sha256: f.sha256,
              ...(f.baseSha256 ? { baseSha256: f.baseSha256 } : {})
            };
          }
          return f;
        });
        this.ws.send(JSON.stringify({
          type: 'frame',
          projectId: this.projectId,
          targetDir: this.targetDir,
          seq,
          files: jsonFiles
        }));
      }
    });
  }

  /** Reconciliación Merkle delta real: consulta `verify` al servidor y transfiere sólo los archivos divergentes. */
  async reconcileDelta() {
    if (this._reconciling) return { reconciled: false, skipped: true };
    this._reconciling = true;
    try {
      const canReuseInitial = Boolean(
        this._initialTreeHasFiles &&
        this.initialLocalTree &&
        this.initialLocalTree.files &&
        this.pending.size === 0 &&
        (Date.now() - (this.initialLocalTreeAt || 0)) < FRESH_TREE_MAX_AGE_MS
      );
      const localTree = canReuseInitial ? this.initialLocalTree : this._computeLocalTree();
      this.initialLocalTree = null;
      this.initialLocalTreeAt = 0;
      this._initialTreeHasFiles = false;

      const verified = await this.verifyWithServer(localTree.files);
      const cmp = verified && verified.comparison;
      if (!cmp || cmp.inSync) {
        this.lastSentHashes.clear();
        for (const [k, v] of Object.entries(localTree.files)) this.lastSentHashes.set(k, v);
        return { reconciled: true, changed: 0, framesSent: 0, rootDigest: localTree.rootDigest };
      }

      /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string, baseSha256?: string }>} */
      const files = [];
      /** @type {Array<{ rel: string, op: 'upsert' | 'delete', hash?: string }>} */
      const pendingHashCommits = [];
      /** @type {Array<{ rel: string, abs: string, size: number }>} */
      const largeFiles = [];

      for (const rel of [...(cmp.missingOnServer || []), ...(cmp.staleOnServer || [])]) {
        const abs = path.join(this.sourceDir, rel);
        const res = await this._readFileSafe(abs);
        if (res.kind === 'file' && res.buffer) {
          const h = res.sha256 || sha256(res.buffer);
          const prevHash = this.lastSentHashes.get(rel);
          pendingHashCommits.push({ rel, op: 'upsert', hash: h });
          files.push({
            path: rel,
            op: 'upsert',
            buffer: res.buffer,
            sha256: h,
            ...(prevHash ? { baseSha256: prevHash } : {})
          });
        } else if (res.kind === 'chunked' && typeof res.size === 'number') {
          if (this.chunkedUploadSupported) {
            largeFiles.push({ rel, abs, size: res.size });
          } else {
            this.emit('file_skipped', { path: rel, size: res.size, limit: MAX_CLIENT_FILE_BYTES });
          }
        }
      }
      for (const rel of (cmp.extraOnServer || [])) {
        const prevHash = this.lastSentHashes.get(rel);
        pendingHashCommits.push({ rel, op: 'delete' });
        files.push({ path: rel, op: 'delete', ...(prevHash ? { baseSha256: prevHash } : {}) });
      }
      if (files.length === 0 && largeFiles.length === 0) {
        return { reconciled: true, changed: 0, framesSent: 0, rootDigest: localTree.rootDigest };
      }

      let lastAck = null;
      let framesSent = 0;
      if (files.length > 0) {
        const res = await this.sendChunked(files);
        lastAck = res.lastAck;
        framesSent += res.framesSent;
        // Confirmar lastSentHashes ÚNICAMENTE tras ACK exitoso (cero envenenamiento si cae el WS)
        for (const c of pendingHashCommits) {
          if (c.op === 'delete') {
            this.lastSentHashes.delete(c.rel);
            this._statCache.delete(path.join(this.sourceDir, c.rel));
          } else if (c.hash) {
            this.lastSentHashes.set(c.rel, c.hash);
          }
        }
      }
      for (const lf of largeFiles) {
        lastAck = await this.sendLargeFileChunked(lf.rel, lf.abs, lf.size);
        framesSent++;
      }
      return { reconciled: true, changed: files.length + largeFiles.length, framesSent, rootDigest: localTree.rootDigest, ack: lastAck };
    } finally {
      this._reconciling = false;
    }
  }

  /** Reconciliación basada en árbol de Merkle con delta automático y troceado. */
  async reconcileFull(serverFilesMap = null) {
    if (!serverFilesMap && this.initialInSync && this.initialLocalTree) {
      this.initialInSync = false;
      const digest = this.initialLocalTree.rootDigest;
      this.initialLocalTree = null;
      this.initialLocalTreeAt = 0;
      this._initialTreeHasFiles = false;
      return { reconciled: true, changed: 0, rootDigest: digest };
    }
    if (!serverFilesMap) {
      try {
        return await this.reconcileDelta();
      } catch (e) {
        // Fallback a reconciliación completa si el servidor no soporta verify delta
      }
    }
    const localTree = this._initialTreeHasFiles && this.initialLocalTree && !serverFilesMap && Object.keys(this.initialLocalTree.files || {}).length > 0
      ? this.initialLocalTree
      : this._computeLocalTree();
    this.initialLocalTree = null;
    this.initialLocalTreeAt = 0;
    this._initialTreeHasFiles = false;
    /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string, baseSha256?: string }>} */
    const files = [];
    /** @type {Array<{ rel: string, op: 'upsert' | 'delete', hash?: string }>} */
    const pendingHashCommits = [];
    /** @type {Array<{ rel: string, abs: string, size: number }>} */
    const largeFiles = [];

    if (serverFilesMap) {
      const diff = diffMerkleTrees(localTree.files, serverFilesMap);
      for (const rel of [...diff.missingOnServer, ...diff.staleOnServer]) {
        const abs = path.join(this.sourceDir, rel);
        const res = await this._readFileSafe(abs);
        if (res.kind === 'file' && res.buffer) {
          const h = res.sha256 || sha256(res.buffer);
          const prevHash = this.lastSentHashes.get(rel);
          pendingHashCommits.push({ rel, op: 'upsert', hash: h });
          files.push({
            path: rel,
            op: 'upsert',
            buffer: res.buffer,
            sha256: h,
            ...(prevHash ? { baseSha256: prevHash } : {})
          });
        } else if (res.kind === 'chunked' && typeof res.size === 'number' && this.chunkedUploadSupported) {
          largeFiles.push({ rel, abs, size: res.size });
        }
      }
      for (const rel of diff.extraOnServer) {
        const prevHash = this.lastSentHashes.get(rel);
        pendingHashCommits.push({ rel, op: 'delete' });
        files.push({ path: rel, op: 'delete', ...(prevHash ? { baseSha256: prevHash } : {}) });
      }
    } else {
      for (const [rel] of Object.entries(localTree.files)) {
        const abs = path.join(this.sourceDir, rel);
        const res = await this._readFileSafe(abs);
        if (res.kind === 'file' && res.buffer) {
          const h = res.sha256 || sha256(res.buffer);
          const prevHash = this.lastSentHashes.get(rel);
          pendingHashCommits.push({ rel, op: 'upsert', hash: h });
          files.push({
            path: rel,
            op: 'upsert',
            buffer: res.buffer,
            sha256: h,
            ...(prevHash ? { baseSha256: prevHash } : {})
          });
        } else if (res.kind === 'chunked' && typeof res.size === 'number' && this.chunkedUploadSupported) {
          largeFiles.push({ rel, abs, size: res.size });
        }
      }
      // Limpiar ficheros que fueron sincronizados antes pero ya no existen en localTree (extras huérfanos en fallback)
      for (const [trackedRel, prevHash] of this.lastSentHashes.entries()) {
        if (!Object.prototype.hasOwnProperty.call(localTree.files, trackedRel)) {
          pendingHashCommits.push({ rel: trackedRel, op: 'delete' });
          files.push({ path: trackedRel, op: 'delete', ...(prevHash ? { baseSha256: prevHash } : {}) });
        }
      }
    }

    if (files.length === 0 && largeFiles.length === 0) return { reconciled: true, changed: 0, rootDigest: localTree.rootDigest };

    let lastAck = null;
    let framesSent = 0;
    if (files.length > 0) {
      const res = await this.sendChunked(files);
      lastAck = res.lastAck;
      framesSent += res.framesSent;
      for (const c of pendingHashCommits) {
        if (c.op === 'delete') {
          this.lastSentHashes.delete(c.rel);
          this._statCache.delete(path.join(this.sourceDir, c.rel));
        } else if (c.hash) {
          this.lastSentHashes.set(c.rel, c.hash);
        }
      }
    }
    for (const lf of largeFiles) {
      lastAck = await this.sendLargeFileChunked(lf.rel, lf.abs, lf.size);
      framesSent++;
    }
    return { reconciled: true, changed: files.length + largeFiles.length, framesSent, rootDigest: localTree.rootDigest, ack: lastAck };
  }

  async stop() {
    this.closed = true;
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this.coalesceTimer) {
      clearTimeout(this.coalesceTimer);
      this.coalesceTimer = null;
    }
    if (this._imm) {
      clearImmediate(this._imm);
      this._imm = null;
    }
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
    if (this.nativeWatcher) {
      try { this.nativeWatcher.close(); } catch (e) {}
      this.nativeWatcher = null;
    }
    if (this.watcher) {
      try { await this.watcher.close(); } catch (e) {}
      this.watcher = null;
    }
    if (this.ws) {
      try { this.ws.close(); } catch (e) {}
      this.ws = null;
    }
    this.connected = false;
  }
}

module.exports = { LiveSyncClient, compileIgnoreRule, loadCulkiboIgnore };
