const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const WebSocket = require('ws');
const { computeMerkleTree, diffMerkleTrees, sha256 } = require('./liveSyncEngine');

/**
 * Cliente real de sincronización en vivo (máquina local -> daemon de Culkibo).
 *
 * Acumula cambios de disco en una ventana corta de quiescencia (`quiescenceMs`)
 * para enviarlos como un único Commit Frame atómico sobre un WebSocket
 * persistente autenticado, con verificación Merkle delta y auto-reconexión.
 */

const IGNORED_SEGMENT_RE = /(^|[\\/])(\.git|node_modules|\.next|\.nuxt|\.turbo|\.svelte-kit|\.output|\.astro|\.cache|\.culkibo|dist|build|coverage|__pycache__|\.venv|venv|target|vendor)([\\/]|$)/;
const MAX_CLIENT_FILE_BYTES = 10 * 1024 * 1024;
const CHUNK_MAX_FILES = 250;
const CHUNK_MAX_BYTES = 8 * 1024 * 1024;

class LiveSyncClient extends EventEmitter {
  /**
   * @param {{
   *   projectId: string,
   *   sourceDir: string,
   *   wsUrl?: string,
   *   token?: string | null,
   *   quiescenceMs?: number,
   *   autoWatch?: boolean,
   *   autoReconnect?: boolean,
   *   clientName?: string,
   *   targetDir?: string | null
   * }} options
   */
  constructor(options) {
    super();
    this.projectId = options.projectId;
    this.sourceDir = path.resolve(options.sourceDir);
    this.wsUrl = options.wsUrl || 'ws://127.0.0.1:3030/ws/sync';
    this.token = options.token || null;
    this.quiescenceMs = typeof options.quiescenceMs === 'number' ? options.quiescenceMs : 12;
    this.autoWatch = options.autoWatch !== false;
    this.autoReconnect = options.autoReconnect !== false;
    this.clientName = options.clientName || os.hostname();
    this.targetDir = options.targetDir || null;

    /** @type {any} */
    this.ws = null;
    /** @type {any} */
    this.watcher = null;
    /** @type {any} */
    this.nativeWatcher = null;
    this.seq = 0;
    this.connected = false;
    this.closed = false;
    this._reconnectAttempt = 0;
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._reconnectTimer = null;
    this._reconciling = false;
    /** @type {Array<{ resolve: (v: any) => void, reject: (e: any) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._verifyWaiters = [];

    /** @type {Map<string, 'upsert' | 'delete'>} */
    this.pending = new Map();
    /** @type {Map<string, string>} */
    this.lastSentHashes = new Map();
    /** @type {any} */
    this.initialLocalTree = null;
    this.initialInSync = false;
    this.binaryFramesSupported = false;
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
    /** @type {Map<number, { resolve: (v: any) => void, reject: (e: any) => void, sentAtNs: bigint }>} */
    this.inflight = new Map();
  }

  /** Conecta el WebSocket persistente, realiza handshake Merkle y arranca el watcher. */
  async start() {
    this.closed = false;
    await this.connect();

    if (this.autoWatch) {
      // En Windows y macOS `fs.watch({ recursive: true })` usa directamente
      // ReadDirectoryChangesW / FSEvents sin la latencia ni la supresión por
      // granularidad de `mtimeMs` de chokidar. En Linux caemos a chokidar (carga perezosa).
      if (process.platform === 'win32' || process.platform === 'darwin') {
        this.nativeWatcher = fs.watch(this.sourceDir, { recursive: true }, (_eventType, filename) => {
          if (!filename) return;
          const rel = String(filename).split(path.sep).join('/');
          if (!rel || IGNORED_SEGMENT_RE.test(rel) || rel.includes('.culkibo-sync-')) return;
          // Sin fs.statSync en el camino caliente: flushNow resuelve ENOENT/EISDIR al leer.
          this._enqueueRel(rel, 'upsert');
        });
        this.nativeWatcher.on('error', (err) => this.emit('error', err));
      } else {
        const chokidar = require('chokidar');
        this.watcher = chokidar.watch(this.sourceDir, {
          ignored: (filePath) => IGNORED_SEGMENT_RE.test(filePath) || path.basename(filePath).includes('.culkibo-sync-'),
          persistent: true,
          ignoreInitial: true,
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

      const ws = new WebSocket(this.wsUrl, { headers, perMessageDeflate: false });
      this.ws = ws;

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

        const localTree = computeMerkleTree(this.sourceDir);
        this.initialLocalTree = localTree;
        ws.send(JSON.stringify({
          type: 'hello',
          projectId: this.projectId,
          targetDir: this.targetDir,
          clientName: this.clientName,
          sourceDir: this.sourceDir,
          pid: process.pid,
          clientDigest: localTree.rootDigest,
          fileCount: localTree.fileCount
        }));

        this.pingTimer = setInterval(() => {
          if (ws.readyState === 1) {
            try { ws.ping(); } catch (e) {}
          }
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
          this.initialInSync = Boolean(msg.inSync);
          this.binaryFramesSupported = Boolean(msg.binaryFramesSupported);
          if (this.initialInSync && this.initialLocalTree) {
            this.lastSentHashes.clear();
            for (const [k, v] of Object.entries(this.initialLocalTree.files)) {
              this.lastSentHashes.set(k, v);
            }
            this.initialLocalTree = { rootDigest: this.initialLocalTree.rootDigest, fileCount: this.initialLocalTree.fileCount, files: {} };
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
            for (const f of msg.restoredFiles) this.lastSentHashes.delete(String(f));
          }
          this.emit('rollback_notice', msg);
          return;
        }

        if (msg.type === 'error') {
          const err = new Error(msg.error || 'Error en sincronización en vivo');
          /** @type {any} */ (err).code = msg.code || 'SYNC_ERROR';
          if (msg.seq && this.inflight.has(msg.seq)) {
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

      ws.on('close', () => {
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
        while (this._verifyWaiters.length) {
          const w = this._verifyWaiters.shift();
          if (w) {
            clearTimeout(w.timer);
            w.reject(new Error('Conexión de sincronización cerrada'));
          }
        }
        this.emit('close');
        if (!this.closed && this.autoReconnect) {
          this._scheduleReconnect();
        }
      });
    });
  }

  /** Reconexión automática con backoff exponencial (500ms → 15s) y reconciliación Merkle delta al reconectar. */
  _scheduleReconnect() {
    if (this.closed || this._reconnectTimer) return;
    const delayMs = Math.min(15000, Math.round(500 * Math.pow(2, this._reconnectAttempt)));
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

  /** Lee un archivo con reintentos cortos ante EBUSY/EPERM transitorios de editores en Windows. */
  async _readFileSafe(abs) {
    for (let attempt = 1; attempt <= 4; attempt++) {
      try {
        const st = fs.statSync(abs);
        if (st.isDirectory()) return { kind: 'dir' };
        if (st.size > MAX_CLIENT_FILE_BYTES) {
          return { kind: 'too_large', size: st.size };
        }
        return { kind: 'file', buffer: fs.readFileSync(abs) };
      } catch (e) {
        if (e && e.code === 'ENOENT') return { kind: 'missing' };
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
    if (!rel || rel.startsWith('..') || IGNORED_SEGMENT_RE.test(rel)) return;
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

  /** Envía inmediatamente todos los ficheros acumulados como uno o varios Commit Frames atómicos. */
  async flushNow() {
    if (!this.ws || this.ws.readyState !== 1 || this.pending.size === 0) return null;

    const batch = Array.from(this.pending.entries());
    this.pending.clear();

    /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string }>} */
    const files = [];
    for (const [rel, op] of batch) {
      if (op === 'delete') {
        this.lastSentHashes.delete(rel);
        files.push({ path: rel, op: 'delete' });
      } else {
        const abs = path.join(this.sourceDir, rel);
        const res = await this._readFileSafe(abs);
        if (res.kind === 'file' && res.buffer) {
          const h = sha256(res.buffer);
          if (this.lastSentHashes.get(rel) === h) continue;
          this.lastSentHashes.set(rel, h);
          files.push({ path: rel, op: 'upsert', buffer: res.buffer, sha256: h });
        } else if (res.kind === 'missing') {
          this.lastSentHashes.delete(rel);
          files.push({ path: rel, op: 'delete' });
        } else if (res.kind === 'too_large') {
          this.emit('file_skipped', { path: rel, size: res.size, limit: MAX_CLIENT_FILE_BYTES });
        }
      }
    }

    if (files.length === 0) return null;
    const { lastAck } = await this.sendChunked(files);
    return lastAck;
  }

  /**
   * Codifica un Commit Frame como trama binaria `[1B 0x01][4B metaLen][JSON meta][buffers]`
   * evitando base64 (+33%) y escapes JSON.
   */
  encodeBinaryFrame(seq, files) {
    /** @type {Buffer[]} */
    const chunks = [];
    const metaFiles = files.map((f) => {
      if (f.op === 'delete') return { path: f.path, op: 'delete' };
      const buf = Buffer.isBuffer(f.buffer)
        ? f.buffer
        : Buffer.from(String(f.content ?? ''), f.encoding === 'base64' ? 'base64' : 'utf8');
      chunks.push(buf);
      return { path: f.path, op: 'upsert', byteLength: buf.length, sha256: f.sha256 };
    });
    const metaBuf = Buffer.from(JSON.stringify({
      type: 'frame',
      projectId: this.projectId,
      targetDir: this.targetDir,
      seq,
      files: metaFiles
    }), 'utf8');
    const prefix = Buffer.allocUnsafe(5);
    prefix[0] = 0x01;
    prefix.writeUInt32BE(metaBuf.length, 1);
    return Buffer.concat([prefix, metaBuf, ...chunks]);
  }

  /**
   * Envía un array de ficheros directamente como Commit Frame y espera el ACK.
   *
   * @param {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, encoding?: 'base64' | 'utf8', content?: string, sha256?: string }>} files
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
          if (f.op === 'delete') return { path: f.path, op: 'delete' };
          if (Buffer.isBuffer(f.buffer)) {
            return { path: f.path, op: 'upsert', encoding: 'base64', content: f.buffer.toString('base64'), sha256: f.sha256 };
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
      const localTree = computeMerkleTree(this.sourceDir);
      const verified = await this.verifyWithServer(localTree.files);
      const cmp = verified && verified.comparison;
      if (!cmp || cmp.inSync) {
        this.lastSentHashes.clear();
        for (const [k, v] of Object.entries(localTree.files)) this.lastSentHashes.set(k, v);
        return { reconciled: true, changed: 0, framesSent: 0, rootDigest: localTree.rootDigest };
      }

      /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string }>} */
      const files = [];
      for (const rel of [...(cmp.missingOnServer || []), ...(cmp.staleOnServer || [])]) {
        const res = await this._readFileSafe(path.join(this.sourceDir, rel));
        if (res.kind === 'file' && res.buffer) {
          const h = sha256(res.buffer);
          this.lastSentHashes.set(rel, h);
          files.push({ path: rel, op: 'upsert', buffer: res.buffer, sha256: h });
        }
      }
      for (const rel of (cmp.extraOnServer || [])) {
        this.lastSentHashes.delete(rel);
        files.push({ path: rel, op: 'delete' });
      }
      if (files.length === 0) {
        return { reconciled: true, changed: 0, framesSent: 0, rootDigest: localTree.rootDigest };
      }
      const { lastAck, framesSent } = await this.sendChunked(files);
      return { reconciled: true, changed: files.length, framesSent, rootDigest: localTree.rootDigest, ack: lastAck };
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
      return { reconciled: true, changed: 0, rootDigest: digest };
    }
    if (!serverFilesMap) {
      try {
        return await this.reconcileDelta();
      } catch (e) {
        // Fallback a reconciliación completa si el servidor no soporta verify delta
      }
    }
    const localTree = this.initialLocalTree && !serverFilesMap && Object.keys(this.initialLocalTree.files || {}).length > 0
      ? this.initialLocalTree
      : computeMerkleTree(this.sourceDir);
    this.initialLocalTree = null;
    /** @type {Array<{ path: string, op: 'upsert' | 'delete', buffer?: Buffer, sha256?: string }>} */
    const files = [];

    if (serverFilesMap) {
      const diff = diffMerkleTrees(localTree.files, serverFilesMap);
      for (const rel of [...diff.missingOnServer, ...diff.staleOnServer]) {
        const buf = fs.readFileSync(path.join(this.sourceDir, rel));
        const h = sha256(buf);
        this.lastSentHashes.set(rel, h);
        files.push({ path: rel, op: 'upsert', buffer: buf, sha256: h });
      }
      for (const rel of diff.extraOnServer) {
        this.lastSentHashes.delete(rel);
        files.push({ path: rel, op: 'delete' });
      }
    } else {
      for (const [rel, hash] of Object.entries(localTree.files)) {
        const buf = fs.readFileSync(path.join(this.sourceDir, rel));
        this.lastSentHashes.set(rel, hash);
        files.push({ path: rel, op: 'upsert', buffer: buf, sha256: hash });
      }
    }

    if (files.length === 0) return { reconciled: true, changed: 0, rootDigest: localTree.rootDigest };

    const { lastAck, framesSent } = await this.sendChunked(files);
    return { reconciled: true, changed: files.length, framesSent, rootDigest: localTree.rootDigest, ack: lastAck };
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

module.exports = { LiveSyncClient };
