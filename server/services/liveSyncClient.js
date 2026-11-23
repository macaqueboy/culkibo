const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const WebSocket = require('ws');
const { computeMerkleTree, diffMerkleTrees, sha256 } = require('./liveSyncEngine');

/**
 * Cliente real de sincronización en vivo (máquina local -> daemon de Culkibo).
 *
 * Acumula cambios de disco en una ventana corta de quiescencia (`quiescenceMs`)
 * para enviarlos como un único Commit Frame atómico sobre un WebSocket
 * persistente autenticado, con verificación Merkle inicial y auto-reparación.
 */

const IGNORED_SEGMENT_RE = /(^|[\\/])(\.git|node_modules|\.next|\.nuxt|\.culkibo|dist|build|coverage|__pycache__|\.venv|venv)([\\/]|$)/;

class LiveSyncClient extends EventEmitter {
  /**
   * @param {{
   *   projectId: string,
   *   sourceDir: string,
   *   wsUrl?: string,
   *   token?: string | null,
   *   quiescenceMs?: number,
   *   autoWatch?: boolean,
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

      // Listener permanente de errores para evitar crash por 'error' tras 'open' (P1-15)
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
          this.seq = msg.lastSeq || 0;
          this.initialInSync = Boolean(msg.inSync);
          this.binaryFramesSupported = Boolean(msg.binaryFramesSupported);
          if (this.initialInSync && this.initialLocalTree) {
            this.lastSentHashes.clear();
            for (const [k, v] of Object.entries(this.initialLocalTree.files)) {
              this.lastSentHashes.set(k, v);
            }
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
          return;
        }

        if (msg.type === 'verify_ack') {
          this.emit('verify_ack', msg);
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
        this.emit('close');
      });
    });
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

  /** Envía inmediatamente todos los ficheros acumulados como un Commit Frame atómico. */
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
        try {
          const buf = fs.readFileSync(abs);
          const h = sha256(buf);
          if (this.lastSentHashes.get(rel) === h) continue;
          this.lastSentHashes.set(rel, h);
          files.push({ path: rel, op: 'upsert', buffer: buf, sha256: h });
        } catch (e) {
          if (e && e.code === 'ENOENT') {
            this.lastSentHashes.delete(rel);
            files.push({ path: rel, op: 'delete' });
          }
          // Ignorar EISDIR / EPERM transitorios de directorio
        }
      }
    }

    if (files.length === 0) return null;
    return this.sendFrame(files);
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

  /** Reconciliación completa basada en árbol de Merkle (auto-curación de deriva). */
  async reconcileFull(serverFilesMap = null) {
    if (!serverFilesMap && this.initialInSync && this.initialLocalTree) {
      this.initialInSync = false;
      return { reconciled: true, changed: 0, rootDigest: this.initialLocalTree.rootDigest };
    }
    const localTree = this.initialLocalTree && !serverFilesMap
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
    const ack = await this.sendFrame(files);
    return { reconciled: true, changed: files.length, rootDigest: localTree.rootDigest, ack };
  }

  async stop() {
    this.closed = true;
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
