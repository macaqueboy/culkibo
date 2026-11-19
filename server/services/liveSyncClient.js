const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const chokidar = require('chokidar');
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
    /** @type {ReturnType<typeof setTimeout> | null} */
    this.coalesceTimer = null;
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
      // granularidad de `mtimeMs` de chokidar. En Linux caemos a chokidar.
      if (process.platform === 'win32' || process.platform === 'darwin') {
        this.nativeWatcher = fs.watch(this.sourceDir, { recursive: true }, (_eventType, filename) => {
          if (!filename) return;
          const rel = String(filename).split(path.sep).join('/');
          if (IGNORED_SEGMENT_RE.test(rel) || path.basename(rel).includes('.culkibo-sync-')) return;
          const abs = path.join(this.sourceDir, rel);
          try {
            if (fs.existsSync(abs)) {
              const st = fs.statSync(abs);
              if (st.isFile()) this.enqueue(abs, 'upsert');
            } else {
              this.enqueue(abs, 'delete');
            }
          } catch (e) {
            // En Windows un editor puede mantener el handle abierto brevemente (EBUSY);
            // encolar igualmente para leer tras `quiescenceMs` evita perder cambios.
            this.enqueue(abs, 'upsert');
          }
        });
        this.nativeWatcher.on('error', (err) => this.emit('error', err));
      } else {
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

      const ws = new WebSocket(this.wsUrl, { headers });
      this.ws = ws;

      const onOpenError = (err) => {
        reject(err);
      };
      ws.once('error', onOpenError);

      ws.once('open', () => {
        ws.off('error', onOpenError);
        this.connected = true;

        const localTree = computeMerkleTree(this.sourceDir);
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
          this.seq = msg.lastSeq || 0;
          this.emit('ready', msg);
          resolve(msg);
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
          } else if (!this.connected) {
            reject(err);
          } else {
            this.emit('sync_error', err);
          }
        }
      });

      ws.on('close', () => {
        this.connected = false;
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
    this.pending.set(rel, op);

    if (this.coalesceTimer) clearTimeout(this.coalesceTimer);
    this.coalesceTimer = setTimeout(() => {
      this.coalesceTimer = null;
      this.flushNow().catch((err) => this.emit('sync_error', err));
    }, this.quiescenceMs);
  }

  /** Envía inmediatamente todos los ficheros acumulados como un Commit Frame atómico. */
  async flushNow() {
    if (!this.ws || this.ws.readyState !== 1 || this.pending.size === 0) return null;

    const batch = Array.from(this.pending.entries());
    this.pending.clear();

    const files = [];
    for (const [rel, op] of batch) {
      if (op === 'delete') {
        files.push({ path: rel, op: 'delete' });
      } else {
        const abs = path.join(this.sourceDir, rel);
        if (!fs.existsSync(abs)) continue;
        try {
          const buf = fs.readFileSync(abs);
          files.push({
            path: rel,
            op: 'upsert',
            encoding: 'base64',
            content: buf.toString('base64'),
            sha256: sha256(buf)
          });
        } catch (e) {}
      }
    }

    if (files.length === 0) return null;
    return this.sendFrame(files);
  }

  /**
   * Envía un array de ficheros directamente como Commit Frame y espera el ACK.
   *
   * @param {Array<{ path: string, op: 'upsert' | 'delete', encoding?: 'base64' | 'utf8', content?: string, sha256?: string }>} files
   */
  sendFrame(files) {
    if (!this.ws || this.ws.readyState !== 1) {
      return Promise.reject(new Error('El WebSocket de sincronización no está conectado'));
    }
    const seq = ++this.seq;
    const sentAtNs = process.hrtime.bigint();

    return new Promise((resolve, reject) => {
      this.inflight.set(seq, { resolve, reject, sentAtNs });
      this.ws.send(JSON.stringify({
        type: 'frame',
        projectId: this.projectId,
        targetDir: this.targetDir,
        seq,
        files
      }));
    });
  }

  /** Reconciliación completa basada en árbol de Merkle (auto-curación de deriva). */
  async reconcileFull(serverFilesMap = null) {
    const localTree = computeMerkleTree(this.sourceDir);
    /** @type {Array<{ path: string, op: 'upsert' | 'delete', encoding?: 'base64', content?: string, sha256?: string }>} */
    const files = [];

    if (serverFilesMap) {
      const diff = diffMerkleTrees(localTree.files, serverFilesMap);
      for (const rel of [...diff.missingOnServer, ...diff.staleOnServer]) {
        const buf = fs.readFileSync(path.join(this.sourceDir, rel));
        files.push({ path: rel, op: 'upsert', encoding: 'base64', content: buf.toString('base64'), sha256: sha256(buf) });
      }
      for (const rel of diff.extraOnServer) {
        files.push({ path: rel, op: 'delete' });
      }
    } else {
      for (const [rel, hash] of Object.entries(localTree.files)) {
        const buf = fs.readFileSync(path.join(this.sourceDir, rel));
        files.push({ path: rel, op: 'upsert', encoding: 'base64', content: buf.toString('base64'), sha256: hash });
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
