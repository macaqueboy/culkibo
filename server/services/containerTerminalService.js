'use strict';

/**
 * Culkibo Zero-Dep Interactive Container Web Terminal Service (Arcane / Dockge class — ZERO `node-pty`).
 *
 * Bridges Culkibo's existing `ws` WebSocket server (`/ws/terminal?ticket=...`) directly
 * to the Docker Engine HTTP API over Unix socket / Windows named pipe (or TCP/SSH tunnel):
 *  - `POST /containers/:id/exec` (`Tty: true`, `AttachStdin/Stdout/Stderr: true`)
 *  - `POST /exec/:id/start` with `Connection: Upgrade`, `Upgrade: tcp` raw socket hijack
 *  - `POST /exec/:id/resize?h=<rows>&w=<cols>` on `{ type: 'resize', cols, rows }` frames
 *
 * Security Guarantees:
 *  - 0 external npm dependencies, 0 shell command construction (`shell: false`).
 *  - Strict shell allowlist (`['/bin/sh', '/bin/bash', '/bin/ash']`) & container name validation.
 *  - Single-use HMAC-SHA256 tickets (60s TTL, constant-time verify, atomic replay-proof consumption).
 *  - Bounded <= 4 concurrent sessions per user & 15-minute idle session auto-termination.
 *  - Tamper-evident audit metadata on session open/close — NEVER logs raw keystrokes or terminal I/O.
 */

const crypto = require('crypto');
const http = require('http');

const ALLOWED_SHELLS = Object.freeze(['/bin/sh', '/bin/bash', '/bin/ash']);
const MAX_SESSIONS_PER_USER = 4;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const TICKET_TTL_MS = 60 * 1000;
const MAX_PENDING_TICKETS = 256;
const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const EXEC_ID_RE = /^[a-zA-Z0-9_-]{4,128}$/;

/**
 * Clamps terminal dimensions safely.
 * @param {any} raw
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clampInt(raw, fallback, min, max) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

/**
 * Resolves default local Docker Engine socket/pipe path.
 * @param {string | null | undefined} explicitPath
 * @returns {string}
 */
function resolveDockerSocketPath(explicitPath) {
  if (typeof explicitPath === 'string' && explicitPath.trim()) {
    return explicitPath.trim();
  }
  if (process.env.DOCKER_SOCKET_PATH && process.env.DOCKER_SOCKET_PATH.trim()) {
    return process.env.DOCKER_SOCKET_PATH.trim();
  }
  return process.platform === 'win32'
    ? '\\\\.\\pipe\\docker_engine'
    : '/var/run/docker.sock';
}

/**
 * Builds Node `http.request` connection options for either a TCP mock/tunneled Docker Engine
 * or a local Unix socket / Windows named pipe.
 * @param {{ transport?: { host?: string, port?: number, socketPath?: string } | null, dockerSocketPath?: string | null }} opts
 */
function resolveTransportOptions(opts) {
  const t = opts && opts.transport && typeof opts.transport === 'object' ? opts.transport : null;
  if (t && t.host && t.port) {
    return {
      host: String(t.host),
      port: Number(t.port)
    };
  }
  if (t && t.socketPath) {
    return { socketPath: String(t.socketPath) };
  }
  return { socketPath: resolveDockerSocketPath(opts && opts.dockerSocketPath) };
}

/**
 * Issues a JSON HTTP request directly against the Docker Engine API (zero shell).
 * @param {{
 *   method: string,
 *   path: string,
 *   body?: any,
 *   timeoutMs?: number,
 *   transport?: { host?: string, port?: number, socketPath?: string } | null,
 *   dockerSocketPath?: string | null
 * }} reqOpts
 * @returns {Promise<{ statusCode: number, body: string, json: any }>}
 */
function dockerApiJsonRequest(reqOpts) {
  return new Promise((resolve, reject) => {
    const conn = resolveTransportOptions(reqOpts);
    const payload = reqOpts.body !== undefined && reqOpts.body !== null
      ? Buffer.from(JSON.stringify(reqOpts.body), 'utf8')
      : null;

    /** @type {Record<string, string>} */
    const headers = {
      Accept: 'application/json',
      Host: 'docker'
    };
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(payload.length);
    }

    const req = http.request(
      {
        ...conn,
        method: reqOpts.method,
        path: reqOpts.path,
        headers,
        timeout: reqOpts.timeoutMs || 10000
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          if (total < 1024 * 1024) {
            chunks.push(c);
            total += c.length;
          }
        });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          if (text.trim()) {
            try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
          }
          resolve({ statusCode: res.statusCode || 0, body: text, json: parsed });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Docker Engine API request timeout (${reqOpts.method} ${reqOpts.path})`));
    });
    req.on('error', (err) => reject(err));

    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Starts a Docker exec session using raw `Connection: Upgrade` / `Upgrade: tcp` hijack.
 * @param {{
 *   execId: string,
 *   timeoutMs?: number,
 *   transport?: { host?: string, port?: number, socketPath?: string } | null,
 *   dockerSocketPath?: string | null
 * }} opts
 * @returns {Promise<{ socket: import('net').Socket, head: Buffer }>}
 */
function dockerExecStartHijack(opts) {
  return new Promise((resolve, reject) => {
    const conn = resolveTransportOptions(opts);
    const startBody = Buffer.from(JSON.stringify({ Detach: false, Tty: true }), 'utf8');
    let settled = false;

    const req = http.request({
      ...conn,
      method: 'POST',
      path: `/exec/${encodeURIComponent(opts.execId)}/start`,
      timeout: opts.timeoutMs || 10000,
      headers: {
        Host: 'docker',
        'Content-Type': 'application/json',
        'Content-Length': String(startBody.length),
        Connection: 'Upgrade',
        Upgrade: 'tcp'
      }
    });

    req.on('upgrade', (_res, socket, head) => {
      if (settled) {
        try { socket.destroy(); } catch (e) {}
        return;
      }
      settled = true;
      socket.setTimeout(0);
      resolve({ socket, head: head || Buffer.alloc(0) });
    });

    req.on('response', (res) => {
      if (settled) return;
      settled = true;
      /** @type {Buffer[]} */
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const msg = Buffer.concat(chunks).toString('utf8').slice(0, 300);
        const err = /** @type {any} */ (new Error(`Docker exec start rejected upgrade (HTTP ${res.statusCode}): ${msg}`));
        err.code = 'DOCKER_EXEC_START_FAILED';
        err.status = res.statusCode || 502;
        reject(err);
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('Docker exec hijack timeout'));
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

    req.write(startBody);
    req.end();
  });
}

class ContainerTerminalService {
  /**
   * @param {{
   *   maxSessionsPerUser?: number,
   *   idleTimeoutMs?: number,
   *   ticketTtlMs?: number,
   *   dockerSocketPath?: string | null,
   *   auditFn?: ((event: string, meta: Record<string, any>) => void) | null
   * }} [opts]
   */
  constructor(opts = {}) {
    this.maxSessionsPerUser = clampInt(opts.maxSessionsPerUser, MAX_SESSIONS_PER_USER, 1, 32);
    this.idleTimeoutMs = clampInt(opts.idleTimeoutMs, IDLE_TIMEOUT_MS, 500, 60 * 60 * 1000);
    this.ticketTtlMs = clampInt(opts.ticketTtlMs, TICKET_TTL_MS, 1000, 5 * 60 * 1000);
    /** @type {string | null} */
    this.dockerSocketPath = opts.dockerSocketPath || null;
    /** @type {((event: string, meta: Record<string, any>) => void) | null} */
    this._auditFn = typeof opts.auditFn === 'function' ? opts.auditFn : null;

    this._hmacKey = crypto.randomBytes(32);
    /** @type {Map<string, { nonce: string, projectId: string, containerName: string, userId: string, username: string, shell: string, cols: number, rows: number, expiresAtMs: number }>} */
    this._pendingTickets = new Map();
    /** @type {Map<string, any>} */
    this._sessions = new Map();
  }

  /**
   * Records session lifecycle metadata (NEVER raw keystrokes or terminal payloads).
   * @param {string} action
   * @param {Record<string, any>} meta
   */
  _audit(action, meta) {
    if (this._auditFn) {
      try { this._auditFn(action, meta); } catch (e) {}
      return;
    }
    // Never mutate repo-root data/audit.jsonl during isolated tests unless CULKIBO_DATA_DIR is set
    if (process.env.NODE_ENV === 'test' && !process.env.CULKIBO_DATA_DIR) return;
    try {
      const auditLogger = require('./auditLogger');
      if (auditLogger && typeof auditLogger.record === 'function') {
        auditLogger.record({
          source: 'ws',
          action,
          resourceId: meta.containerName || meta.projectId || 'container',
          actor: meta.username || meta.userId || 'terminal',
          detail: meta
        });
      }
    } catch (e) {}
  }

  /** Removes expired pending single-use tickets. */
  _pruneExpiredTickets() {
    const now = Date.now();
    for (const [nonce, rec] of this._pendingTickets.entries()) {
      if (rec.expiresAtMs <= now) {
        this._pendingTickets.delete(nonce);
      }
    }
  }

  /**
   * Counts active terminal sessions belonging to `userId`.
   * @param {string} userId
   * @returns {number}
   */
  _countUserSessions(userId) {
    let count = 0;
    for (const s of this._sessions.values()) {
      if (s.userId === userId) count++;
    }
    return count;
  }

  /**
   * Issues a single-use HMAC-SHA256 WebSocket terminal ticket (60s TTL).
   * Strictly validates `shell` against `ALLOWED_SHELLS`, `containerName` against Docker naming
   * rules, and enforces `<= MAX_SESSIONS_PER_USER` concurrent sessions per user.
   *
   * @param {{
   *   projectId?: string,
   *   containerName: string,
   *   userId?: string,
   *   username?: string,
   *   shell?: string,
   *   cols?: number,
   *   rows?: number
   * }} opts
   */
  issueTicket(opts) {
    if (!opts || typeof opts !== 'object') {
      const err = /** @type {any} */ (new Error('issueTicket requires an options object'));
      err.code = 'INVALID_REQUEST';
      err.status = 400;
      throw err;
    }

    const containerName = String(opts.containerName || '').trim();
    if (!CONTAINER_NAME_RE.test(containerName)) {
      const err = /** @type {any} */ (new Error(`Invalid containerName: "${containerName.slice(0, 64)}"`));
      err.code = 'INVALID_CONTAINER_NAME';
      err.status = 400;
      throw err;
    }

    const shell = String(opts.shell || '/bin/sh').trim();
    if (!ALLOWED_SHELLS.includes(/** @type {any} */ (shell))) {
      const err = /** @type {any} */ (new Error(`Disallowed shell "${shell}". Allowed: ${ALLOWED_SHELLS.join(', ')}`));
      err.code = 'INVALID_SHELL';
      err.status = 400;
      throw err;
    }

    const projectId = String(opts.projectId || 'default').trim().slice(0, 128) || 'default';
    const userId = String(opts.userId || opts.username || 'anonymous').trim().slice(0, 128) || 'anonymous';
    const username = String(opts.username || userId).trim().slice(0, 128);
    const cols = clampInt(opts.cols, 120, 20, 500);
    const rows = clampInt(opts.rows, 32, 5, 200);

    if (this._countUserSessions(userId) >= this.maxSessionsPerUser) {
      const err = /** @type {any} */ (new Error(`Max concurrent terminal sessions (${this.maxSessionsPerUser}) reached for user "${userId}"`));
      err.code = 'MAX_SESSIONS_EXCEEDED';
      err.status = 429;
      throw err;
    }

    this._pruneExpiredTickets();
    if (this._pendingTickets.size >= MAX_PENDING_TICKETS) {
      const oldest = this._pendingTickets.keys().next().value;
      if (oldest) this._pendingTickets.delete(oldest);
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const expiresAtMs = Date.now() + this.ticketTtlMs;
    const payloadObj = {
      n: nonce,
      p: projectId,
      c: containerName,
      u: userId,
      un: username,
      s: shell,
      w: cols,
      h: rows,
      e: expiresAtMs
    };
    const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
    const sigB64 = crypto.createHmac('sha256', this._hmacKey).update(payloadB64).digest('base64url');
    const ticket = `${payloadB64}.${sigB64}`;

    this._pendingTickets.set(nonce, {
      nonce,
      projectId,
      containerName,
      userId,
      username,
      shell,
      cols,
      rows,
      expiresAtMs
    });

    return {
      ticket,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      wsPath: `/ws/terminal?ticket=${encodeURIComponent(ticket)}`,
      projectId,
      containerName,
      shell,
      cols,
      rows
    };
  }

  /**
   * Constant-time verifies and atomically consumes a single-use terminal ticket (replay-proof).
   * @param {string | null | undefined} ticket
   * @returns {{ valid: boolean, reason?: string, sessionSpec?: { nonce: string, projectId: string, containerName: string, userId: string, username: string, shell: string, cols: number, rows: number, expiresAtMs: number } }}
   */
  consumeTicket(ticket) {
    if (typeof ticket !== 'string' || !ticket.includes('.')) {
      return { valid: false, reason: 'MALFORMED_TICKET' };
    }
    const parts = ticket.trim().split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { valid: false, reason: 'MALFORMED_TICKET' };
    }
    const [payloadB64, sigB64] = parts;
    const expectedSig = crypto.createHmac('sha256', this._hmacKey).update(payloadB64).digest();
    let providedSig;
    try {
      providedSig = Buffer.from(sigB64, 'base64url');
    } catch (e) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }
    if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(expectedSig, providedSig)) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }

    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch (e) {
      return { valid: false, reason: 'INVALID_PAYLOAD' };
    }
    if (!parsed || typeof parsed.n !== 'string' || typeof parsed.e !== 'number') {
      return { valid: false, reason: 'INVALID_PAYLOAD' };
    }

    const record = this._pendingTickets.get(parsed.n);
    if (!record) {
      return { valid: false, reason: 'TICKET_ALREADY_USED' };
    }
    // Atomic single-use deletion BEFORE returning
    this._pendingTickets.delete(parsed.n);

    if (Date.now() > record.expiresAtMs || Date.now() > parsed.e) {
      return { valid: false, reason: 'TICKET_EXPIRED' };
    }
    if (this._countUserSessions(record.userId) >= this.maxSessionsPerUser) {
      return { valid: false, reason: 'MAX_SESSIONS_EXCEEDED' };
    }

    return { valid: true, sessionSpec: record };
  }

  /**
   * Resizes an active Docker exec TTY via `POST /exec/:id/resize?h=<rows>&w=<cols>`.
   * @param {string} execId
   * @param {number} cols
   * @param {number} rows
   * @param {{ transport?: { host?: string, port?: number, socketPath?: string } | null, dockerSocketPath?: string | null }} [opts]
   */
  async resizeExec(execId, cols, rows, opts = {}) {
    const cleanId = String(execId || '').trim();
    if (!EXEC_ID_RE.test(cleanId)) {
      throw new Error(`Invalid Docker execId: "${cleanId.slice(0, 40)}"`);
    }
    const safeCols = clampInt(cols, 120, 20, 500);
    const safeRows = clampInt(rows, 32, 5, 200);
    const res = await dockerApiJsonRequest({
      method: 'POST',
      path: `/exec/${encodeURIComponent(cleanId)}/resize?h=${safeRows}&w=${safeCols}`,
      transport: opts.transport || null,
      dockerSocketPath: opts.dockerSocketPath || this.dockerSocketPath
    });
    return {
      ok: res.statusCode >= 200 && res.statusCode < 300,
      statusCode: res.statusCode,
      execId: cleanId,
      cols: safeCols,
      rows: safeRows
    };
  }

  /**
   * Opens a Docker Engine TTY exec stream directly via HTTP + `Upgrade: tcp` hijack (zero `node-pty`).
   * @param {{
   *   containerName: string,
   *   shell?: string,
   *   cols?: number,
   *   rows?: number,
   *   dockerSocketPath?: string | null,
   *   transport?: { host?: string, port?: number, socketPath?: string } | null
   * }} opts
   */
  async createExecStream(opts) {
    const containerName = String((opts && opts.containerName) || '').trim();
    if (!CONTAINER_NAME_RE.test(containerName)) {
      throw new Error(`Invalid containerName: "${containerName.slice(0, 64)}"`);
    }
    const shell = String((opts && opts.shell) || '/bin/sh').trim();
    if (!ALLOWED_SHELLS.includes(/** @type {any} */ (shell))) {
      throw new Error(`Disallowed shell "${shell}"`);
    }
    const cols = clampInt(opts && opts.cols, 120, 20, 500);
    const rows = clampInt(opts && opts.rows, 32, 5, 200);
    const transport = (opts && opts.transport) || null;
    const dockerSocketPath = (opts && opts.dockerSocketPath) || this.dockerSocketPath;

    const createRes = await dockerApiJsonRequest({
      method: 'POST',
      path: `/containers/${encodeURIComponent(containerName)}/exec`,
      body: {
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        Tty: true,
        Cmd: [shell],
        Env: ['TERM=xterm-256color', `COLUMNS=${cols}`, `LINES=${rows}`]
      },
      transport,
      dockerSocketPath
    });

    if (createRes.statusCode < 200 || createRes.statusCode >= 300 || !createRes.json || !createRes.json.Id) {
      const err = /** @type {any} */ (new Error(`Docker exec create failed (HTTP ${createRes.statusCode}): ${createRes.body.slice(0, 200)}`));
      err.code = 'DOCKER_EXEC_CREATE_FAILED';
      err.status = createRes.statusCode || 502;
      throw err;
    }

    const execId = String(createRes.json.Id);
    const { socket, head } = await dockerExecStartHijack({
      execId,
      transport,
      dockerSocketPath
    });

    // Best-effort initial TTY sizing right after stream attaches
    this.resizeExec(execId, cols, rows, { transport, dockerSocketPath }).catch(() => {});

    return {
      execId,
      containerName,
      shell,
      cols,
      rows,
      socket,
      head,
      resize: (/** @type {number} */ nextCols, /** @type {number} */ nextRows) =>
        this.resizeExec(execId, nextCols, nextRows, { transport, dockerSocketPath }),
      close: () => {
        try { socket.destroy(); } catch (e) {}
      }
    };
  }

  /**
   * Attaches a WebSocket client (`/ws/terminal?ticket=...`) to a Docker container TTY hijack stream.
   * Handles single-use ticket consumption, bidirectional I/O, JSON `{ type: 'resize' | 'ping' }`
   * control frames, 15-min idle timeout, session tracking, and metadata-only audit logging.
   *
   * @param {any} ws
   * @param {import('http').IncomingMessage | { url?: string }} req
   * @param {{ transport?: { host?: string, port?: number, socketPath?: string } | null, dockerSocketPath?: string | null }} [opts]
   */
  async attachWebSocket(ws, req, opts = {}) {
    const rawUrl = (req && req.url) ? String(req.url) : '';
    let ticket = '';
    try {
      const parsed = new URL(rawUrl, 'http://localhost');
      ticket = parsed.searchParams.get('ticket') || '';
    } catch (e) {
      ticket = '';
    }

    const safeSendJson = (/** @type {Record<string, any>} */ obj) => {
      try {
        if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
      } catch (e) {}
    };

    const consumed = this.consumeTicket(ticket);
    if (!consumed.valid || !consumed.sessionSpec) {
      const code = consumed.reason === 'MAX_SESSIONS_EXCEEDED' ? 4429 : 4401;
      safeSendJson({ type: 'error', code: consumed.reason || 'UNAUTHORIZED' });
      try { ws.close(code, consumed.reason || 'Unauthorized'); } catch (e) {}
      return { ok: false, reason: consumed.reason || 'UNAUTHORIZED' };
    }

    const spec = consumed.sessionSpec;
    const sessionId = `term_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const createdAtMs = Date.now();

    /** @type {any} */
    const session = {
      sessionId,
      projectId: spec.projectId,
      containerName: spec.containerName,
      userId: spec.userId,
      username: spec.username,
      shell: spec.shell,
      cols: spec.cols,
      rows: spec.rows,
      execId: null,
      createdAt: new Date(createdAtMs).toISOString(),
      createdAtMs,
      lastActivityAt: new Date(createdAtMs).toISOString(),
      lastActivityMs: createdAtMs,
      ws,
      /** @type {import('net').Socket | null} */
      socket: null,
      /** @type {ReturnType<typeof setTimeout> | null} */
      idleTimer: null,
      closed: false,
      close: (/** @type {string} */ _reason) => {}
    };

    // Reserve user session slot immediately before async Docker connect
    this._sessions.set(sessionId, session);

    /** @param {string} reason @param {number} [wsCode] */
    const teardown = (reason, wsCode = 1000) => {
      if (session.closed) return;
      session.closed = true;
      if (session.idleTimer) {
        clearTimeout(session.idleTimer);
        session.idleTimer = null;
      }
      this._sessions.delete(sessionId);
      if (session.socket) {
        try { session.socket.destroy(); } catch (e) {}
        session.socket = null;
      }
      try {
        if (ws && (ws.readyState === 0 || ws.readyState === 1)) {
          ws.close(wsCode, reason.slice(0, 120));
        }
      } catch (e) {}

      this._audit('terminal.session.closed', {
        sessionId,
        projectId: session.projectId,
        containerName: session.containerName,
        userId: session.userId,
        username: session.username,
        shell: session.shell,
        execId: session.execId,
        durationMs: Date.now() - createdAtMs,
        reason
      });
    };
    session.close = teardown;

    const resetIdleTimer = () => {
      const now = Date.now();
      session.lastActivityMs = now;
      session.lastActivityAt = new Date(now).toISOString();
      if (session.idleTimer) clearTimeout(session.idleTimer);
      session.idleTimer = setTimeout(() => {
        safeSendJson({ type: 'timeout', message: 'Terminal idle timeout reached' });
        teardown('idle_timeout', 4408);
      }, this.idleTimeoutMs);
      if (session.idleTimer.unref) session.idleTimer.unref();
    };

    let stream;
    try {
      stream = await this.createExecStream({
        containerName: spec.containerName,
        shell: spec.shell,
        cols: spec.cols,
        rows: spec.rows,
        transport: opts.transport || null,
        dockerSocketPath: opts.dockerSocketPath || this.dockerSocketPath
      });
    } catch (err) {
      const errMsg = err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : 'Docker exec failed';
      safeSendJson({ type: 'error', code: 'EXEC_ATTACH_FAILED', message: errMsg });
      teardown('exec_attach_failed', 1011);
      return { ok: false, reason: 'EXEC_ATTACH_FAILED', error: errMsg };
    }

    if (session.closed || ws.readyState !== 1) {
      stream.close();
      teardown('ws_closed_before_attach', 1000);
      return { ok: false, reason: 'WS_CLOSED' };
    }

    session.execId = stream.execId;
    session.socket = stream.socket;
    resetIdleTimer();

    this._audit('terminal.session.opened', {
      sessionId,
      projectId: session.projectId,
      containerName: session.containerName,
      userId: session.userId,
      username: session.username,
      shell: session.shell,
      execId: stream.execId,
      cols: session.cols,
      rows: session.rows
    });

    safeSendJson({
      type: 'ready',
      sessionId,
      execId: stream.execId,
      containerName: session.containerName,
      shell: session.shell,
      cols: session.cols,
      rows: session.rows
    });

    if (stream.head && stream.head.length > 0 && ws.readyState === 1) {
      try { ws.send(stream.head); } catch (e) {}
    }

    stream.socket.on('data', (chunk) => {
      if (session.closed) return;
      resetIdleTimer();
      try {
        if (ws.readyState === 1) ws.send(chunk);
      } catch (e) {
        teardown('ws_send_error', 1011);
      }
    });

    stream.socket.on('end', () => teardown('container_eof', 1000));
    stream.socket.on('close', () => teardown('container_socket_closed', 1000));
    stream.socket.on('error', () => teardown('container_socket_error', 1011));

    ws.on('message', (data, isBinary) => {
      if (session.closed || !session.socket || session.socket.destroyed) return;
      resetIdleTimer();

      // Inspect UTF-8 text frames for JSON control commands (`resize`, `ping`, `input`)
      if (!isBinary) {
        const text = typeof data === 'string' ? data : Buffer.from(data).toString('utf8');
        if (text.startsWith('{') && text.endsWith('}') && text.length <= 16384) {
          try {
            const ctrl = JSON.parse(text);
            if (ctrl && typeof ctrl === 'object') {
              if (ctrl.type === 'ping') {
                safeSendJson({ type: 'pong', ts: Date.now() });
                return;
              }
              if (ctrl.type === 'resize') {
                const nextCols = clampInt(ctrl.cols, session.cols, 20, 500);
                const nextRows = clampInt(ctrl.rows, session.rows, 5, 200);
                session.cols = nextCols;
                session.rows = nextRows;
                stream.resize(nextCols, nextRows)
                  .then((r) => safeSendJson({ type: 'resized', ok: r.ok, cols: r.cols, rows: r.rows }))
                  .catch(() => safeSendJson({ type: 'resized', ok: false, cols: nextCols, rows: nextRows }));
                return;
              }
              if (ctrl.type === 'input' && typeof ctrl.data === 'string') {
                session.socket.write(ctrl.data, 'utf8');
                return;
              }
            }
          } catch (e) {
            // Not JSON control frame — fall through and write raw bytes to TTY stdin
          }
        }
        session.socket.write(text, 'utf8');
        return;
      }

      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      session.socket.write(buf);
    });

    ws.on('close', () => teardown('client_closed', 1000));
    ws.on('error', () => teardown('client_error', 1011));

    return {
      ok: true,
      sessionId,
      execId: stream.execId,
      containerName: session.containerName,
      shell: session.shell
    };
  }

  /**
   * Lists active terminal sessions (optionally filtered by `projectId`).
   * Never exposes internal socket/WS handles or tickets.
   * @param {string | null | undefined} [projectId]
   */
  listSessions(projectId) {
    /** @type {Array<any>} */
    const out = [];
    for (const s of this._sessions.values()) {
      if (projectId && s.projectId !== projectId) continue;
      out.push({
        sessionId: s.sessionId,
        projectId: s.projectId,
        containerName: s.containerName,
        userId: s.userId,
        username: s.username,
        shell: s.shell,
        cols: s.cols,
        rows: s.rows,
        execId: s.execId,
        createdAt: s.createdAt,
        lastActivityAt: s.lastActivityAt
      });
    }
    return out;
  }

  /**
   * Closes an active terminal session by ID.
   * @param {string} sessionId
   * @param {string} [reason]
   */
  closeSession(sessionId, reason = 'admin_closed') {
    const s = this._sessions.get(String(sessionId || ''));
    if (!s) return { closed: false, sessionId };
    s.close(reason, 1000);
    return { closed: true, sessionId };
  }

  /** Closes all active sessions cleanly (for daemon shutdown / tests). */
  closeAll(reason = 'server_shutdown') {
    for (const id of Array.from(this._sessions.keys())) {
      this.closeSession(id, reason);
    }
    this._pendingTickets.clear();
  }
}

const defaultContainerTerminalService = new ContainerTerminalService();

const exported = Object.assign(defaultContainerTerminalService, {
  ContainerTerminalService,
  ALLOWED_SHELLS,
  MAX_SESSIONS_PER_USER,
  IDLE_TIMEOUT_MS,
  TICKET_TTL_MS,
  CONTAINER_NAME_RE
});

module.exports = exported;
