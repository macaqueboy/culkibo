const crypto = require('crypto');
const { EventEmitter } = require('events');
const http = require('http');
const net = require('net');
const path = require('path');
const { atomicWriteJsonSync, loadJsonWithBackupSync, isMetadataIp } = require('./ssrfGuard');

/**
 * Culkibo EdgeTunnel — Túnel CGNAT soberano multiplexado sobre WebSocket (0 lock-in Cloudflare).
 *
 * Inspirado en Pangolin/Newt, pero implementado directamente sobre la dependencia `ws`
 * ya incluida en Culkibo (`ROOT_DEPS=6`, cero binarios externos, cero llamadas de shell):
 *  - Autenticación por túnel con token aleatorio de 256 bits verificado en tiempo constante
 *    mediante HMAC-SHA256 (`crypto.timingSafeEqual`). El token en claro sólo se entrega al crear.
 *  - Protocolo binario multiplexado `ET1` de 12 bytes de cabecera (`SYN` / `DATA` / `FIN` /
 *    `RST` / `PING` / `PONG`) con `streamId` de 32 bits: múltiples peticiones HTTP concurrentes
 *    viajan entrelazadas sobre una única conexión WebSocket saliente desde detrás de CGNAT/NAT.
 *  - Validación SSRF estricta: bloquea endpoints de metadatos cloud (`169.254.169.254`,
 *    `metadata.google.internal`, `100.100.100.200`, `fd00:ec2::254`, `.internal`) en servidor y agente.
 *  - Aislamiento completo por `CULKIBO_DATA_DIR` / `opts.dataDir` (0 escrituras en `data/` en tests).
 */

const FRAME_MAGIC_0 = 0x45; // 'E'
const FRAME_MAGIC_1 = 0x54; // 'T'
const FRAME_VERSION = 0x01;
const FRAME_HEADER_BYTES = 12;

const FRAME_TYPE = Object.freeze({
  SYN: 0x01,
  DATA: 0x02,
  FIN: 0x03,
  RST: 0x04,
  PING: 0x05,
  PONG: 0x06
});

const MAX_FRAME_PAYLOAD_BYTES = 2 * 1024 * 1024; // 2 MiB por frame
const MAX_RESPONSE_BODY_BYTES = 16 * 1024 * 1024; // 16 MiB por respuesta HTTP
const MAX_CONCURRENT_STREAMS = 128;
const DATA_CHUNK_SIZE = 64 * 1024;

const TUNNEL_ID_RE = /^tun_[a-z0-9_-]{4,48}$/;
const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const TARGET_HOST_RE = /^[a-zA-Z0-9._:\[\]-]{1,253}$/;
const BLOCKED_METADATA_HOSTS = new Set([
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'fd00:ec2::254'
]);
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

/** Carga perezosa de `ws` para no añadir RAM en arranque cuando EdgeTunnel no se usa. */
/** @type {any} */
let _wsMod = null;
function getWs() {
  if (!_wsMod) _wsMod = require('ws');
  return _wsMod;
}

/**
 * Resuelve el directorio `data/` respetando `opts.dataDir` o `CULKIBO_DATA_DIR`.
 * @param {string | null} [overrideDir]
 */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Valida que el destino de un túnel (`targetHost`, `targetPort`) no apunte a metadatos cloud
 * ni contenga caracteres de control/inyección. Permite loopback y hosts internos/Docker
 * (caso de uso legítimo de túneles CGNAT).
 *
 * @param {string} rawHost
 * @param {number | string} rawPort
 * @returns {{ targetHost: string, targetPort: number }}
 */
function validateTunnelTarget(rawHost, rawPort) {
  const host = String(rawHost || '127.0.0.1').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || !TARGET_HOST_RE.test(host) || /[\s\r\n\0]/.test(host)) {
    throw new Error(`targetHost inválido para EdgeTunnel: "${String(rawHost || '').slice(0, 60)}"`);
  }
  if (
    BLOCKED_METADATA_HOSTS.has(host)
    || host.endsWith('.internal')
    || host.endsWith('.goog')
    || isMetadataIp(host)
  ) {
    throw new Error(`targetHost bloqueado por protección SSRF (metadatos cloud): "${host}"`);
  }
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`targetPort inválido para EdgeTunnel (1-65535): "${rawPort}"`);
  }
  // Evitar IPv6 malformadas
  if (host.includes(':') && net.isIP(host) !== 6) {
    throw new Error(`Dirección IPv6 inválida en targetHost: "${host}"`);
  }
  return { targetHost: host, targetPort: port };
}

/**
 * Codifica un frame binario del protocolo `ET1`.
 * @param {number} type
 * @param {number} streamId
 * @param {Buffer | Uint8Array | string | null} [payload]
 * @returns {Buffer}
 */
function encodeFrame(type, streamId, payload = null) {
  const body = payload === null || payload === undefined
    ? Buffer.alloc(0)
    : (Buffer.isBuffer(payload) ? payload : Buffer.from(payload));
  if (body.length > MAX_FRAME_PAYLOAD_BYTES) {
    throw new Error(`Frame ET1 excede el límite máximo (${body.length} > ${MAX_FRAME_PAYLOAD_BYTES})`);
  }
  const frame = Buffer.allocUnsafe(FRAME_HEADER_BYTES + body.length);
  frame[0] = FRAME_MAGIC_0;
  frame[1] = FRAME_MAGIC_1;
  frame[2] = FRAME_VERSION;
  frame[3] = type & 0xff;
  frame.writeUInt32BE(streamId >>> 0, 4);
  frame.writeUInt32BE(body.length >>> 0, 8);
  if (body.length > 0) body.copy(frame, FRAME_HEADER_BYTES);
  return frame;
}

/**
 * Decodifica un frame binario `ET1` validando firma, versión y longitud exacta.
 * @param {Buffer | Uint8Array | ArrayBuffer | Buffer[]} raw
 * @returns {{ type: number, streamId: number, payload: Buffer }}
 */
function decodeFrame(raw) {
  /** @type {Buffer} */
  let buf;
  if (Buffer.isBuffer(raw)) buf = raw;
  else if (Array.isArray(raw)) buf = Buffer.concat(raw);
  else if (raw instanceof ArrayBuffer) buf = Buffer.from(raw);
  else buf = Buffer.from(raw);

  if (buf.length < FRAME_HEADER_BYTES) {
    throw new Error('Frame ET1 truncado');
  }
  if (buf[0] !== FRAME_MAGIC_0 || buf[1] !== FRAME_MAGIC_1 || buf[2] !== FRAME_VERSION) {
    throw new Error('Cabecera ET1 inválida o versión incompatible');
  }
  const type = buf[3];
  const streamId = buf.readUInt32BE(4);
  const payloadLen = buf.readUInt32BE(8);
  if (payloadLen > MAX_FRAME_PAYLOAD_BYTES || buf.length !== FRAME_HEADER_BYTES + payloadLen) {
    throw new Error(`Longitud de frame ET1 inconsistente (${buf.length - FRAME_HEADER_BYTES} != ${payloadLen})`);
  }
  return {
    type,
    streamId,
    payload: buf.subarray(FRAME_HEADER_BYTES)
  };
}

/**
 * Sanitiza cabeceras HTTP quitando hop-by-hop y caracteres CRLF.
 * @param {Record<string, any> | null | undefined} rawHeaders
 * @returns {Record<string, string>}
 */
function sanitizeHttpHeaders(rawHeaders) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;
  for (const [k, v] of Object.entries(rawHeaders)) {
    const lk = String(k || '').trim().toLowerCase();
    if (!lk || !/^[a-z0-9-]+$/.test(lk) || HOP_BY_HOP_HEADERS.has(lk)) continue;
    const rawVal = Array.isArray(v) ? v.join(', ') : String(v ?? '');
    if (/[\r\n\0]/.test(rawVal)) continue;
    out[lk] = rawVal.slice(0, 4096);
  }
  return out;
}

/**
 * Calcula HMAC-SHA256 del token de túnel con sal por túnel (protege contra fugas de store).
 * @param {string} tunnelId
 * @param {string} saltHex
 * @param {string} token
 * @returns {string}
 */
function computeTokenHmac(tunnelId, saltHex, token) {
  return crypto
    .createHmac('sha256', Buffer.from(saltHex, 'hex'))
    .update(`edgetunnel:v1:${tunnelId}:${token}`, 'utf8')
    .digest('hex');
}

/**
 * Comparación en tiempo constante de dos hashes hexadecimales.
 * @param {string} aHex
 * @param {string} bHex
 * @returns {boolean}
 */
function timingSafeEqualHex(aHex, bHex) {
  if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  if (aHex.length !== bHex.length || aHex.length === 0 || aHex.length % 2 !== 0) return false;
  try {
    const a = Buffer.from(aHex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

// ============================================================================
// SERVER SIDE: EdgeTunnelService
// ============================================================================

class EdgeTunnelService extends EventEmitter {
  /**
   * @param {{ dataDir?: string | null, heartbeatIntervalMs?: number, streamTimeoutMs?: number }} [opts]
   */
  constructor(opts = {}) {
    super();
    this._dataDirOverride = opts.dataDir || null;
    this._heartbeatIntervalMs = Math.max(5000, Number(opts.heartbeatIntervalMs) || 25000);
    this._defaultStreamTimeoutMs = Math.max(1000, Number(opts.streamTimeoutMs) || 30000);
    this._loaded = false;
    this._loadedStorePath = '';
    /** @type {Map<string, any>} */
    this.tunnels = new Map();
    /**
     * Conexiones WebSocket activas por `tunnelId`.
     * @type {Map<string, {
     *   ws: any,
     *   connectedAt: string,
     *   lastHeartbeatAt: string,
     *   nextStreamId: number,
     *   streams: Map<number, {
     *     resolve: (v: any) => void,
     *     reject: (e: Error) => void,
     *     timer: ReturnType<typeof setTimeout>,
     *     startedAt: number,
     *     status: number,
     *     headers: Record<string, string>,
     *     chunks: Buffer[],
     *     bodyBytes: number,
     *     gotSyn: boolean
     *   }>,
     *   heartbeatTimer: ReturnType<typeof setInterval> | null
     * }>}
     */
    this._connections = new Map();
    this._stats = {
      totalRequestsForwarded: 0,
      totalBytesIn: 0,
      totalBytesOut: 0,
      rejectedAuthCount: 0
    };
  }

  get storeFile() {
    return path.join(resolveDataDir(this._dataDirOverride), 'edge-tunnels.json');
  }

  _ensureLoaded() {
    const sf = this.storeFile;
    if (this._loaded && this._loadedStorePath === sf) return;
    this._loaded = true;
    this._loadedStorePath = sf;
    this.tunnels.clear();

    const loaded = loadJsonWithBackupSync(sf, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && Array.isArray(parsed.tunnels))
    });
    if (loaded.ok && loaded.data && Array.isArray(loaded.data.tunnels)) {
      for (const rec of loaded.data.tunnels) {
        if (rec && typeof rec.id === 'string' && TUNNEL_ID_RE.test(rec.id)) {
          this.tunnels.set(rec.id, rec);
        }
      }
    }
  }

  _save() {
    this._ensureLoaded();
    atomicWriteJsonSync(
      this.storeFile,
      { version: 1, tunnels: Array.from(this.tunnels.values()) },
      { mode: 0o600, backup: true }
    );
  }

  /**
   * Crea un nuevo túnel EdgeTunnel soberano y devuelve el token en claro UNA única vez.
   *
   * @param {{
   *   name?: string,
   *   targetHost?: string,
   *   targetPort: number | string,
   *   hostname?: string | null
   * }} cfg
   */
  createTunnel(cfg) {
    this._ensureLoaded();
    const { targetHost, targetPort } = validateTunnelTarget(String((cfg && cfg.targetHost) || '127.0.0.1'), cfg && cfg.targetPort);
    const name = String((cfg && cfg.name) || `tunnel-${targetPort}`)
      .replace(/[\x00-\x1f\x7f<>]/g, '')
      .trim()
      .slice(0, 80) || `tunnel-${targetPort}`;

    let hostname = '';
    if (cfg && cfg.hostname) {
      const cleanHost = String(cfg.hostname).trim().toLowerCase().replace(/\.+$/, '');
      if (!HOSTNAME_RE.test(cleanHost)) {
        throw new Error(`hostname inválido para EdgeTunnel (RFC 1123): "${cleanHost.slice(0, 80)}"`);
      }
      hostname = cleanHost;
    }

    const id = `tun_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const rawToken = `cket_${crypto.randomBytes(32).toString('base64url')}`;
    const tokenSalt = crypto.randomBytes(16).toString('hex');
    const tokenHmac = computeTokenHmac(id, tokenSalt, rawToken);
    const now = new Date().toISOString();

    const record = {
      id,
      name,
      targetHost,
      targetPort,
      hostname: hostname || null,
      tokenSalt,
      tokenHmac,
      tokenPreview: `${rawToken.slice(0, 9)}…${rawToken.slice(-4)}`,
      revoked: false,
      createdAt: now,
      updatedAt: now
    };

    this.tunnels.set(id, record);
    this._save();
    this.emit('tunnel_created', { id, name, hostname: record.hostname, targetHost, targetPort });

    return {
      ...this._toPublicTunnel(record),
      token: rawToken
    };
  }

  /**
   * Proyección pública segura de un túnel (JAMÁS expone `tokenSalt` ni `tokenHmac`).
   * @param {any} rec
   */
  _toPublicTunnel(rec) {
    const conn = this._connections.get(rec.id);
    return {
      id: rec.id,
      name: rec.name,
      targetHost: rec.targetHost,
      targetPort: rec.targetPort,
      hostname: rec.hostname || null,
      tokenPreview: rec.tokenPreview,
      revoked: Boolean(rec.revoked),
      status: rec.revoked ? 'revoked' : (conn ? 'connected' : 'offline'),
      connected: Boolean(conn && !rec.revoked),
      activeStreams: conn ? conn.streams.size : 0,
      connectedAt: conn ? conn.connectedAt : null,
      lastHeartbeatAt: conn ? conn.lastHeartbeatAt : null,
      createdAt: rec.createdAt,
      updatedAt: rec.updatedAt
    };
  }

  listTunnels() {
    this._ensureLoaded();
    return Array.from(this.tunnels.values())
      .map((rec) => this._toPublicTunnel(rec))
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  }

  /**
   * Verifica un token de túnel en tiempo constante (HMAC-SHA256 + timingSafeEqual).
   * @param {string} tunnelId
   * @param {string} token
   * @returns {boolean}
   */
  verifyToken(tunnelId, token) {
    this._ensureLoaded();
    if (typeof tunnelId !== 'string' || typeof token !== 'string' || !token) return false;
    const rec = this.tunnels.get(tunnelId);
    if (!rec || rec.revoked || !rec.tokenSalt || !rec.tokenHmac) return false;
    const candidateHmac = computeTokenHmac(tunnelId, rec.tokenSalt, token);
    return timingSafeEqualHex(candidateHmac, rec.tokenHmac);
  }

  /**
   * Revoca un túnel, cierra su sesión WebSocket activa y aborta streams pendientes.
   * @param {string} id
   */
  revokeTunnel(id) {
    this._ensureLoaded();
    const rec = this.tunnels.get(id);
    if (!rec) return { revoked: false, id };

    rec.revoked = true;
    rec.updatedAt = new Date().toISOString();
    this._save();

    const conn = this._connections.get(id);
    if (conn) {
      this._teardownConnection(id, conn, new Error('Túnel revocado por el administrador'));
      try { conn.ws.close(4401, 'Tunnel revoked'); } catch (e) {}
    }

    this.emit('tunnel_revoked', { id });
    return { revoked: true, id };
  }

  getStatus() {
    this._ensureLoaded();
    const list = this.listTunnels();
    let activeStreams = 0;
    for (const conn of this._connections.values()) activeStreams += conn.streams.size;
    return {
      enabled: true,
      protocol: 'culkibo-edgetunnel/v1',
      totalTunnels: list.length,
      activeTunnels: list.filter((t) => !t.revoked).length,
      connectedTunnels: list.filter((t) => t.connected).length,
      activeStreams,
      totalRequestsForwarded: this._stats.totalRequestsForwarded,
      totalBytesIn: this._stats.totalBytesIn,
      totalBytesOut: this._stats.totalBytesOut,
      rejectedAuthCount: this._stats.rejectedAuthCount,
      tunnels: list
    };
  }

  /**
   * Conecta un servidor `ws.WebSocketServer` para aceptar agentes EdgeTunnel salientes.
   * @param {any} wss
   */
  attachWebSocketServer(wss) {
    if (!wss || typeof wss.on !== 'function') {
      throw new Error('Se requiere una instancia válida de WebSocketServer');
    }

    wss.on('connection', (ws, req) => {
      const { tunnelId, token } = this._extractAuthFromRequest(req);
      if (!tunnelId || !token || !this.verifyToken(tunnelId, token)) {
        this._stats.rejectedAuthCount++;
        try { ws.close(4401, 'Unauthorized tunnel credentials'); } catch (e) {}
        return;
      }

      // Si había una conexión previa del mismo agente, reemplazarla limpiamente
      const existing = this._connections.get(tunnelId);
      if (existing) {
        this._teardownConnection(tunnelId, existing, new Error('Conexión de agente reemplazada'));
        try { existing.ws.close(4000, 'Replaced by newer agent session'); } catch (e) {}
      }

      const now = new Date().toISOString();
      /** @type {any} */
      const conn = {
        ws,
        connectedAt: now,
        lastHeartbeatAt: now,
        nextStreamId: 1,
        streams: new Map(),
        heartbeatTimer: null
      };
      this._connections.set(tunnelId, conn);

      conn.heartbeatTimer = setInterval(() => {
        if (ws.readyState !== 1) return;
        try {
          ws.send(encodeFrame(FRAME_TYPE.PING, 0, Buffer.from(String(Date.now()), 'utf8')));
        } catch (e) {}
      }, this._heartbeatIntervalMs);
      if (conn.heartbeatTimer && conn.heartbeatTimer.unref) conn.heartbeatTimer.unref();

      ws.on('message', (data) => {
        this._handleAgentFrame(tunnelId, conn, data);
      });

      ws.on('close', () => {
        if (this._connections.get(tunnelId) === conn) {
          this._teardownConnection(tunnelId, conn, new Error('Agente EdgeTunnel desconectado'));
        }
      });

      ws.on('error', () => {
        if (this._connections.get(tunnelId) === conn) {
          this._teardownConnection(tunnelId, conn, new Error('Error de socket en agente EdgeTunnel'));
        }
      });

      this.emit('tunnel_connected', { tunnelId, connectedAt: now });
    });

    return wss;
  }

  /**
   * Extrae `(tunnelId, token)` de cabeceras HTTP o query string del handshake WebSocket.
   * @param {any} req
   */
  _extractAuthFromRequest(req) {
    const headers = (req && req.headers) || {};
    let tunnelId = String(headers['x-tunnel-id'] || '').trim();
    let token = '';
    const authHeader = String(headers.authorization || '').trim();
    if (/^Bearer\s+/i.test(authHeader)) {
      token = authHeader.replace(/^Bearer\s+/i, '').trim();
    }
    if ((!tunnelId || !token) && req && typeof req.url === 'string') {
      try {
        const parsed = new URL(req.url, 'http://localhost');
        if (!tunnelId) tunnelId = String(parsed.searchParams.get('tunnelId') || '').trim();
        if (!token) token = String(parsed.searchParams.get('token') || '').trim();
      } catch (e) {}
    }
    return { tunnelId, token };
  }

  /**
   * Procesa un frame binario `ET1` recibido desde el agente remoto.
   * @param {string} tunnelId
   * @param {any} conn
   * @param {any} rawData
   */
  _handleAgentFrame(tunnelId, conn, rawData) {
    let frame;
    try {
      frame = decodeFrame(rawData);
    } catch (err) {
      return;
    }

    if (frame.type === FRAME_TYPE.PING) {
      conn.lastHeartbeatAt = new Date().toISOString();
      try { conn.ws.send(encodeFrame(FRAME_TYPE.PONG, 0, frame.payload)); } catch (e) {}
      return;
    }
    if (frame.type === FRAME_TYPE.PONG) {
      conn.lastHeartbeatAt = new Date().toISOString();
      return;
    }

    const stream = conn.streams.get(frame.streamId);
    if (!stream) return;

    if (frame.type === FRAME_TYPE.SYN) {
      try {
        const meta = JSON.parse(frame.payload.toString('utf8'));
        stream.status = Number(meta.status) || 200;
        stream.headers = sanitizeHttpHeaders(meta.headers);
        stream.gotSyn = true;
      } catch (err) {
        clearTimeout(stream.timer);
        conn.streams.delete(frame.streamId);
        stream.reject(new Error('Frame SYN de respuesta malformado'));
      }
      return;
    }

    if (frame.type === FRAME_TYPE.DATA) {
      if (stream.bodyBytes + frame.payload.length > MAX_RESPONSE_BODY_BYTES) {
        clearTimeout(stream.timer);
        conn.streams.delete(frame.streamId);
        try { conn.ws.send(encodeFrame(FRAME_TYPE.RST, frame.streamId, 'Response body too large')); } catch (e) {}
        stream.reject(new Error('Respuesta HTTP a través del túnel excede el límite de 16 MiB'));
        return;
      }
      const copy = Buffer.from(frame.payload);
      stream.chunks.push(copy);
      stream.bodyBytes += copy.length;
      this._stats.totalBytesIn += copy.length;
      return;
    }

    if (frame.type === FRAME_TYPE.FIN) {
      clearTimeout(stream.timer);
      conn.streams.delete(frame.streamId);
      const body = stream.chunks.length === 0
        ? Buffer.alloc(0)
        : (stream.chunks.length === 1 ? stream.chunks[0] : Buffer.concat(stream.chunks));
      stream.resolve({
        status: stream.gotSyn ? stream.status : 502,
        headers: stream.headers,
        body,
        bodyText: body.toString('utf8'),
        streamId: frame.streamId,
        tunnelId,
        durationMs: Date.now() - stream.startedAt
      });
      return;
    }

    if (frame.type === FRAME_TYPE.RST) {
      clearTimeout(stream.timer);
      conn.streams.delete(frame.streamId);
      const msg = frame.payload.toString('utf8') || 'Stream reiniciado por el agente EdgeTunnel';
      stream.reject(new Error(msg));
    }
  }

  /**
   * Limpia temporizadores y rechaza streams en vuelo cuando una conexión cae o es revocada.
   * @param {string} tunnelId
   * @param {any} conn
   * @param {Error} reason
   */
  _teardownConnection(tunnelId, conn, reason) {
    if (conn.heartbeatTimer) {
      clearInterval(conn.heartbeatTimer);
      conn.heartbeatTimer = null;
    }
    this._connections.delete(tunnelId);
    for (const [sid, st] of conn.streams.entries()) {
      clearTimeout(st.timer);
      conn.streams.delete(sid);
      st.reject(reason);
    }
    this.emit('tunnel_disconnected', { tunnelId });
  }

  /**
   * Reenvía una petición HTTP multiplexada a través del túnel WebSocket conectado.
   *
   * @param {string} tunnelId
   * @param {{
   *   method?: string,
   *   path?: string,
   *   headers?: Record<string, any>,
   *   body?: Buffer | string | null,
   *   timeoutMs?: number
   * }} reqSpec
   */
  forwardHttp(tunnelId, reqSpec = {}) {
    this._ensureLoaded();
    const rec = this.tunnels.get(tunnelId);
    if (!rec || rec.revoked) {
      return Promise.reject(new Error(`Túnel no encontrado o revocado: ${tunnelId}`));
    }
    const conn = this._connections.get(tunnelId);
    if (!conn || !conn.ws || conn.ws.readyState !== 1) {
      return Promise.reject(new Error(`Agente EdgeTunnel sin conexión activa para ${tunnelId}`));
    }
    if (conn.streams.size >= MAX_CONCURRENT_STREAMS) {
      return Promise.reject(new Error(`Límite de streams concurrentes alcanzado (${MAX_CONCURRENT_STREAMS})`));
    }

    const method = String(reqSpec.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '') || 'GET';
    const rawPath = String(reqSpec.path || '/');
    const reqPath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
    if (/[\r\n\0]/.test(reqPath)) {
      return Promise.reject(new Error('Ruta HTTP inválida en forwardHttp'));
    }
    const headers = sanitizeHttpHeaders(reqSpec.headers);
    const bodyBuf = reqSpec.body === null || reqSpec.body === undefined
      ? Buffer.alloc(0)
      : (Buffer.isBuffer(reqSpec.body) ? reqSpec.body : Buffer.from(String(reqSpec.body), 'utf8'));
    const timeoutMs = Math.max(500, Math.min(120000, Number(reqSpec.timeoutMs) || this._defaultStreamTimeoutMs));

    const streamId = conn.nextStreamId++;
    if (conn.nextStreamId > 0x7ffffff0) conn.nextStreamId = 1;

    this._stats.totalRequestsForwarded++;
    this._stats.totalBytesOut += bodyBuf.length;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (conn.streams.has(streamId)) {
          conn.streams.delete(streamId);
          try { conn.ws.send(encodeFrame(FRAME_TYPE.RST, streamId, 'Upstream tunnel timeout')); } catch (e) {}
          reject(new Error(`Timeout (${timeoutMs} ms) reenviando petición por túnel ${tunnelId}`));
        }
      }, timeoutMs);
      if (timer.unref) timer.unref();

      conn.streams.set(streamId, {
        resolve,
        reject,
        timer,
        startedAt: Date.now(),
        status: 502,
        headers: {},
        chunks: [],
        bodyBytes: 0,
        gotSyn: false
      });

      try {
        const synPayload = JSON.stringify({ method, path: reqPath, headers });
        conn.ws.send(encodeFrame(FRAME_TYPE.SYN, streamId, Buffer.from(synPayload, 'utf8')));
        for (let off = 0; off < bodyBuf.length; off += DATA_CHUNK_SIZE) {
          const slice = bodyBuf.subarray(off, Math.min(bodyBuf.length, off + DATA_CHUNK_SIZE));
          conn.ws.send(encodeFrame(FRAME_TYPE.DATA, streamId, slice));
        }
        conn.ws.send(encodeFrame(FRAME_TYPE.FIN, streamId));
      } catch (err) {
        clearTimeout(timer);
        conn.streams.delete(streamId);
        reject(err);
      }
    });
  }

  /** Cierra todas las conexiones activas (útil en apagado limpio o fin de tests). */
  closeAll() {
    for (const [id, conn] of Array.from(this._connections.entries())) {
      this._teardownConnection(id, conn, new Error('EdgeTunnelService detenido'));
      try { conn.ws.close(1001, 'Server shutting down'); } catch (e) {}
    }
  }
}

// ============================================================================
// CLIENT AGENT: EdgeTunnelClient (runs behind CGNAT / NAT, connects outbound)
// ============================================================================

class EdgeTunnelClient extends EventEmitter {
  /**
   * @param {{
   *   serverUrl: string,
   *   tunnelId: string,
   *   token: string,
   *   targetHost?: string,
   *   targetPort: number | string,
   *   heartbeatMs?: number,
   *   requestTimeoutMs?: number
   * }} opts
   */
  constructor(opts) {
    super();
    if (!opts || !opts.serverUrl || !opts.tunnelId || !opts.token) {
      throw new Error('EdgeTunnelClient requiere serverUrl, tunnelId y token');
    }
    const { targetHost, targetPort } = validateTunnelTarget(opts.targetHost || '127.0.0.1', opts.targetPort);
    this.serverUrl = String(opts.serverUrl).trim();
    this.tunnelId = String(opts.tunnelId).trim();
    this.token = String(opts.token).trim();
    this.targetHost = targetHost;
    this.targetPort = targetPort;
    this.heartbeatMs = Math.max(5000, Number(opts.heartbeatMs) || 25000);
    this.requestTimeoutMs = Math.max(1000, Number(opts.requestTimeoutMs) || 30000);
    /** @type {any} */
    this.ws = null;
    /** @type {Map<number, { method: string, path: string, headers: Record<string, string>, chunks: Buffer[], bodyBytes: number }>} */
    this._incoming = new Map();
    /** @type {ReturnType<typeof setInterval> | null} */
    this._hbTimer = null;
    this.connected = false;
  }

  /** Abre la conexión WebSocket saliente hacia el servidor EdgeTunnel de Culkibo. */
  connect() {
    const { WebSocket } = getWs();
    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = new WebSocket(this.serverUrl, {
        headers: {
          Authorization: `Bearer ${this.token}`,
          'X-Tunnel-Id': this.tunnelId
        }
      });
      this.ws = ws;

      ws.once('open', () => {
        this.connected = true;
        this._hbTimer = setInterval(() => {
          if (ws.readyState === 1) {
            try { ws.send(encodeFrame(FRAME_TYPE.PING, 0, Buffer.from(String(Date.now()), 'utf8'))); } catch (e) {}
          }
        }, this.heartbeatMs);
        if (this._hbTimer && this._hbTimer.unref) this._hbTimer.unref();
        this.emit('connected');
        if (!settled) {
          settled = true;
          resolve(true);
        }
      });

      ws.on('message', (raw) => {
        this._onFrame(raw);
      });

      ws.on('close', (code, reasonBuf) => {
        this.connected = false;
        if (this._hbTimer) {
          clearInterval(this._hbTimer);
          this._hbTimer = null;
        }
        this._incoming.clear();
        const reason = reasonBuf ? reasonBuf.toString('utf8') : '';
        this.emit('close', { code, reason });
        if (!settled) {
          settled = true;
          reject(new Error(`EdgeTunnel rechazado (close ${code}${reason ? `: ${reason}` : ''})`));
        }
      });

      ws.on('error', (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        } else {
          this.emit('error', err);
        }
      });
    });
  }

  /** @param {any} raw */
  _onFrame(raw) {
    let frame;
    try {
      frame = decodeFrame(raw);
    } catch (e) {
      return;
    }

    if (frame.type === FRAME_TYPE.PING) {
      try { this.ws && this.ws.send(encodeFrame(FRAME_TYPE.PONG, 0, frame.payload)); } catch (e) {}
      return;
    }
    if (frame.type === FRAME_TYPE.PONG) {
      this.emit('pong');
      return;
    }
    if (frame.type === FRAME_TYPE.RST) {
      this._incoming.delete(frame.streamId);
      return;
    }

    if (frame.type === FRAME_TYPE.SYN) {
      try {
        const meta = JSON.parse(frame.payload.toString('utf8'));
        this._incoming.set(frame.streamId, {
          method: String(meta.method || 'GET'),
          path: String(meta.path || '/'),
          headers: sanitizeHttpHeaders(meta.headers),
          chunks: [],
          bodyBytes: 0
        });
      } catch (err) {
        try { this.ws && this.ws.send(encodeFrame(FRAME_TYPE.RST, frame.streamId, 'Invalid SYN payload')); } catch (e) {}
      }
      return;
    }

    if (frame.type === FRAME_TYPE.DATA) {
      const st = this._incoming.get(frame.streamId);
      if (!st) return;
      if (st.bodyBytes + frame.payload.length > MAX_RESPONSE_BODY_BYTES) {
        this._incoming.delete(frame.streamId);
        try { this.ws && this.ws.send(encodeFrame(FRAME_TYPE.RST, frame.streamId, 'Request body limit exceeded')); } catch (e) {}
        return;
      }
      st.chunks.push(Buffer.from(frame.payload));
      st.bodyBytes += frame.payload.length;
      return;
    }

    if (frame.type === FRAME_TYPE.FIN) {
      const st = this._incoming.get(frame.streamId);
      if (!st) return;
      this._incoming.delete(frame.streamId);
      const body = st.chunks.length === 0
        ? Buffer.alloc(0)
        : (st.chunks.length === 1 ? st.chunks[0] : Buffer.concat(st.chunks));
      this._proxyToLocal(frame.streamId, st.method, st.path, st.headers, body);
    }
  }

  /**
   * Ejecuta la petición HTTP contra el servicio local (`targetHost:targetPort`) y transmite
   * la respuesta multiplexada por `streamId`.
   * @param {number} streamId
   * @param {string} method
   * @param {string} reqPath
   * @param {Record<string, string>} headers
   * @param {Buffer} body
   */
  _proxyToLocal(streamId, method, reqPath, headers, body) {
    const reqHeaders = { ...headers };
    if (body.length > 0 && !reqHeaders['content-length']) {
      reqHeaders['content-length'] = String(body.length);
    }

    const req = http.request(
      {
        hostname: this.targetHost,
        port: this.targetPort,
        path: reqPath.startsWith('/') ? reqPath : `/${reqPath}`,
        method,
        headers: reqHeaders,
        timeout: this.requestTimeoutMs
      },
      (res) => {
        const ws = this.ws;
        if (!ws || ws.readyState !== 1) {
          res.resume();
          return;
        }
        const synMeta = JSON.stringify({
          status: res.statusCode || 200,
          headers: sanitizeHttpHeaders(res.headers)
        });
        try {
          ws.send(encodeFrame(FRAME_TYPE.SYN, streamId, Buffer.from(synMeta, 'utf8')));
        } catch (e) {
          res.resume();
          return;
        }
        res.on('data', (chunk) => {
          if (!ws || ws.readyState !== 1) return;
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          for (let off = 0; off < buf.length; off += DATA_CHUNK_SIZE) {
            try {
              ws.send(encodeFrame(FRAME_TYPE.DATA, streamId, buf.subarray(off, Math.min(buf.length, off + DATA_CHUNK_SIZE))));
            } catch (e) {}
          }
        });
        res.on('end', () => {
          if (ws && ws.readyState === 1) {
            try { ws.send(encodeFrame(FRAME_TYPE.FIN, streamId)); } catch (e) {}
          }
        });
        res.on('error', (err) => {
          if (ws && ws.readyState === 1) {
            try { ws.send(encodeFrame(FRAME_TYPE.RST, streamId, err.message || 'Local upstream error')); } catch (e) {}
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Timeout contactando servicio local ${this.targetHost}:${this.targetPort}`));
    });
    req.on('error', (err) => {
      if (this.ws && this.ws.readyState === 1) {
        try { this.ws.send(encodeFrame(FRAME_TYPE.RST, streamId, err.message || 'Local connect error')); } catch (e) {}
      }
    });

    if (body.length > 0) req.end(body);
    else req.end();
  }

  close() {
    if (this._hbTimer) {
      clearInterval(this._hbTimer);
      this._hbTimer = null;
    }
    this._incoming.clear();
    this.connected = false;
    if (this.ws) {
      try { this.ws.close(1000, 'Client closing'); } catch (e) {}
      this.ws = null;
    }
  }
}

const instance = /** @type {any} */ (new EdgeTunnelService());
instance.EdgeTunnelService = EdgeTunnelService;
instance.EdgeTunnelClient = EdgeTunnelClient;
instance.FRAME_TYPE = FRAME_TYPE;
instance.encodeFrame = encodeFrame;
instance.decodeFrame = decodeFrame;
instance.validateTunnelTarget = validateTunnelTarget;

module.exports = instance;
