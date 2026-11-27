const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * Zero-Config Fleet WireGuard L3 Private Mesh (`10.88.0.0/24`) — Cero Dependencias, Cero Shell.
 *
 * Inspirado en Headscale / Netbird, construido 100% con `node:crypto` nativo (`x25519` + `aes-256-gcm`):
 *  - Genera pares de claves Curve25519 compatibles byte-a-byte con `wg genkey` / `wg pubkey`
 *    (claves crudas de 32 bytes codificadas en Base64 estándar de 44 caracteres).
 *  - Almacena `fleet-mesh.json` de forma atómica (`0o600`) en `CULKIBO_DATA_DIR/data/` con
 *    TODAS las claves privadas cifradas en reposo mediante AES-256-GCM y AAD contextual
 *    (`wg:<nodeId>`) usando `.fleet-mesh.key` (`0o600`, `flag: 'wx'`).
 *  - JAMÁS expone claves privadas en claro en `getStatus()`, `planMesh()`, `rotatePeerKey()`,
 *    ni en disco (`privateKeyEncrypted: true`, solo `publicKey` + huella SHA-256).
 *  - Incluye guardia anti-bypass de UFW por reglas NAT de Docker (`kamal#1856`) recomendando
 *    vincular BDs a `10.88.0.0/24` o `127.0.0.1` en lugar de `0.0.0.0`.
 */

const MESH_CIDR = '10.88.0.0/24';
const MESH_PREFIX = '10.88.0.';
const DEFAULT_INTERFACE = 'wg0';
const DEFAULT_LISTEN_PORT = 51820;
const DEFAULT_DB_PORTS = Object.freeze([5432, 3306, 6379, 27017, 9000, 8123]);
const NODE_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const SAFE_ENDPOINT_HOST_RE = /^[a-zA-Z0-9._:-]{1,253}$/;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Resuelve el directorio de datos respetando `CULKIBO_DATA_DIR`.
 * @param {string | null} [overrideDir]
 * @returns {string}
 */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/** @param {string} raw */
function sanitizeNodeId(raw) {
  const clean = String(raw || '').trim();
  if (!NODE_ID_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    throw new Error(`Identificador de nodo WireGuard inválido: "${clean.slice(0, 60)}"`);
  }
  return clean;
}

/** @param {string} publicKey */
function computeKeyFingerprint(publicKey) {
  const hash = crypto.createHash('sha256').update(String(publicKey || ''), 'utf8').digest('hex');
  return `wg:${hash.slice(0, 16)}`;
}

/**
 * Genera un par de claves WireGuard Curve25519 real mediante `crypto.generateKeyPairSync('x25519')`,
 * extrayendo los 32 bytes crudos `d` (privada) y `x` (pública) en Base64 estándar de 44 caracteres
 * (formato idéntico a `wg genkey` / `wg pubkey`).
 *
 * @returns {{ privateKey: string, publicKey: string, fingerprint: string, algorithm: 'x25519' }}
 */
function generateWireGuardKeyPair() {
  const { publicKey: pubObj, privateKey: privObj } = crypto.generateKeyPairSync('x25519');
  const privJwk = /** @type {{ d?: string, x?: string }} */ (privObj.export({ format: 'jwk' }));
  const pubJwk = /** @type {{ x?: string }} */ (pubObj.export({ format: 'jwk' }));

  const rawPriv = Buffer.from(String(privJwk.d || ''), 'base64url');
  const rawPub = Buffer.from(String(pubJwk.x || ''), 'base64url');
  if (rawPriv.length !== 32 || rawPub.length !== 32) {
    throw new Error(`Longitud de clave x25519 inesperada (priv=${rawPriv.length}, pub=${rawPub.length})`);
  }

  const privateKey = rawPriv.toString('base64');
  const publicKey = rawPub.toString('base64');
  return {
    privateKey,
    publicKey,
    fingerprint: computeKeyFingerprint(publicKey),
    algorithm: 'x25519'
  };
}

/**
 * Cifra una clave privada WireGuard en reposo con AES-256-GCM y AAD contextual (`wg:<nodeId>`).
 * @param {string} plaintextKey
 * @param {Buffer} masterKey
 * @param {string} nodeId
 * @returns {string}
 */
function encryptPrivateKey(plaintextKey, masterKey, nodeId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(`wg:${nodeId}`, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plaintextKey), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

/**
 * Descifra una clave privada WireGuard únicamente en memoria cuando se verifica integridad interna.
 * @param {string} blob
 * @param {Buffer} masterKey
 * @param {string} nodeId
 * @returns {string}
 */
function decryptPrivateKey(blob, masterKey, nodeId) {
  const parts = String(blob || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Formato de clave privada WireGuard cifrada inválido');
  }
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAAD(Buffer.from(`wg:${nodeId}`, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * Renderiza una plantilla segura `wg0.conf` para un nodo del mesh.
 * Jamás inserta claves privadas reales: siempre emite un marcador redactado seguro.
 *
 * @param {{ nodeId: string, name: string, meshIp: string, publicKey: string, listenPort?: number, endpoint?: string | null }} selfPeer
 * @param {Array<{ nodeId: string, name: string, meshIp: string, publicKey: string, listenPort?: number, endpoint?: string | null }>} allPeers
 * @param {{ includeRedactedTemplate?: boolean, privateKeyPlaceholder?: string }} [opts]
 * @returns {string}
 */
function renderWgConfig(selfPeer, allPeers = [], opts = {}) {
  const listenPort = Number(selfPeer.listenPort) || DEFAULT_LISTEN_PORT;
  const placeholder = opts.includeRedactedTemplate === false
    ? '[REDACTED_PRIVATE_KEY]'
    : String(opts.privateKeyPlaceholder || '[REDACT_ON_API]');

  const lines = [
    `# Culkibo WireGuard Fleet Mesh — ${selfPeer.name} (${selfPeer.nodeId})`,
    `# CIDR: ${MESH_CIDR} | Curve25519 | Zero-Shell Provisioning`,
    '[Interface]',
    `Address = ${selfPeer.meshIp}/24`,
    `ListenPort = ${listenPort}`,
    `PrivateKey = ${placeholder}`,
    'SaveConfig = false',
    ''
  ];

  const remotePeers = (Array.isArray(allPeers) ? allPeers : []).filter((p) => p && p.nodeId !== selfPeer.nodeId);
  for (const peer of remotePeers) {
    lines.push(`# Peer: ${peer.name} (${peer.nodeId})`);
    lines.push('[Peer]');
    lines.push(`PublicKey = ${peer.publicKey}`);
    lines.push(`AllowedIPs = ${peer.meshIp}/32`);
    if (peer.endpoint) {
      lines.push(`Endpoint = ${peer.endpoint}`);
    }
    lines.push('PersistentKeepalive = 25');
    lines.push('');
  }

  return lines.join('\n').trimEnd() + '\n';
}

/**
 * Genera reglas seguras de firewall (UFW + nftables) que abren únicamente WireGuard UDP
 * y permiten puertos de bases de datos EXCLUSIVAMENTE sobre `wg0` (`10.88.0.0/24`),
 * cerrando el bypass de Docker iptables NAT (`kamal#1856`).
 *
 * @param {{ interfaceName?: string, listenPort?: number, cidr?: string, dbPorts?: number[] }} [opts]
 */
function renderFirewallPlan(opts = {}) {
  const iface = String(opts.interfaceName || DEFAULT_INTERFACE).replace(/[^a-zA-Z0-9_-]/g, '') || DEFAULT_INTERFACE;
  const listenPort = Math.min(65535, Math.max(1024, Number(opts.listenPort) || DEFAULT_LISTEN_PORT));
  const cidr = String(opts.cidr || MESH_CIDR);
  const dbPorts = Array.isArray(opts.dbPorts) && opts.dbPorts.length > 0
    ? opts.dbPorts.map((p) => Number(p)).filter((p) => Number.isInteger(p) && p > 0 && p < 65536)
    : [...DEFAULT_DB_PORTS];

  const ufwRules = [
    `ufw allow ${listenPort}/udp comment 'Culkibo WireGuard Fleet Mesh'`,
    ...dbPorts.map((p) => `ufw allow in on ${iface} from ${cidr} to any port ${p} proto tcp comment 'Culkibo Mesh DB ${p}'`),
    ...dbPorts.map((p) => `ufw deny ${p}/tcp comment 'Block public DB port ${p} (kamal#1856)'`)
  ];

  const ufwArgvs = [
    { program: 'ufw', args: ['allow', `${listenPort}/udp`, 'comment', 'Culkibo WireGuard Fleet Mesh'] },
    ...dbPorts.map((p) => ({
      program: 'ufw',
      args: ['allow', 'in', 'on', iface, 'from', cidr, 'to', 'any', 'port', String(p), 'proto', 'tcp']
    })),
    ...dbPorts.map((p) => ({
      program: 'ufw',
      args: ['deny', `${p}/tcp`]
    }))
  ];

  const nftablesSnippet = [
    'table inet culkibo_mesh {',
    '  chain input {',
    '    type filter hook input priority 0; policy accept;',
    `    udp dport ${listenPort} accept`,
    `    iifname "${iface}" ip saddr ${cidr} tcp dport { ${dbPorts.join(', ')} } accept`,
    `    iifname != "${iface}" iifname != "lo" tcp dport { ${dbPorts.join(', ')} } drop`,
    '  }',
    '}'
  ].join('\n');

  return {
    interfaceName: iface,
    listenPort,
    cidr,
    protectedDbPorts: dbPorts,
    blocksPublicDbPorts: true,
    dockerUserChainNote: 'Bind Docker DB containers to 127.0.0.1 or the wg0 mesh IP (never 0.0.0.0) so Docker NAT rules cannot bypass UFW (kamal#1856).',
    ufwRules,
    ufwArgvs,
    nftablesSnippet
  };
}

class FleetMeshService {
  /**
   * @param {{ dataDir?: string | null, serverFleetManager?: any }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._fleetManagerOverride = opts.serverFleetManager || null;
    /** @type {Buffer | null} */
    this._masterKey = null;
    this._loaded = false;
    /** @type {{ version: number, cidr: string, interfaceName: string, listenPort: number, peers: Record<string, any> }} */
    this.state = {
      version: 1,
      cidr: MESH_CIDR,
      interfaceName: DEFAULT_INTERFACE,
      listenPort: DEFAULT_LISTEN_PORT,
      peers: Object.create(null)
    };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'fleet-mesh.json');
  }

  get keyFile() {
    return path.join(this.dataDir, '.fleet-mesh.key');
  }

  _getFleetManager() {
    if (this._fleetManagerOverride) return this._fleetManagerOverride;
    try {
      return require('./serverFleetManager');
    } catch (e) {
      return null;
    }
  }

  _ensureMasterKey() {
    if (this._masterKey) return this._masterKey;
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.keyFile)) {
      const buf = Buffer.from(fs.readFileSync(this.keyFile, 'utf8').trim(), 'hex');
      if (buf.length === 32) {
        this._masterKey = buf;
        return this._masterKey;
      }
    }
    const rawKey = crypto.randomBytes(32);
    try {
      fs.writeFileSync(this.keyFile, rawKey.toString('hex'), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      this._masterKey = rawKey;
    } catch (err) {
      if (err && err.code === 'EEXIST') {
        this._masterKey = Buffer.from(fs.readFileSync(this.keyFile, 'utf8').trim(), 'hex');
      } else {
        throw err;
      }
    }
    return this._masterKey;
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && parsed.peers && typeof parsed.peers === 'object') {
          const cleanPeers = Object.create(null);
          for (const [nid, peer] of Object.entries(parsed.peers)) {
            if (!FORBIDDEN_PROTO_KEYS.has(nid) && peer && typeof peer === 'object') {
              cleanPeers[nid] = peer;
            }
          }
          this.state = {
            version: 1,
            cidr: String(parsed.cidr || MESH_CIDR),
            interfaceName: String(parsed.interfaceName || DEFAULT_INTERFACE),
            listenPort: Number(parsed.listenPort) || DEFAULT_LISTEN_PORT,
            peers: cleanPeers
          };
          return;
        }
      } catch (e) {}
    }
    this.state = {
      version: 1,
      cidr: MESH_CIDR,
      interfaceName: DEFAULT_INTERFACE,
      listenPort: DEFAULT_LISTEN_PORT,
      peers: Object.create(null)
    };
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
   * Resuelve la lista normalizada de servidores de flota a sincronizar en el mesh.
   * @param {any[] | null | undefined} servers
   */
  _resolveInputServers(servers) {
    /** @type {any[]} */
    let rawList = [];
    if (Array.isArray(servers) && servers.length > 0) {
      rawList = servers;
    } else {
      const fm = this._getFleetManager();
      if (fm && typeof fm.listServers === 'function') {
        try {
          const listed = fm.listServers();
          if (Array.isArray(listed) && listed.length > 0) rawList = listed;
        } catch (e) {}
      }
    }
    if (rawList.length === 0) {
      rawList = [{ id: 'local', name: 'Local Server (Primary)', host: '127.0.0.1', isLocal: true, status: 'online' }];
    }

    return rawList.map((srv, idx) => {
      const rawId = srv && (srv.id || srv.nodeId) ? String(srv.id || srv.nodeId) : `node-${idx + 1}`;
      const nodeId = sanitizeNodeId(rawId);
      const isLocal = Boolean(srv && (srv.isLocal || nodeId === 'local' || srv.role === 'control-plane'));
      const rawHost = String((srv && (srv.publicIp || srv.host || srv.ip)) || '').trim();
      const safeHost = rawHost && SAFE_ENDPOINT_HOST_RE.test(rawHost) && !/^(127\.|localhost$)/i.test(rawHost)
        ? rawHost
        : null;
      const listenPort = Number(srv && srv.listenPort) || DEFAULT_LISTEN_PORT;
      const endpoint = srv && srv.endpoint
        ? String(srv.endpoint).trim()
        : (safeHost ? `${safeHost}:${listenPort}` : null);
      return {
        nodeId,
        name: String((srv && srv.name) || nodeId).slice(0, 80),
        role: isLocal ? 'control-plane' : 'worker',
        endpoint,
        listenPort,
        status: String((srv && srv.status) || 'ready')
      };
    });
  }

  /** Asigna la menor IP determinista libre en `10.88.0.1..254` (`local`/control-plane siempre `.1`). */
  _allocateMeshIp(nodeId, role, usedIps) {
    if (role === 'control-plane' || nodeId === 'local') {
      const primary = `${MESH_PREFIX}1`;
      if (!usedIps.has(primary)) {
        usedIps.add(primary);
        return primary;
      }
    }
    for (let octet = 2; octet <= 254; octet++) {
      const candidate = `${MESH_PREFIX}${octet}`;
      if (!usedIps.has(candidate)) {
        usedIps.add(candidate);
        return candidate;
      }
    }
    throw new Error(`Espacio de direcciones WireGuard agotado en ${MESH_CIDR}`);
  }

  /** Proyección pública 100% segura de un peer (jamás incluye `encryptedPrivateKey` ni clave en claro). */
  _sanitizePeer(peer) {
    return {
      nodeId: peer.nodeId,
      name: peer.name,
      meshIp: peer.meshIp,
      publicKey: peer.publicKey,
      keyFingerprint: peer.keyFingerprint || computeKeyFingerprint(peer.publicKey),
      privateKeyEncrypted: Boolean(peer.encryptedPrivateKey),
      keyVersion: Number(peer.keyVersion) || 1,
      endpoint: peer.endpoint || null,
      listenPort: Number(peer.listenPort) || DEFAULT_LISTEN_PORT,
      role: peer.role || 'worker',
      keyRotatedAt: peer.keyRotatedAt || peer.createdAt || null,
      status: peer.status || 'ready'
    };
  }

  /**
   * Sincroniza peers desde `serverFleetManager` (o lista explícita), generando claves
   * `x25519` cifradas con AES-256-GCM para nuevos nodos y asignando IPs `10.88.0.x`.
   * @param {any[] | null | undefined} [servers]
   * @param {{ persist?: boolean, pruneMissing?: boolean }} [opts]
   */
  _syncPeers(servers, opts = {}) {
    this._ensureLoaded();
    const persist = opts.persist !== false;
    const normalized = this._resolveInputServers(servers);
    const desiredIds = new Set(normalized.map((s) => s.nodeId));

    /** @type {Set<string>} */
    const usedIps = new Set();
    for (const peer of Object.values(this.state.peers)) {
      if (peer && peer.meshIp) usedIps.add(peer.meshIp);
    }

    /** @type {string[]} */
    const added = [];
    /** @type {string[]} */
    const updated = [];
    /** @type {string[]} */
    const removed = [];

    /** @type {Record<string, any>} */
    const workingPeers = Object.create(null);
    for (const [k, v] of Object.entries(this.state.peers)) {
      workingPeers[k] = { ...v };
    }

    let dirty = false;
    for (const srv of normalized) {
      const existing = workingPeers[srv.nodeId];
      if (!existing) {
        const masterKey = persist ? this._ensureMasterKey() : crypto.randomBytes(32);
        const kp = generateWireGuardKeyPair();
        const meshIp = this._allocateMeshIp(srv.nodeId, srv.role, usedIps);
        const nowIso = new Date().toISOString();
        workingPeers[srv.nodeId] = {
          nodeId: srv.nodeId,
          name: srv.name,
          meshIp,
          publicKey: kp.publicKey,
          keyFingerprint: kp.fingerprint,
          encryptedPrivateKey: encryptPrivateKey(kp.privateKey, masterKey, srv.nodeId),
          keyVersion: 1,
          endpoint: srv.endpoint,
          listenPort: srv.listenPort,
          role: srv.role,
          status: srv.status,
          createdAt: nowIso,
          keyRotatedAt: nowIso
        };
        added.push(srv.nodeId);
        dirty = true;
      } else {
        const changed = existing.name !== srv.name
          || existing.endpoint !== srv.endpoint
          || existing.listenPort !== srv.listenPort
          || existing.role !== srv.role
          || existing.status !== srv.status;
        if (changed) {
          existing.name = srv.name;
          existing.endpoint = srv.endpoint;
          existing.listenPort = srv.listenPort;
          existing.role = srv.role;
          existing.status = srv.status;
          updated.push(srv.nodeId);
          dirty = true;
        }
      }
    }

    for (const existingId of Object.keys(workingPeers)) {
      if (!desiredIds.has(existingId)) {
        if (opts.pruneMissing !== false) {
          removed.push(existingId);
          if (persist) {
            delete workingPeers[existingId];
            dirty = true;
          }
        }
      }
    }

    if (persist && dirty) {
      this.state.peers = workingPeers;
      this._save();
    }

    const activePeers = Object.values(workingPeers)
      .filter((p) => p && (opts.pruneMissing === false || desiredIds.has(p.nodeId)))
      .sort((a, b) => {
        const octA = Number(String(a.meshIp || '').split('.')[3]) || 999;
        const octB = Number(String(b.meshIp || '').split('.')[3]) || 999;
        return octA - octB;
      });

    return {
      peers: activePeers,
      diff: { added, updated, removed }
    };
  }

  /**
   * Devuelve el estado actual del WireGuard Fleet Mesh (100% libre de claves privadas).
   * @param {any[] | null} [servers]
   */
  getStatus(servers = null) {
    const { peers } = this._syncPeers(servers, { persist: true, pruneMissing: Array.isArray(servers) });
    const safePeers = peers.map((p) => this._sanitizePeer(p));
    return {
      ok: true,
      cidr: this.state.cidr,
      interfaceName: this.state.interfaceName,
      listenPort: this.state.listenPort,
      encryption: 'x25519+aes-256-gcm',
      peerCount: safePeers.length,
      peers: safePeers,
      firewallGuard: {
        blocksPublicDbPorts: true,
        protectedDbPorts: [...DEFAULT_DB_PORTS],
        ufwBypassWarning: 'Docker iptables NAT rules bypass UFW on 0.0.0.0-published DB ports (kamal#1856). Bind managed databases to 127.0.0.1 or 10.88.0.0/24 (wg0).'
      }
    };
  }

  /**
   * Planifica la configuración WireGuard (`wg0.conf` redactado por nodo), reglas UFW/nftables
   * y diff de topología de peers sin exponer jamás claves privadas.
   *
   * @param {any[] | null} [servers]
   * @param {{ dryRun?: boolean, includeRedactedTemplate?: boolean }} [opts]
   */
  planMesh(servers = null, opts = {}) {
    const dryRun = opts.dryRun !== false;
    const includeRedactedTemplate = opts.includeRedactedTemplate !== false;
    const { peers, diff } = this._syncPeers(servers, { persist: !dryRun });
    const safePeers = peers.map((p) => this._sanitizePeer(p));

    const wgConfigs = safePeers.map((peer) => ({
      nodeId: peer.nodeId,
      name: peer.name,
      meshIp: peer.meshIp,
      interfaceName: this.state.interfaceName,
      config: renderWgConfig(peer, safePeers, {
        includeRedactedTemplate,
        privateKeyPlaceholder: '[REDACT_ON_API]'
      })
    }));

    const firewallPlan = renderFirewallPlan({
      interfaceName: this.state.interfaceName,
      listenPort: this.state.listenPort,
      cidr: this.state.cidr
    });

    return {
      ok: true,
      dryRun,
      cidr: this.state.cidr,
      interfaceName: this.state.interfaceName,
      listenPort: this.state.listenPort,
      peerCount: safePeers.length,
      peers: safePeers,
      diff,
      wgConfigs,
      firewallPlan
    };
  }

  /**
   * Rota el par de claves `x25519` de un peer con `dryRun: true` por defecto.
   * En `dryRun: false` cifra la nueva clave privada con AES-256-GCM, incrementa `keyVersion`
   * y guarda atómicamente en `fleet-mesh.json` sin exponer jamás la clave privada.
   *
   * @param {string} nodeId
   * @param {{ dryRun?: boolean, servers?: any[] }} [opts]
   */
  rotatePeerKey(nodeId, opts = {}) {
    const cleanId = sanitizeNodeId(nodeId);
    const dryRun = opts.dryRun !== false;
    this._ensureLoaded();

    if (!this.state.peers[cleanId]) {
      this._syncPeers(opts.servers || null, { persist: !dryRun });
    }
    const existing = this.state.peers[cleanId];
    if (!existing) {
      const err = new Error(`Peer WireGuard no encontrado en el mesh: "${cleanId}"`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    const nextKp = generateWireGuardKeyPair();
    const oldPublicKey = existing.publicKey;
    const oldFingerprint = existing.keyFingerprint || computeKeyFingerprint(oldPublicKey);
    const currentKeyVersion = Number(existing.keyVersion) || 1;
    const nextKeyVersion = currentKeyVersion + 1;
    const affectedPeers = Object.keys(this.state.peers).filter((id) => id !== cleanId);

    const rolloutSteps = [
      `1. Write encrypted wg0 private key for ${cleanId} (${existing.meshIp}) via SSH stdin (mode 0600, 0 shell argv exposure).`,
      `2. Update PublicKey=${nextKp.publicKey} on ${affectedPeers.length} remote peer(s) using wg syncconf wg0.`,
      `3. Verify handshake freshness on ${existing.meshIp} before pruning old key version v${currentKeyVersion}.`
    ];

    if (dryRun) {
      return {
        ok: true,
        dryRun: true,
        rotated: false,
        nodeId: cleanId,
        meshIp: existing.meshIp,
        currentKeyVersion,
        nextKeyVersion,
        oldPublicKey,
        oldFingerprint,
        previewNewPublicKey: nextKp.publicKey,
        previewNewFingerprint: nextKp.fingerprint,
        privateKeyEncrypted: true,
        affectedPeers,
        rolloutSteps
      };
    }

    const masterKey = this._ensureMasterKey();
    const nowIso = new Date().toISOString();
    existing.publicKey = nextKp.publicKey;
    existing.keyFingerprint = nextKp.fingerprint;
    existing.encryptedPrivateKey = encryptPrivateKey(nextKp.privateKey, masterKey, cleanId);
    existing.keyVersion = nextKeyVersion;
    existing.keyRotatedAt = nowIso;
    this._save();

    return {
      ok: true,
      dryRun: false,
      rotated: true,
      nodeId: cleanId,
      meshIp: existing.meshIp,
      keyVersion: nextKeyVersion,
      keyRotatedAt: nowIso,
      oldPublicKey,
      oldFingerprint,
      newPublicKey: nextKp.publicKey,
      newFingerprint: nextKp.fingerprint,
      privateKeyEncrypted: true,
      affectedPeers,
      rolloutSteps
    };
  }
}

const instance = /** @type {any} */ (new FleetMeshService());
instance.FleetMeshService = FleetMeshService;
instance.MESH_CIDR = MESH_CIDR;
instance.generateWireGuardKeyPair = generateWireGuardKeyPair;
instance.renderWgConfig = renderWgConfig;
instance.renderFirewallPlan = renderFirewallPlan;
instance.encryptPrivateKey = encryptPrivateKey;
instance.decryptPrivateKey = decryptPrivateKey;
module.exports = instance;
