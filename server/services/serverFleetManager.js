const { execFile, spawn } = require('child_process');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const {
  isMetadataIp,
  extractEmbeddedIPv4,
  atomicWriteJsonSync,
  loadJsonWithBackupSync,
  assertContainedPath
} = require('./ssrfGuard');

/** @type {any} */
let _dnsPromises = null;
function getDnsPromises() {
  if (!_dnsPromises) _dnsPromises = require('dns').promises;
  return _dnsPromises;
}

/** @type {any} */
let _auditLogger = null;
function getAuditLogger() {
  if (!_auditLogger) {
    try { _auditLogger = require('./auditLogger'); } catch (e) {}
  }
  return _auditLogger;
}

const DEFAULT_DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');

const LOCAL_SERVER_ID = 'local';

const DEFAULTS = Object.freeze({
  sshPort: 22,
  sshUser: 'root',
  dockerSocketPath: '/var/run/docker.sock',
  caddyAdminPort: 2019,
  region: 'default',
  teamId: 'team_default',
  hostKeyPolicy: 'tofu',
  connectTimeoutSec: 10,
  probeTimeoutMs: 15000,
  probeTtlMs: 15000,
  tunnelConnectTimeoutMs: 15000,
  tunnelIdleMs: 60000,
  monitorIntervalMs: 60000,
  dnsTimeoutMs: 5000,
  remotePortMin: 30000,
  remotePortMax: 39999
});

// Strict allowlists (reject, never escape or interpolate into shell strings)
const SERVER_ID_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const TEAM_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const SSH_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const DOCKER_SOCKET_RE = /^\/[a-zA-Z0-9._/-]{1,180}$/;
const DOCKER_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.\-/:]*$/;
const DOCKER_SINCE_RE = /^(?:\d{1,6}[smhd]|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)$/;
const DOCKER_WORKDIR_RE = /^\/[a-zA-Z0-9._/-]{1,256}$/;
const DOCKER_USER_RE = /^[a-zA-Z0-9_.:-]{1,64}$/;
const DOCKER_ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const REGION_RE = /^[a-z0-9_-]{1,32}$/;
const TAG_RE = /^[a-z0-9._:-]{1,32}$/;
const STALE_SOCKET_RE = /^ck-[a-f0-9]{10}\.sock$/;
const RFC1123_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const HOST_FORBIDDEN_RE = /[\0\r\n\s;|&`$<>()'"\\/@%#?,!*=]/;
const CONTROL_CHAR_RE = /[\0\r\n]/;
const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}=?$/;
const BASE64_STRICT_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const VALID_MAINTENANCE_STATES = new Set(['active', 'draining', 'maintenance']);
const VALID_PLACEMENT_STRATEGIES = new Set(['balanced', 'most-free-ram', 'least-loaded', 'lowest-latency']);
const BOOTSTRAP_SENTINEL = 'CULKIBO_BOOTSTRAP_EOF';

const NON_RETRYABLE_TUNNEL_CODES = new Set([
  'HOST_KEY_MISMATCH',
  'SSRF_BLOCKED',
  'SERVER_NOT_FOUND',
  'KEY_NOT_FOUND',
  'FLEET_KEY_MISSING',
  'FLEET_KEY_CORRUPT',
  'CRYPTO_DECRYPT_FAILED',
  'ABORTED',
  'SERVER_IN_MAINTENANCE',
  'LOCAL_SERVER_IMMUTABLE',
  'INVALID_DOCKER_REF',
  'INVALID_EXEC_COMMAND',
  'INVALID_INPUT',
  'INVALID_HOST',
  'INVALID_PORT',
  'INVALID_USER'
]);

const TRANSIENT_TUNNEL_ERROR_RE = /cannot connect to the docker daemon|broken pipe|connection reset|socket hang up|unexpected eof|econnrefused|econnreset|epipe|etimedout|connection closed by remote host|administratively prohibited/i;

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.com',
  'instance-data',
  'instance-data.ec2.internal'
]);

/** Preferred SSH host-key algorithm order (DSA ssh-dss is explicitly excluded). */
const ALLOWED_SSH_KEY_TYPES = [
  'ssh-ed25519',
  'sk-ssh-ed25519@openssh.com',
  'ecdsa-sha2-nistp521',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp256',
  'sk-ecdsa-sha2-nistp256@openssh.com',
  'ssh-rsa'
];
const ALLOWED_SSH_KEY_TYPE_SET = new Set(ALLOWED_SSH_KEY_TYPES);

/**
 * Static constant read-only POSIX probe executed in a single SSH roundtrip.
 * ZERO user input is ever interpolated into this command.
 * Compatible with POSIX /bin/sh, dash, ash, bash, and zsh.
 */
const PROBE_CMD = [
  'printf "OS=%s\\n" "$(uname -s 2>/dev/null || echo unknown)"',
  'printf "ARCH=%s\\n" "$(uname -m 2>/dev/null || echo unknown)"',
  'printf "CPUS=%s\\n" "$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"',
  'printf "LOAD=%s\\n" "$(cut -d" " -f1 /proc/loadavg 2>/dev/null || echo 0)"',
  'printf "MEM_KB=%s\\n" "$(awk \'/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%d %d",t+0,a+0}\' /proc/meminfo 2>/dev/null || echo "0 0")"',
  'printf "DISK_KB=%s\\n" "$(df -Pk / 2>/dev/null | awk \'NR==2{printf "%s %s",$2,$4}\' || echo "0 0")"',
  'printf "DOCKER=%s\\n" "$(docker version --format "{{.Server.Version}}" 2>/dev/null || echo none)"',
  'printf "DOCKER_SOCK=%s\\n" "$(test -w /var/run/docker.sock && echo rw || (test -e /var/run/docker.sock && echo ro || echo missing))"',
  'printf "CADDY=%s\\n" "$(command -v caddy >/dev/null 2>&1 && (caddy version 2>/dev/null | awk \'{print $1}\') || echo none)"'
].join('; ');

const HOST_KEY_MISMATCH_PATTERNS = [
  /REMOTE HOST IDENTIFICATION HAS CHANGED/i,
  /Host key verification failed/i,
  /Offending [A-Za-z0-9_ -]+ key/i,
  /No [A-Za-z0-9_ -]+ host key is known/i
];

// ---------------------------------------------------------------------------
// Error & Redaction Helpers
// ---------------------------------------------------------------------------

/**
 * @param {string} message
 * @param {string} code
 * @param {number} [statusCode]
 * @param {Record<string, any>} [extra]
 * @returns {Error & Record<string, any>}
 */
function createFleetError(message, code, statusCode = 400, extra = {}) {
  /** @type {Error & Record<string, any>} */
  const err = new Error(redactSensitiveOutput(message));
  err.code = code;
  err.statusCode = statusCode;
  Object.assign(err, extra);
  return err;
}

/**
 * Strips any accidental private key PEM or encrypted vault blob from strings/logs.
 * @param {any} text
 * @returns {string}
 */
function redactSensitiveOutput(text) {
  return String(text == null ? '' : text)
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/v1:[A-Za-z0-9+/=]{12,}:[A-Za-z0-9+/=]{16,}:[A-Za-z0-9+/=]{8,}/g, '[REDACTED_CIPHERTEXT]');
}

/**
 * @param {string} stderr
 * @returns {boolean}
 */
function isHostKeyErrorText(stderr) {
  const s = String(stderr || '');
  return HOST_KEY_MISMATCH_PATTERNS.some((re) => re.test(s));
}

/**
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @param {string} label
 * @returns {Promise<T>}
 */
function withTimeout(promise, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(createFleetError(`${label} excedió el tiempo límite (${timeoutMs} ms)`, 'TIMEOUT', 504));
    }, timeoutMs);
    if (timer.unref) timer.unref();
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

// ---------------------------------------------------------------------------
// Filesystem Hardening (Symlink Checks + 0o600 + Zero-Wipe)
// ---------------------------------------------------------------------------

/**
 * Ensures `dirPath` exists as a real directory (NEVER a symlink) with `0o700`.
 * @param {string} dirPath
 */
function ensureSecureDir(dirPath) {
  const resolved = path.resolve(dirPath);
  try {
    const st = fs.lstatSync(resolved);
    if (st.isSymbolicLink()) {
      throw createFleetError(`Directorio inseguro (symlink detectado): ${path.basename(resolved)}`, 'SYMLINK_DETECTED', 500);
    }
    if (!st.isDirectory()) {
      throw createFleetError(`Ruta no es un directorio válido: ${path.basename(resolved)}`, 'INVALID_DIRECTORY', 500);
    }
  } catch (err) {
    /** @type {any} */
    const e = err;
    if (e && e.code !== 'ENOENT') throw e;
    fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
    const post = fs.lstatSync(resolved);
    if (post.isSymbolicLink() || !post.isDirectory()) {
      throw createFleetError(`Directorio inseguro tras creación: ${path.basename(resolved)}`, 'SYMLINK_DETECTED', 500);
    }
  }
  if (process.platform !== 'win32') {
    try { fs.chmodSync(resolved, 0o700); } catch (e) {}
  }
}

/**
 * Overwrites a regular file with zero bytes, fsyncs, and unlinks it.
 * If the target is a symlink, unlinks the symlink WITHOUT opening/overwriting its target.
 * @param {string} filePath
 */
function secureUnlinkFile(filePath) {
  if (!filePath) return;
  try {
    const st = fs.lstatSync(filePath);
    if (st.isSymbolicLink()) {
      try { fs.unlinkSync(filePath); } catch (e) {}
      return;
    }
    if (st.isFile() && st.size > 0) {
      let fd = -1;
      try {
        fd = fs.openSync(filePath, 'r+');
        const zeros = Buffer.alloc(Math.min(st.size, 65536), 0);
        let written = 0;
        while (written < st.size) {
          const chunk = Math.min(zeros.length, st.size - written);
          fs.writeSync(fd, zeros, 0, chunk, written);
          written += chunk;
        }
        fs.fsyncSync(fd);
      } catch (e) {
        // Proceed to unlink even if overwrite failed
      } finally {
        if (fd >= 0) {
          try { fs.closeSync(fd); } catch (e) {}
        }
      }
    }
    fs.unlinkSync(filePath);
  } catch (err) {
    /** @type {any} */
    const e = err;
    if (e && e.code === 'ENOENT') return;
    try { fs.unlinkSync(filePath); } catch (_) {}
  }
}

/**
 * Writes a text file atomically with `0o600`, refusing to overwrite symlinks.
 * @param {string} targetPath
 * @param {string} content
 */
function writeTextAtomic0600(targetPath, content) {
  const dir = path.dirname(targetPath);
  ensureSecureDir(dir);
  try {
    const existing = fs.lstatSync(targetPath);
    if (existing.isSymbolicLink()) {
      throw createFleetError(`Archivo destino inseguro (symlink): ${path.basename(targetPath)}`, 'SYMLINK_DETECTED', 500);
    }
  } catch (err) {
    /** @type {any} */
    const e = err;
    if (e && e.code !== 'ENOENT') throw e;
  }

  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    const fd = fs.openSync(tmpPath, 'wx', 0o600);
    try {
      fs.writeSync(fd, content, 0, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (process.platform !== 'win32') {
      try { fs.chmodSync(tmpPath, 0o600); } catch (e) {}
    }
    let renamed = false;
    /** @type {any} */
    let lastRenameErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        fs.renameSync(tmpPath, targetPath);
        renamed = true;
        break;
      } catch (renameErr) {
        lastRenameErr = renameErr;
        if (renameErr && (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY' || renameErr.code === 'EACCES') && attempt < 2) {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * (attempt + 1));
          continue;
        }
        break;
      }
    }
    if (!renamed) {
      fs.copyFileSync(tmpPath, targetPath);
      secureUnlinkFile(tmpPath);
      if (lastRenameErr && !fs.existsSync(targetPath)) throw lastRenameErr;
    }
    if (process.platform !== 'win32') {
      try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
    }
  } catch (err) {
    secureUnlinkFile(tmpPath);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// AES-256-GCM Vault Crypto (with AAD binding)
// ---------------------------------------------------------------------------

/**
 * Encrypts an SSH private key with AES-256-GCM bound to `fleet-key:<keyId>` via AAD.
 * @param {string} plainPem
 * @param {string} keyId
 * @param {Buffer} masterKey
 * @returns {string}
 */
function encryptPrivateKey(plainPem, keyId, masterKey) {
  if (!plainPem || typeof plainPem !== 'string') {
    throw createFleetError('Clave privada vacía para cifrado', 'CRYPTO_INVALID_INPUT', 400);
  }
  if (!keyId || typeof keyId !== 'string') {
    throw createFleetError('keyId requerido para AAD', 'CRYPTO_INVALID_INPUT', 400);
  }
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw createFleetError('Clave maestra AES-256 inválida', 'CRYPTO_INVALID_KEY', 500);
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(`fleet-key:${keyId}`, 'utf8'));
  const ct = Buffer.concat([cipher.update(plainPem, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

/**
 * Decrypts an AES-256-GCM private key blob verifying authTag and `fleet-key:<keyId>` AAD.
 * Never falls back to plaintext.
 * @param {string} blob
 * @param {string} keyId
 * @param {Buffer} masterKey
 * @returns {string}
 */
function decryptPrivateKey(blob, keyId, masterKey) {
  if (typeof blob !== 'string') {
    throw createFleetError('Formato de clave cifrada inválido', 'CRYPTO_DECRYPT_FAILED', 500);
  }
  const parts = blob.split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw createFleetError('Formato de cifrado no soportado (se requiere v1 AES-256-GCM)', 'CRYPTO_DECRYPT_FAILED', 500);
  }
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw createFleetError('Clave maestra AES-256 inválida', 'CRYPTO_INVALID_KEY', 500);
  }
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');
  if (iv.length !== 12 || tag.length !== 16 || ct.length === 0) {
    throw createFleetError('Bloque cifrado malformado o truncado', 'CRYPTO_DECRYPT_FAILED', 500);
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
    decipher.setAAD(Buffer.from(`fleet-key:${keyId}`, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch (err) {
    throw createFleetError('Error al descifrar la clave SSH (integridad o AAD comprometidos)', 'CRYPTO_DECRYPT_FAILED', 500);
  }
}

// ---------------------------------------------------------------------------
// SSH Fingerprint & Validation Helpers
// ---------------------------------------------------------------------------

/**
 * Normalizes a `SHA256:...` fingerprint (strips optional trailing `=`).
 * @param {string} fp
 * @returns {string}
 */
function normalizeFingerprint(fp) {
  const s = String(fp || '').trim();
  if (!FINGERPRINT_RE.test(s)) {
    throw createFleetError('Huella SHA-256 inválida (formato esperado: SHA256:<base64>)', 'INVALID_FINGERPRINT', 400);
  }
  return s.replace(/=+$/, '');
}

/**
 * Constant-time comparison of two normalized `SHA256:...` fingerprints.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function fingerprintsEqual(a, b) {
  try {
    const na = Buffer.from(normalizeFingerprint(a), 'utf8');
    const nb = Buffer.from(normalizeFingerprint(b), 'utf8');
    if (na.length !== nb.length) return false;
    return crypto.timingSafeEqual(na, nb);
  } catch (e) {
    return false;
  }
}

/**
 * Computes OpenSSH `SHA256:...` fingerprint in pure Node from a single-line public key.
 * Rejects DSA (`ssh-dss`), multi-line input, and invalid base64.
 * @param {string} pubKeyLine
 * @returns {{ keyType: string, keyBase64: string, fingerprint: string, normalizedLine: string }}
 */
function computeSshFingerprint(pubKeyLine) {
  const trimmed = String(pubKeyLine || '').trim();
  if (!trimmed || CONTROL_CHAR_RE.test(trimmed)) {
    throw createFleetError('Clave pública SSH vacía o con saltos de línea', 'INVALID_PUBLIC_KEY', 400);
  }
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) {
    throw createFleetError('Formato de clave pública SSH inválido', 'INVALID_PUBLIC_KEY', 400);
  }
  const [keyType, keyBase64, ...rest] = parts;
  if (keyType === 'ssh-dss') {
    throw createFleetError('Algoritmo DSA (ssh-dss) rechazado por inseguro', 'WEAK_KEY_TYPE', 400);
  }
  if (!ALLOWED_SSH_KEY_TYPE_SET.has(keyType)) {
    throw createFleetError(`Tipo de clave SSH no soportado: ${keyType.slice(0, 40)}`, 'INVALID_PUBLIC_KEY', 400);
  }
  if (!BASE64_STRICT_RE.test(keyBase64) || keyBase64.length < 24 || keyBase64.length > 8192) {
    throw createFleetError('Bloque base64 de clave pública SSH inválido', 'INVALID_PUBLIC_KEY', 400);
  }
  const raw = Buffer.from(keyBase64, 'base64');
  if (raw.length < 16) {
    throw createFleetError('Clave pública SSH demasiado corta', 'INVALID_PUBLIC_KEY', 400);
  }
  const digest = crypto.createHash('sha256').update(raw).digest('base64').replace(/=+$/, '');
  const comment = rest.join(' ').replace(CONTROL_CHAR_RE, '').slice(0, 128);
  const normalizedLine = comment ? `${keyType} ${keyBase64} ${comment}` : `${keyType} ${keyBase64}`;
  return {
    keyType,
    keyBase64,
    fingerprint: `SHA256:${digest}`,
    normalizedLine
  };
}

/**
 * Validates syntax of an SSH host (IPv4, IPv6, or strict RFC1123 hostname).
 * Rejects leading `-`, shell metacharacters, whitespace, control chars, and obfuscated numeric IPs.
 * @param {any} rawHost
 * @returns {string}
 */
function validateHostSyntax(rawHost) {
  if (typeof rawHost !== 'string') {
    throw createFleetError('Host SSH inválido', 'INVALID_HOST', 400);
  }
  let clean = rawHost.trim();
  if (!clean || clean.length > 253) {
    throw createFleetError('Host SSH vacío o demasiado largo (máx. 253 caracteres)', 'INVALID_HOST', 400);
  }
  if (HOST_FORBIDDEN_RE.test(clean)) {
    throw createFleetError('Host SSH contiene caracteres no permitidos', 'INVALID_HOST', 400);
  }
  if (clean.startsWith('[') && clean.endsWith(']')) {
    const inner = clean.slice(1, -1);
    if (net.isIP(inner) !== 6) {
      throw createFleetError('Host IPv6 entre corchetes inválido', 'INVALID_HOST', 400);
    }
    clean = inner;
  }
  if (clean.includes('[') || clean.includes(']')) {
    throw createFleetError('Host SSH contiene corchetes no permitidos', 'INVALID_HOST', 400);
  }
  if (clean.startsWith('-')) {
    throw createFleetError('El host SSH no puede empezar por guion ("-")', 'INVALID_HOST', 400);
  }

  const ipKind = net.isIP(clean);
  if (ipKind === 4 || ipKind === 6) {
    return clean.toLowerCase();
  }

  // Reject colon outside valid IPv6
  if (clean.includes(':')) {
    throw createFleetError('Host SSH inválido (no incluyas puerto ni caracteres ":" fuera de IPv6)', 'INVALID_HOST', 400);
  }

  // Reject obfuscated integer/hex/octal IP representations (e.g. 2130706433, 0x7f000001, 0177.0.0.1)
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(clean)) {
    throw createFleetError('Representación numérica/hex de IP no permitida', 'INVALID_HOST', 400);
  }

  if (clean.startsWith('.') || clean.endsWith('.') || clean.includes('..')) {
    throw createFleetError('Hostname SSH malformado', 'INVALID_HOST', 400);
  }

  const labels = clean.split('.');
  const allNumericOrOctalHex = labels.every((l) => /^(?:0x[0-9a-f]+|\d+)$/i.test(l));
  if (allNumericOrOctalHex) {
    throw createFleetError('Dirección IP ambigua/octal/hex no permitida', 'INVALID_HOST', 400);
  }
  for (const label of labels) {
    if (!RFC1123_LABEL_RE.test(label)) {
      throw createFleetError(`Etiqueta de hostname SSH inválida: "${label.slice(0, 32)}"`, 'INVALID_HOST', 400);
    }
  }
  return clean.toLowerCase();
}

/**
 * Parses any valid IPv6 textual representation (compressed, expanded, mixed dotted IPv4)
 * into its canonical 16-byte array so textual tricks like `::0001`, `0::1`, or
 * `0:0:0:0:0:ffff:127.0.0.1` can never bypass loopback/metadata SSRF checks.
 * @param {string} ip
 * @returns {Uint8Array | null}
 */
function parseIpv6Bytes(ip) {
  let clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const zoneIdx = clean.indexOf('%');
  if (zoneIdx !== -1) clean = clean.slice(0, zoneIdx);
  if (net.isIP(clean) !== 6) return null;

  // Handle trailing dotted IPv4 (e.g. ::ffff:127.0.0.1 or 0:0:0:0:0:ffff:169.254.169.254)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1 && clean.slice(lastColon + 1).includes('.')) {
    const v4Part = clean.slice(lastColon + 1);
    if (net.isIP(v4Part) !== 4) return null;
    const octets = v4Part.split('.').map(Number);
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;

  const groups = [...left, ...new Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    if (!Number.isInteger(val) || val < 0 || val > 0xffff) return null;
    bytes[i * 2] = (val >> 8) & 0xff;
    bytes[i * 2 + 1] = val & 0xff;
  }
  return bytes;
}

/**
 * Checks whether an IP address is blocked for remote fleet nodes.
 * Blocks: cloud metadata (169.254.0.0/16, fd00:ec2::/32, 100.100.100.200),
 * unspecified (0.0.0.0/8, ::), loopback (127.0.0.0/8, ::1 in any notation),
 * IPv6 link-local (fe80::/10), multicast/reserved (>=224.0.0.0, ff00::/8),
 * Teredo, and IPv4-mapped/SIIT/NAT64/6to4 equivalents of blocked IPv4s.
 * Allows: public IPs, RFC1918 private LAN/VPC (10/8, 172.16/12, 192.168/16),
 * CGNAT/Tailscale (100.64/10 except 100.100.100.200), and WireGuard/Tailscale IPv6 ULA (except fd00:ec2::/32).
 * @param {string} ip
 * @returns {boolean}
 */
function isBlockedFleetIp(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return true;

  // Cloud metadata (includes IPv4-mapped hex/dec, NAT64, 6to4, fd00:ec2::, 100.100.100.200)
  if (isMetadataIp(clean)) return true;

  const embedded = extractEmbeddedIPv4(clean);
  if (embedded) return isBlockedFleetIp(embedded);

  const kind = net.isIP(clean);
  if (kind === 4) {
    const parts = clean.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    if (a === 0) return true;                     // 0.0.0.0/8 (unspecified / routes to localhost on Linux)
    if (a === 127) return true;                   // 127.0.0.0/8 (loopback — use virtual 'local' server)
    if (a === 169 && b === 254) return true;      // 169.254.0.0/16 (link-local / cloud metadata)
    if (clean === '100.100.100.200') return true; // Alibaba Cloud metadata
    if (a >= 224) return true;                    // multicast / reserved / broadcast
    return false;
  }

  if (kind === 6) {
    const b = parseIpv6Bytes(clean);
    if (!b) return true;

    // :: (unspecified) and ::1 (loopback) in ANY representation (::0001, 0::1, etc.)
    let first15Zero = true;
    for (let i = 0; i < 15; i++) {
      if (b[i] !== 0) { first15Zero = false; break; }
    }
    if (first15Zero && (b[15] === 0 || b[15] === 1)) return true;

    // IPv4-mapped ::ffff:0:0/96
    let first10Zero = true;
    for (let i = 0; i < 10; i++) {
      if (b[i] !== 0) { first10Zero = false; break; }
    }
    if (first10Zero && b[10] === 0xff && b[11] === 0xff) {
      return isBlockedFleetIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
    }

    // SIIT ::ffff:0:0:0/96
    let first8Zero = true;
    for (let i = 0; i < 8; i++) {
      if (b[i] !== 0) { first8Zero = false; break; }
    }
    if (first8Zero && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) {
      return isBlockedFleetIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
    }

    // Deprecated IPv4-compatible ::/96
    if (first10Zero && b[10] === 0 && b[11] === 0) {
      return isBlockedFleetIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
    }

    // NAT64 64:ff9b::/96 and 64:ff9b:1::/48
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
      return isBlockedFleetIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
    }

    // 6to4 2002::/16
    if (b[0] === 0x20 && b[1] === 0x02) {
      return isBlockedFleetIp(`${b[2]}.${b[3]}.${b[4]}.${b[5]}`);
    }

    // Teredo 2001:0000::/32 (block outright — tunnel encapsulation bypass vector)
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true;

    // AWS IMDSv2 IPv6 fd00:ec2::/32
    if (b[0] === 0xfd && b[1] === 0x00 && b[2] === 0x0e && b[3] === 0xc2) return true;

    // Link-local fe80::/10
    if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;

    // Multicast ff00::/8
    if (b[0] === 0xff) return true;

    return false;
  }

  return true;
}

/**
 * Default DNS resolver returning all A/AAAA records (with 5s timeout).
 * @param {string} host
 * @param {number} [timeoutMs]
 * @returns {Promise<string[]>}
 */
async function defaultResolveHost(host, timeoutMs = DEFAULTS.dnsTimeoutMs) {
  const dns = getDnsPromises();
  /** @type {string[]} */
  let addresses = [];
  try {
    const [v4, v6] = await withTimeout(
      Promise.all([
        dns.resolve4(host).catch(() => []),
        dns.resolve6(host).catch(() => [])
      ]),
      timeoutMs,
      `Resolución DNS de ${host}`
    );
    addresses = [...v4, ...v6];
  } catch (e) {
    addresses = [];
  }
  if (addresses.length === 0) {
    try {
      const looked = await withTimeout(
        dns.lookup(host, { all: true }),
        timeoutMs,
        `Resolución DNS de ${host}`
      );
      addresses = looked.map((r) => r.address);
    } catch (e) {
      throw createFleetError(`No se pudo resolver el host SSH: ${host}`, 'DNS_RESOLUTION_FAILED', 400);
    }
  }
  return Array.from(new Set(addresses.filter(Boolean)));
}

/**
 * Validates an SSH host syntax, blocks metadata/loopback hostnames & resolved IPs,
 * and returns a pinned IP to close DNS-rebinding TOCTOU windows.
 * @param {string} rawHost
 * @param {{ resolveHost?: ((host: string) => Promise<string[]>) | null, dnsTimeoutMs?: number }} [opts]
 * @returns {Promise<{ host: string, pinnedIp: string, addresses: string[] }>}
 */
async function assertSafeFleetHost(rawHost, opts = {}) {
  const host = validateHostSyntax(rawHost);

  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost')) {
    throw createFleetError(
      `Destino SSH bloqueado por seguridad (${host}). Usa el servidor virtual "local" para este equipo.`,
      'SSRF_BLOCKED',
      400
    );
  }

  /** @type {string[]} */
  let addresses;
  if (net.isIP(host)) {
    addresses = [host];
  } else {
    const resolver = typeof opts.resolveHost === 'function'
      ? opts.resolveHost
      : (h) => defaultResolveHost(h, opts.dnsTimeoutMs || DEFAULTS.dnsTimeoutMs);
    const resolved = await resolver(host);
    addresses = Array.isArray(resolved) ? Array.from(new Set(resolved.map((a) => String(a || '').trim()).filter(Boolean))) : [];
    if (addresses.length === 0) {
      throw createFleetError(`No se pudo resolver ninguna IP para el host SSH: ${host}`, 'DNS_RESOLUTION_FAILED', 400);
    }
  }

  for (const addr of addresses) {
    if (isBlockedFleetIp(addr)) {
      throw createFleetError(
        `Destino SSH bloqueado por protección SSRF/loopback (${addr})`,
        'SSRF_BLOCKED',
        400
      );
    }
  }

  const pinnedIp = addresses.find((a) => net.isIP(a) === 4) || addresses[0];
  return { host, pinnedIp, addresses };
}

/** @param {any} rawPort @param {string} [field] */
function validatePort(rawPort, field = 'port') {
  const n = Number(rawPort);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw createFleetError(`${field} inválido (entero 1..65535)`, 'INVALID_PORT', 400);
  }
  return n;
}

/** @param {any} rawUser */
function validateSshUser(rawUser) {
  const u = String(rawUser == null || rawUser === '' ? DEFAULTS.sshUser : rawUser).trim();
  if (!SSH_USER_RE.test(u)) {
    throw createFleetError('Usuario SSH inválido (solo a-z, 0-9, _, -; debe iniciar por letra o "_")', 'INVALID_USER', 400);
  }
  return u;
}

/** @param {any} rawSock */
function validateDockerSocketPath(rawSock) {
  const s = String(rawSock == null || rawSock === '' ? DEFAULTS.dockerSocketPath : rawSock).trim();
  if (!DOCKER_SOCKET_RE.test(s) || s.includes('..') || s.includes('//') || CONTROL_CHAR_RE.test(s)) {
    throw createFleetError('Ruta de socket Docker inválida (debe ser ruta absoluta segura sin "..")', 'INVALID_DOCKER_SOCKET', 400);
  }
  return s;
}

/** @param {any} rawId */
function validateServerId(rawId) {
  const id = String(rawId || '').trim().toLowerCase();
  if (id === LOCAL_SERVER_ID) {
    throw createFleetError('El identificador "local" está reservado para el nodo principal', 'RESERVED_SERVER_ID', 400);
  }
  if (!SERVER_ID_RE.test(id)) {
    throw createFleetError('serverId inválido (1..48 caracteres: a-z, 0-9, _, -)', 'INVALID_SERVER_ID', 400);
  }
  return id;
}

/** @param {any} rawRegion */
function validateRegion(rawRegion) {
  const r = String(rawRegion == null || rawRegion === '' ? DEFAULTS.region : rawRegion).trim().toLowerCase();
  if (!REGION_RE.test(r)) {
    throw createFleetError('Región inválida (1..32 caracteres: a-z, 0-9, _, -)', 'INVALID_REGION', 400);
  }
  return r;
}

/** @param {any} rawTags @returns {string[]} */
function validateTags(rawTags) {
  if (rawTags == null) return [];
  if (!Array.isArray(rawTags)) {
    throw createFleetError('tags debe ser un array de cadenas', 'INVALID_TAGS', 400);
  }
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const item of rawTags) {
    const tag = String(item || '').trim().toLowerCase();
    if (!tag) continue;
    if (!TAG_RE.test(tag)) {
      throw createFleetError(`Etiqueta inválida: "${tag.slice(0, 32)}"`, 'INVALID_TAGS', 400);
    }
    if (!seen.has(tag)) {
      seen.add(tag);
      out.push(tag);
    }
    if (out.length > 16) {
      throw createFleetError('Máximo 16 etiquetas por servidor', 'INVALID_TAGS', 400);
    }
  }
  return out;
}

/** @param {any} rawName @param {string} [field] */
function validateDisplayName(rawName, field = 'name') {
  const s = String(rawName || '').trim();
  if (!s || s.length > 80 || CONTROL_CHAR_RE.test(s)) {
    throw createFleetError(`${field} inválido (1..80 caracteres, sin saltos de línea)`, 'INVALID_NAME', 400);
  }
  return s;
}

/** @param {any} rawTeamId */
function validateTeamId(rawTeamId) {
  const t = String(rawTeamId == null || rawTeamId === '' ? DEFAULTS.teamId : rawTeamId).trim();
  if (!TEAM_ID_RE.test(t)) {
    throw createFleetError('teamId inválido', 'INVALID_TEAM_ID', 400);
  }
  return t;
}

/**
 * Validates node maintenance state (`'active' | 'draining' | 'maintenance'`).
 * @param {any} rawState
 * @returns {'active' | 'draining' | 'maintenance'}
 */
function validateMaintenanceState(rawState) {
  const s = String(rawState == null || rawState === '' ? 'active' : rawState).trim().toLowerCase();
  if (!VALID_MAINTENANCE_STATES.has(s)) {
    throw createFleetError(
      'maintenanceState inválido (usa "active", "draining" o "maintenance")',
      'INVALID_MAINTENANCE_STATE',
      400
    );
  }
  return /** @type {'active' | 'draining' | 'maintenance'} */ (s);
}

/**
 * Validates optional human-readable maintenance reason (no null bytes or control newlines).
 * @param {any} rawReason
 * @returns {string | null}
 */
function validateMaintenanceReason(rawReason) {
  if (rawReason == null) return null;
  const raw = String(rawReason);
  if (raw.includes('\0')) {
    throw createFleetError('maintenanceReason contiene bytes nulos', 'INVALID_MAINTENANCE_REASON', 400);
  }
  const clean = raw.replace(/[\r\n]+/g, ' ').trim();
  if (!clean) return null;
  return clean.slice(0, 240);
}

/**
 * Validates a Docker container/image reference (strict allowlist; never starts with `-`).
 * @param {any} rawRef
 * @param {string} [label]
 * @returns {string}
 */
function validateDockerRef(rawRef, label = 'containerId') {
  const ref = String(rawRef == null ? '' : rawRef).trim();
  if (!ref || ref.length > 255 || !DOCKER_REF_RE.test(ref)) {
    throw createFleetError(`${label} de Docker inválido`, 'INVALID_DOCKER_REF', 400);
  }
  return ref;
}

/**
 * Validates a Docker exec argv array (strict non-empty string[]; zero shell construction).
 * @param {any} command
 * @returns {string[]}
 */
function validateDockerExecCommand(command) {
  if (!Array.isArray(command) || command.length === 0 || command.length > 64) {
    throw createFleetError(
      'command debe ser un array argv no vacío (1..64 argumentos); no se permiten cadenas de shell',
      'INVALID_EXEC_COMMAND',
      400
    );
  }
  /** @type {string[]} */
  const out = [];
  for (let i = 0; i < command.length; i++) {
    const arg = command[i];
    if (typeof arg !== 'string') {
      throw createFleetError(`Argumento #${i} de command debe ser string`, 'INVALID_EXEC_COMMAND', 400);
    }
    if (arg.includes('\0') || arg.length > 4096) {
      throw createFleetError(`Argumento #${i} de command inválido (byte nulo o >4096 bytes)`, 'INVALID_EXEC_COMMAND', 400);
    }
    if (i === 0 && (!arg.trim() || CONTROL_CHAR_RE.test(arg))) {
      throw createFleetError('El binario inicial de command es inválido', 'INVALID_EXEC_COMMAND', 400);
    }
    out.push(arg);
  }
  return out;
}

/**
 * Validates an optional IPv4/IPv6 or CIDR control-plane address for UFW allowlisting
 * inside generated VPS bootstrap scripts. Rejects metadata/loopback/metacharacters.
 * @param {any} rawCidr
 * @returns {string | null}
 */
function validateControlPlaneCidr(rawCidr) {
  if (rawCidr == null || String(rawCidr).trim() === '') return null;
  const s = String(rawCidr).trim();
  if (CONTROL_CHAR_RE.test(s) || HOST_FORBIDDEN_RE.test(s.replace('/', ''))) {
    throw createFleetError('controlPlaneIp contiene caracteres no permitidos', 'INVALID_CONTROL_PLANE_IP', 400);
  }
  const slashIdx = s.indexOf('/');
  const ipPart = slashIdx === -1 ? s : s.slice(0, slashIdx);
  const prefixPart = slashIdx === -1 ? null : s.slice(slashIdx + 1);
  const ipKind = net.isIP(ipPart);
  if (ipKind !== 4 && ipKind !== 6) {
    throw createFleetError('controlPlaneIp debe ser una IPv4/IPv6 o CIDR válido', 'INVALID_CONTROL_PLANE_IP', 400);
  }
  if (isBlockedFleetIp(ipPart)) {
    throw createFleetError('controlPlaneIp no puede apuntar a loopback/metadatos', 'INVALID_CONTROL_PLANE_IP', 400);
  }
  if (prefixPart !== null) {
    if (!/^\d{1,3}$/.test(prefixPart)) {
      throw createFleetError('Prefijo CIDR inválido en controlPlaneIp', 'INVALID_CONTROL_PLANE_IP', 400);
    }
    const prefix = parseInt(prefixPart, 10);
    const maxPrefix = ipKind === 4 ? 32 : 128;
    if (prefix < 1 || prefix > maxPrefix) {
      throw createFleetError(`Prefijo CIDR fuera de rango (1..${maxPrefix})`, 'INVALID_CONTROL_PLANE_IP', 400);
    }
    return `${ipPart.toLowerCase()}/${prefix}`;
  }
  return ipPart.toLowerCase();
}

/**
 * Parses NDJSON output from `docker stats --format '{{json .}}'` safely.
 * @param {string} stdout
 * @returns {Array<{
 *   id: string,
 *   name: string,
 *   cpuPercent: number | null,
 *   memUsage: string,
 *   memPercent: number | null,
 *   netIO: string,
 *   blockIO: string,
 *   pids: number | null,
 *   raw: Record<string, any>
 * }>}
 */
function parseDockerStatsLines(stdout) {
  const out = [];
  const lines = String(stdout || '').split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || !trimmed.startsWith('{')) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (!obj || typeof obj !== 'object') continue;
      const cpuNum = parseFloat(String(obj.CPUPerc || '').replace('%', ''));
      const memNum = parseFloat(String(obj.MemPerc || '').replace('%', ''));
      const pidsNum = parseInt(String(obj.PIDs || ''), 10);
      out.push({
        id: String(obj.ID || obj.Container || ''),
        name: String(obj.Name || obj.Container || ''),
        cpuPercent: Number.isFinite(cpuNum) ? cpuNum : null,
        memUsage: String(obj.MemUsage || ''),
        memPercent: Number.isFinite(memNum) ? memNum : null,
        netIO: String(obj.NetIO || ''),
        blockIO: String(obj.BlockIO || ''),
        pids: Number.isFinite(pidsNum) ? pidsNum : null,
        raw: obj
      });
    } catch (e) {
      // Ignore malformed / partial status lines
    }
  }
  return out;
}

/**
 * Determines whether a tunnel/Docker error is transient and safe to retry after reconnect.
 * @param {any} err
 * @returns {boolean}
 */
function isRetryableTunnelError(err) {
  if (!err) return false;
  const code = String(err.code || '').toUpperCase();
  if (NON_RETRYABLE_TUNNEL_CODES.has(code)) return false;
  if (
    code === 'TUNNEL_EXIT_EARLY' ||
    code === 'TUNNEL_TIMEOUT' ||
    code === 'TUNNEL_DROPPED' ||
    code === 'ECONNREFUSED' ||
    code === 'ECONNRESET' ||
    code === 'EPIPE' ||
    code === 'ETIMEDOUT' ||
    code === 'ENOENT'
  ) {
    return true;
  }
  const msg = `${err.stderr || ''}\n${err.message || ''}`;
  return TRANSIENT_TUNNEL_ERROR_RE.test(msg);
}

/**
 * Sleeps for `ms` milliseconds, cancelling immediately if `signal` aborts.
 * @param {number} ms
 * @param {AbortSignal | null} [signal]
 * @returns {Promise<void>}
 */
function sleepWithAbort(ms, signal = null) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      return reject(createFleetError('Operación cancelada', 'ABORTED', 499));
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(createFleetError('Operación cancelada', 'ABORTED', 499));
    };
    const timer = setTimeout(() => {
      if (signal && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onAbort);
      }
      resolve();
    }, Math.max(0, ms));
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

/**
 * Fast active liveness probe for a cached local TCP or Unix tunnel endpoint.
 * @param {{ localSock?: string | null, localPort?: number | null }} endpoint
 * @param {number} [timeoutMs]
 * @returns {Promise<boolean>}
 */
function defaultProbeEndpoint(endpoint, timeoutMs = 400) {
  return new Promise((resolve) => {
    if (!endpoint || (!endpoint.localSock && !endpoint.localPort)) {
      return resolve(false);
    }
    let settled = false;
    let sock;
    try {
      sock = endpoint.localSock
        ? net.createConnection({ path: endpoint.localSock })
        : net.createConnection({ host: '127.0.0.1', port: Number(endpoint.localPort) });
    } catch (e) {
      return resolve(false);
    }
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (e) {}
      resolve(ok);
    };
    sock.setTimeout(Math.max(50, timeoutMs));
    sock.once('connect', () => finish(true));
    sock.once('error', () => finish(false));
    sock.once('timeout', () => finish(false));
  });
}

/**
 * Builds hardened OpenSSH argv array.
 * - Uses `-F /dev/null`, `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`,
 *   `IdentitiesOnly=yes`, `ForwardAgent=no`, `ForwardX11=no`, `PermitLocalCommand=no`,
 *   `ServerAliveInterval=15`, `ServerAliveCountMax=3`, `ExitOnForwardFailure=yes`.
 * - Connects to `-- <user>@<pinnedIp>` with `-o HostKeyAlias=<server.host>` to prevent DNS-rebinding TOCTOU.
 * - Includes `-o ClearAllForwardings=yes` for non-tunnel commands, and omits it when `-L` is used!
 *
 * @param {{ host: string, port: number, user: string }} server
 * @param {{
 *   keyFile: string,
 *   knownHostsFile: string,
 *   pinnedIp?: string,
 *   connectTimeoutSec?: number,
 *   clearAllForwardings?: boolean,
 *   platform?: NodeJS.Platform,
 *   extraArgs?: string[]
 * }} opts
 * @returns {string[]}
 */
function buildBaseSshArgs(server, opts) {
  const {
    keyFile,
    knownHostsFile,
    pinnedIp,
    connectTimeoutSec = DEFAULTS.connectTimeoutSec,
    clearAllForwardings = true,
    platform = process.platform,
    extraArgs = []
  } = opts;

  const safeHost = validateHostSyntax(server.host);
  const safeUser = validateSshUser(server.user);
  const safePort = validatePort(server.port, 'port');
  const targetHost = pinnedIp ? validateHostSyntax(pinnedIp) : safeHost;
  const nullDev = platform === 'win32' ? 'NUL' : '/dev/null';

  if (!keyFile || CONTROL_CHAR_RE.test(keyFile)) {
    throw createFleetError('keyFile inválido', 'INVALID_SSH_ARGS', 500);
  }
  if (!knownHostsFile || CONTROL_CHAR_RE.test(knownHostsFile)) {
    throw createFleetError('knownHostsFile inválido', 'INVALID_SSH_ARGS', 500);
  }

  const hasLocalForward = extraArgs.includes('-L') || extraArgs.some((a) => typeof a === 'string' && a.startsWith('-L'));
  const shouldClearForwardings = clearAllForwardings && !hasLocalForward;

  /** @type {string[]} */
  const args = [
    '-F', nullDev,
    '-T',
    '-p', String(safePort),
    '-i', keyFile,
    '-o', 'BatchMode=yes',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'ForwardAgent=no',
    '-o', 'ForwardX11=no',
    '-o', 'PermitLocalCommand=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsFile}`,
    '-o', `GlobalKnownHostsFile=${nullDev}`,
    '-o', `HostKeyAlias=${safeHost}`,
    '-o', `ConnectTimeout=${Math.max(1, Math.min(60, Math.floor(Number(connectTimeoutSec) || DEFAULTS.connectTimeoutSec)))}`,
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'ExitOnForwardFailure=yes'
  ];

  if (shouldClearForwardings) {
    args.push('-o', 'ClearAllForwardings=yes');
  }

  for (const extra of extraArgs) {
    args.push(String(extra));
  }

  args.push('--', `${safeUser}@${targetHost}`);
  return args;
}

// ---------------------------------------------------------------------------
// Probe Output & Docker Published-Port Parsers
// ---------------------------------------------------------------------------

/**
 * Parses output from static `PROBE_CMD` into structured host resource telemetry.
 * Tolerates MOTD/banner noise before or after tagged `KEY=VALUE` lines.
 * @param {string} stdout
 * @param {number} [latencyMs]
 * @param {string} [sshUser]
 */
function parseProbeOutput(stdout, latencyMs = 0, sshUser = 'root') {
  /** @type {Record<string, string>} */
  const kv = Object.create(null);
  const lines = String(stdout || '').split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    const m = /^(OS|ARCH|CPUS|LOAD|MEM_KB|DISK_KB|DOCKER|DOCKER_SOCK|CADDY)=(.*)$/.exec(line);
    if (m) {
      kv[m[1]] = m[2].trim();
    }
  }

  const osName = kv.OS && kv.OS !== 'unknown' ? kv.OS : 'unknown';
  const arch = kv.ARCH && kv.ARCH !== 'unknown' ? kv.ARCH : 'unknown';
  const cpusParsed = parseInt(kv.CPUS || '1', 10);
  const cpus = Number.isInteger(cpusParsed) && cpusParsed > 0 ? cpusParsed : 1;
  const loadParsed = parseFloat(kv.LOAD || '0');
  const load1m = Number.isFinite(loadParsed) && loadParsed >= 0 ? Number(loadParsed.toFixed(2)) : 0;

  const memParts = (kv.MEM_KB || '0 0').split(/\s+/).map((x) => parseInt(x, 10));
  const memTotalKb = Number.isFinite(memParts[0]) && memParts[0] > 0 ? memParts[0] : 0;
  const rawMemAvailKb = Number.isFinite(memParts[1]) && memParts[1] >= 0 ? memParts[1] : 0;
  const memAvailKb = memTotalKb > 0 ? Math.min(rawMemAvailKb, memTotalKb) : rawMemAvailKb;
  const memoryTotalMb = Math.round(memTotalKb / 1024);
  const memoryAvailableMb = Math.round(memAvailKb / 1024);

  const diskParts = (kv.DISK_KB || '0 0').split(/\s+/).map((x) => parseInt(x, 10));
  const diskTotalKb = Number.isFinite(diskParts[0]) && diskParts[0] > 0 ? diskParts[0] : 0;
  const rawDiskAvailKb = Number.isFinite(diskParts[1]) && diskParts[1] >= 0 ? diskParts[1] : 0;
  const diskAvailKb = diskTotalKb > 0 ? Math.min(rawDiskAvailKb, diskTotalKb) : rawDiskAvailKb;
  const diskTotalGb = Number((diskTotalKb / (1024 * 1024)).toFixed(2));
  const diskAvailableGb = Number((diskAvailKb / (1024 * 1024)).toFixed(2));

  const rawDocker = kv.DOCKER || 'none';
  const dockerVersion = rawDocker && rawDocker !== 'none' ? rawDocker : null;
  const dockerSockState = kv.DOCKER_SOCK === 'rw' || kv.DOCKER_SOCK === 'ro' || kv.DOCKER_SOCK === 'missing'
    ? kv.DOCKER_SOCK
    : 'unknown';

  // Docker is ready if `docker version` returned a valid server version (supports rootless too)
  // AND socket is not explicitly unreadable while version failed.
  const dockerReady = Boolean(dockerVersion);

  const rawCaddy = kv.CADDY || 'none';
  const caddyVersion = rawCaddy && rawCaddy !== 'none' ? rawCaddy : null;
  const caddyAvailable = Boolean(caddyVersion);
  const caddyMode = caddyAvailable ? 'native' : 'none';

  /** @type {string[]} */
  const warnings = [];
  /** @type {string | null} */
  let statusReason = null;
  /** @type {string | null} */
  let statusFix = null;

  if (!dockerReady) {
    if (dockerSockState === 'ro') {
      statusReason = `El usuario SSH "${sshUser}" no tiene permiso de escritura sobre /var/run/docker.sock`;
      statusFix = `Ejecuta en el servidor remoto: sudo usermod -aG docker ${sshUser} && sudo systemctl restart docker`;
    } else if (dockerSockState === 'missing') {
      statusReason = 'Docker no está instalado o el daemon no está activo (/var/run/docker.sock ausente)';
      statusFix = 'Instala Docker Engine en el servidor remoto y habilita el servicio: sudo systemctl enable --now docker';
    } else {
      statusReason = 'Docker daemon no respondió a "docker version"';
      statusFix = `Verifica el estado del daemon (systemctl status docker) y permisos del usuario "${sshUser}" (usermod -aG docker ${sshUser})`;
    }
    warnings.push(statusReason);
  } else if (!caddyAvailable) {
    warnings.push('Caddy no está instalado en el nodo remoto (necesario para rutas HTTPS automáticas)');
  }

  return {
    resources: {
      os: osName,
      arch,
      cpus,
      load1m,
      memoryTotalMb,
      memoryAvailableMb,
      diskTotalGb,
      diskAvailableGb,
      dockerVersion,
      dockerSockState,
      dockerReady,
      caddyAvailable,
      caddyVersion,
      caddyMode,
      latencyMs: Math.max(0, Math.round(Number(latencyMs) || 0))
    },
    status: dockerReady ? 'online' : 'degraded',
    statusReason,
    statusFix,
    warnings
  };
}

/**
 * Parses `docker ps -a --format '{{.Ports}}'` output and extracts all published host ports.
 * Handles IPv4 (`127.0.0.1:30001->3000/tcp`), IPv6 (`[::]:30002->3000/tcp`),
 * wildcard (`0.0.0.0:8080->80/tcp`), and port ranges (`127.0.0.1:30010-30012->3010-3012/tcp`).
 * @param {string} stdout
 * @returns {Set<number>}
 */
function parseDockerPublishedPorts(stdout) {
  /** @type {Set<number>} */
  const used = new Set();
  const re = /(?:^|[,\s])(?:[\d.]+|\[[^\]]+\]|):(\d{1,5})(?:-(\d{1,5}))?->/g;
  const text = String(stdout || '');
  let match;
  while ((match = re.exec(text)) !== null) {
    const start = parseInt(match[1], 10);
    const end = match[2] ? parseInt(match[2], 10) : start;
    if (Number.isInteger(start) && Number.isInteger(end) && start >= 1 && end <= 65535 && end >= start) {
      const cap = Math.min(end, start + 1000);
      for (let p = start; p <= cap; p++) used.add(p);
    }
  }
  return used;
}

/**
 * Picks the strongest host key from `ssh-keyscan` stdout, rejecting `ssh-dss`.
 * @param {string} stdout
 * @returns {{ keyType: string, keyBase64: string, fingerprint: string }}
 */
function parseBestKeyscanOutput(stdout) {
  const lines = String(stdout || '').split(/\r?\n/);
  /** @type {Array<{ priority: number, keyType: string, keyBase64: string, fingerprint: string }>} */
  const candidates = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [, keyType, keyBase64] = parts;
    if (keyType === 'ssh-dss') continue;
    const priority = ALLOWED_SSH_KEY_TYPES.indexOf(keyType);
    if (priority === -1) continue;
    try {
      const parsed = computeSshFingerprint(`${keyType} ${keyBase64}`);
      candidates.push({
        priority,
        keyType: parsed.keyType,
        keyBase64: parsed.keyBase64,
        fingerprint: parsed.fingerprint
      });
    } catch (e) {
      // Ignore malformed lines
    }
  }

  if (candidates.length === 0) {
    throw createFleetError(
      'No se recibió ninguna clave de host SSH válida (ed25519/ecdsa/rsa) desde ssh-keyscan',
      'KEYSCAN_NO_VALID_KEY',
      502
    );
  }

  candidates.sort((a, b) => a.priority - b.priority);
  const best = candidates[0];
  return {
    keyType: best.keyType,
    keyBase64: best.keyBase64,
    fingerprint: best.fingerprint
  };
}

/**
 * Allocates a free ephemeral loopback port on `127.0.0.1`.
 * @returns {Promise<number>}
 */
function findFreeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = addr && typeof addr === 'object' ? addr.port : 0;
      srv.close((err) => {
        if (err) return reject(err);
        if (!port) return reject(createFleetError('No se pudo asignar un puerto local libre', 'PORT_ALLOC_FAILED', 500));
        resolve(port);
      });
    });
  });
}

/**
 * Default async wrapper around `child_process.execFile` with `shell: false` strictly enforced.
 * @param {string} bin
 * @param {string[]} args
 * @param {{ timeout?: number, env?: NodeJS.ProcessEnv, maxBuffer?: number }} [opts]
 * @returns {Promise<{ stdout: string, stderr: string }>}
 */
function defaultExecFile(bin, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      bin,
      args,
      {
        shell: false,
        windowsHide: true,
        timeout: opts.timeout ?? 15000,
        maxBuffer: opts.maxBuffer ?? 2 * 1024 * 1024,
        env: opts.env
      },
      (err, stdout, stderr) => {
        const outStr = typeof stdout === 'string' ? stdout : String(stdout || '');
        const errStr = typeof stderr === 'string' ? stderr : String(stderr || '');
        if (err) {
          /** @type {any} */
          const wrapped = err;
          wrapped.stdout = outStr;
          wrapped.stderr = errStr;
          return reject(wrapped);
        }
        resolve({ stdout: outStr, stderr: errStr });
      }
    );
  });
}

/**
 * Default wrapper around `child_process.spawn` with `shell: false` strictly enforced.
 * @param {string} bin
 * @param {string[]} args
 * @param {import('child_process').SpawnOptions} [opts]
 */
function defaultSpawn(bin, args, opts = {}) {
  return spawn(bin, args, {
    ...opts,
    shell: false,
    windowsHide: true
  });
}

/**
 * Polls a local TCP or Unix socket endpoint until it accepts a connection or child exits.
 * @param {{ localSock?: string | null, localPort?: number | null }} endpoint
 * @param {any} child
 * @param {{ timeoutMs?: number, signal?: AbortSignal | null, getStderr?: () => string }} opts
 * @returns {Promise<void>}
 */
function defaultWaitForEndpoint(endpoint, child, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.tunnelConnectTimeoutMs;
  const signal = opts.signal || null;
  const getStderr = opts.getStderr || (() => '');

  return new Promise((resolve, reject) => {
    let settled = false;
    /** @type {ReturnType<typeof setTimeout> | null} */
    let retryTimer = null;
    /** @type {ReturnType<typeof setTimeout> | null} */
    let deadlineTimer = null;

    const cleanup = () => {
      if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
      if (deadlineTimer) { clearTimeout(deadlineTimer); deadlineTimer = null; }
      if (child && typeof child.removeListener === 'function') {
        child.removeListener('exit', onExit);
        child.removeListener('error', onError);
      }
      if (signal && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onAbort);
      }
    };

    const done = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) reject(err);
      else resolve();
    };

    const onExit = (code, sig) => {
      const stderr = redactSensitiveOutput(getStderr()).trim();
      if (isHostKeyErrorText(stderr)) {
        return done(createFleetError(
          `Verificación de clave de host SSH fallida: ${stderr.slice(0, 240)}`,
          'HOST_KEY_MISMATCH',
          409,
          { stderr }
        ));
      }
      done(createFleetError(
        `El túnel SSH terminó prematuramente (code=${code}, signal=${sig || 'none'})${stderr ? `: ${stderr.slice(0, 200)}` : ''}`,
        'TUNNEL_EXIT_EARLY',
        502,
        { stderr }
      ));
    };

    const onError = (err) => {
      done(createFleetError(`Error al lanzar ssh: ${err && err.message ? err.message : String(err)}`, 'TUNNEL_SPAWN_ERROR', 502));
    };

    const onAbort = () => {
      done(createFleetError('Apertura de túnel SSH cancelada', 'ABORTED', 499));
    };

    if (signal && signal.aborted) return onAbort();
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', onAbort, { once: true });
    }
    if (child && typeof child.once === 'function') {
      child.once('exit', onExit);
      child.once('error', onError);
    }

    deadlineTimer = setTimeout(() => {
      const stderr = redactSensitiveOutput(getStderr()).trim();
      if (isHostKeyErrorText(stderr)) {
        return done(createFleetError('Verificación de clave de host SSH fallida', 'HOST_KEY_MISMATCH', 409, { stderr }));
      }
      done(createFleetError(
        `Tiempo de espera agotado abriendo túnel SSH (${timeoutMs} ms)${stderr ? `: ${stderr.slice(0, 180)}` : ''}`,
        'TUNNEL_TIMEOUT',
        504
      ));
    }, timeoutMs);
    if (deadlineTimer.unref) deadlineTimer.unref();

    const probe = () => {
      if (settled) return;
      const sock = endpoint.localSock
        ? net.createConnection({ path: endpoint.localSock })
        : net.createConnection({ host: '127.0.0.1', port: Number(endpoint.localPort) });

      let sockDone = false;
      const finishSock = (ok) => {
        if (sockDone) return;
        sockDone = true;
        try { sock.destroy(); } catch (e) {}
        if (ok) {
          done(null);
        } else if (!settled) {
          retryTimer = setTimeout(probe, 60);
        }
      };

      sock.setTimeout(500);
      sock.once('connect', () => finishSock(true));
      sock.once('error', () => finishSock(false));
      sock.once('timeout', () => finishSock(false));
    };

    probe();
  });
}

// ---------------------------------------------------------------------------
// ServerFleetManager
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} FleetKeyRecord
 * @property {string} id
 * @property {string} name
 * @property {string} teamId
 * @property {string} keyType
 * @property {string} publicKey
 * @property {string} fingerprint
 * @property {string} privateKeyEnc
 * @property {string} createdAt
 * @property {string} updatedAt
 */

/**
 * @typedef {Object} FleetServerRecord
 * @property {string} id
 * @property {string} name
 * @property {string} host
 * @property {number} port
 * @property {string} user
 * @property {string} keyId
 * @property {string} dockerSocketPath
 * @property {number} caddyAdminPort
 * @property {string} region
 * @property {string[]} tags
 * @property {string} teamId
 * @property {'tofu' | 'strict'} hostKeyPolicy
 * @property {string | null} expectedFingerprint
 * @property {string | null} hostKeyFingerprint
 * @property {string | null} hostKeyType
 * @property {string | null} hostKeyLine
 * @property {string | null} hostKeyPinnedAt
 * @property {'pending' | 'online' | 'degraded' | 'offline' | 'host_key_mismatch'} status
 * @property {'active' | 'draining' | 'maintenance'} maintenanceState
 * @property {string | null} maintenanceReason
 * @property {string | null} maintenanceSince
 * @property {string | null} statusReason
 * @property {string | null} statusFix
 * @property {string[]} warnings
 * @property {string | null} lastProbedAt
 * @property {Record<string, any> | null} resources
 * @property {number} consecutiveFailures
 * @property {string} createdAt
 * @property {string} updatedAt
 */

/**
 * @typedef {Object} ActiveDockerTunnel
 * @property {string} id
 * @property {string} serverId
 * @property {string} dockerHost
 * @property {string | null} localSock
 * @property {number | null} localPort
 * @property {any} child
 * @property {number} refCount
 * @property {boolean} draining
 * @property {boolean} alive
 * @property {ReturnType<typeof setTimeout> | null} idleTimer
 * @property {number} createdAt
 */

/**
 * @typedef {Object} InFlightTunnelConnect
 * @property {Promise<ActiveDockerTunnel>} promise
 * @property {Set<symbol>} waiters
 * @property {AbortController} internalController
 */

class ServerFleetManager extends EventEmitter {
  /**
   * @param {{
   *   dataDir?: string,
   *   _execFile?: typeof defaultExecFile,
   *   _spawn?: typeof defaultSpawn,
   *   _resolveHost?: (host: string) => Promise<string[]>,
   *   _waitForEndpoint?: typeof defaultWaitForEndpoint,
   *   _probeEndpoint?: typeof defaultProbeEndpoint,
   *   _caddyManager?: any,
   *   tunnelIdleMs?: number,
   *   probeTtlMs?: number,
   *   monitorIntervalMs?: number,
   *   autoMonitor?: boolean,
   *   platform?: NodeJS.Platform,
   *   tmpSocketBaseDir?: string
   * }} [opts]
   */
  constructor(opts = {}) {
    super();
    this.dataDir = path.resolve(opts.dataDir || DEFAULT_DATA_DIR);
    this.keyFile = path.join(this.dataDir, '.fleet.key');
    this.keysDataFile = path.join(this.dataDir, 'fleet-keys.json');
    this.serversDataFile = path.join(this.dataDir, 'servers.json');
    this.tmpDir = path.join(this.dataDir, '.fleet-tmp');
    this.knownHostsDir = path.join(this.dataDir, '.fleet-known-hosts');

    this._execFile = opts._execFile || defaultExecFile;
    this._spawn = opts._spawn || defaultSpawn;
    this._resolveHost = opts._resolveHost || defaultResolveHost;
    this._waitForEndpoint = opts._waitForEndpoint || defaultWaitForEndpoint;
    this._customProbeEndpoint = typeof opts._probeEndpoint === 'function';
    this._probeEndpoint = opts._probeEndpoint || defaultProbeEndpoint;
    this._caddyManager = opts._caddyManager || null;

    this._tunnelIdleMs = opts.tunnelIdleMs ?? DEFAULTS.tunnelIdleMs;
    this._probeTtlMs = opts.probeTtlMs ?? DEFAULTS.probeTtlMs;
    this._monitorIntervalMs = opts.monitorIntervalMs ?? DEFAULTS.monitorIntervalMs;
    this._autoMonitor = opts.autoMonitor !== undefined
      ? Boolean(opts.autoMonitor)
      : process.env.CULKIBO_DISABLE_FLEET_MONITOR !== '1';
    this._platform = opts.platform || process.platform;
    this._tmpSocketBaseDir = opts.tmpSocketBaseDir || null;

    /** @type {Buffer | null} */
    this._masterKey = null;
    this._loaded = false;

    /** @type {Map<string, FleetKeyRecord>} */
    this._keys = new Map();
    /** @type {Map<string, FleetServerRecord>} */
    this._servers = new Map();

    /** Active non-draining Docker tunnel per serverId. */
    /** @type {Map<string, ActiveDockerTunnel>} */
    this._dockerTunnels = new Map();
    /** Draining tunnels awaiting active leases to finish before closing. */
    /** @type {Set<ActiveDockerTunnel>} */
    this._drainingTunnels = new Set();
    /** Coalesced in-flight connect entries per serverId (with per-caller abort isolation). */
    /** @type {Map<string, InFlightTunnelConnect>} */
    this._dockerTunnelConnects = new Map();
    /** Short-lived port/caddy tunnel children tracked for clean shutdown. */
    /** @type {Set<any>} */
    this._ephemeralTunnelChildren = new Set();

    /** Coalesced in-flight probes per serverId. */
    /** @type {Map<string, Promise<any>>} */
    this._inFlightProbes = new Map();
    /** Per-server backoff timestamps (epoch ms) for background monitor. */
    /** @type {Map<string, number>} */
    this._nextProbeAt = new Map();
    /** Recently allocated remote ports (with expiry) to prevent concurrent deploy collisions. */
    /** @type {Map<string, Map<number, number>>} */
    this._recentRemotePorts = new Map();
    /** Monotonic drain epoch per serverId so in-flight connects during key rotation drain cleanly. */
    /** @type {Map<string, number>} */
    this._serverDrainEpoch = new Map();

    /** @type {ReturnType<typeof setTimeout> | null} */
    this._monitorTimer = null;
    this._monitorRunning = false;

    // Startup sweep of orphaned ephemeral keys/files if .fleet-tmp already exists
    // (does not create any directory or timer on single-node installs).
    if (fs.existsSync(this.tmpDir)) {
      try { this.sweepTmpDir(); } catch (e) {}
    }

    // Startup sweep of orphaned POSIX tunnel sockets (`ck-*.sock`) if socket dir already exists.
    // Never creates directories on single-node installs.
    for (const sockDir of this._getSocketDirs()) {
      if (fs.existsSync(sockDir)) {
        try { this.sweepStaleSockets(); } catch (e) {}
        break;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Lazy Loading, Master Key Vault & Persistence
  // -------------------------------------------------------------------------

  /**
   * Returns candidate POSIX Unix socket directories owned by this instance.
   * @returns {string[]}
   */
  _getSocketDirs() {
    if (this._tmpSocketBaseDir) {
      return [path.resolve(this._tmpSocketBaseDir)];
    }
    const uid = typeof process.getuid === 'function' ? String(process.getuid()) : 'user';
    const dirs = [path.resolve(path.join(os.tmpdir(), `ck-fleet-${uid}`))];
    if (this._platform !== 'win32') {
      const fallback = path.resolve(path.join('/tmp', `ck-fleet-${uid}`));
      if (!dirs.includes(fallback)) dirs.push(fallback);
    }
    return dirs;
  }

  /**
   * Sweeps stale orphaned POSIX tunnel sockets (`ck-<10hex>.sock`) left behind by crashes.
   * - Never touches sockets owned by currently active or draining tunnels.
   * - Refuses to follow a symlinked socket directory (`SYMLINK_DETECTED`).
   * - Does NOT create directories if absent.
   * @returns {number} Number of stale sockets removed
   */
  sweepStaleSockets() {
    /** @type {Set<string>} */
    const activeSocks = new Set();
    for (const t of this._dockerTunnels.values()) {
      if (t && t.localSock) activeSocks.add(path.resolve(t.localSock));
    }
    for (const t of this._drainingTunnels) {
      if (t && t.localSock) activeSocks.add(path.resolve(t.localSock));
    }

    let cleaned = 0;
    for (const dir of this._getSocketDirs()) {
      let st;
      try {
        st = fs.lstatSync(dir);
      } catch (err) {
        /** @type {any} */
        const e = err;
        if (e && e.code === 'ENOENT') continue;
        throw e;
      }
      if (st.isSymbolicLink()) {
        throw createFleetError(`Directorio de sockets inseguro (symlink detectado): ${path.basename(dir)}`, 'SYMLINK_DETECTED', 500);
      }
      if (!st.isDirectory()) continue;

      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        if (!STALE_SOCKET_RE.test(entry)) continue;
        const full = path.resolve(path.join(dir, entry));
        if (activeSocks.has(full)) continue;
        secureUnlinkFile(full);
        cleaned++;
      }
    }
    return cleaned;
  }

  /**
   * Sweeps stale ephemeral key files in `data/.fleet-tmp/` safely.
   * Refuses to follow a symlinked `.fleet-tmp` directory; unlinks any symlinked entries without following.
   * @returns {number} Number of entries cleaned
   */
  sweepTmpDir() {
    let st;
    try {
      st = fs.lstatSync(this.tmpDir);
    } catch (err) {
      /** @type {any} */
      const e = err;
      if (e && e.code === 'ENOENT') return 0;
      throw e;
    }
    if (st.isSymbolicLink()) {
      throw createFleetError('Directorio temporal .fleet-tmp es un symlink inseguro', 'SYMLINK_DETECTED', 500);
    }
    if (!st.isDirectory()) return 0;

    let cleaned = 0;
    const entries = fs.readdirSync(this.tmpDir);
    for (const entry of entries) {
      const full = path.join(this.tmpDir, entry);
      secureUnlinkFile(full);
      cleaned++;
    }
    return cleaned;
  }

  /**
   * Loads or creates `data/.fleet.key` (`0o600`), enforcing the anti-key-loss guard:
   * refuses to invent a fresh key if `fleet-keys.json` (or `.bak`) already contains `"v1:` ciphertext.
   * @returns {Buffer}
   */
  _loadOrCreateMasterKey() {
    if (this._masterKey) return this._masterKey;

    if (fs.existsSync(this.keyFile)) {
      const st = fs.lstatSync(this.keyFile);
      if (st.isSymbolicLink()) {
        throw createFleetError('Archivo de clave maestra .fleet.key es un symlink inseguro', 'SYMLINK_DETECTED', 500);
      }
      const raw = fs.readFileSync(this.keyFile, 'utf8').trim();
      if (!/^[0-9a-f]{64}$/i.test(raw)) {
        throw createFleetError(
          `Clave maestra corrupta en ${this.keyFile} (se esperan 32 bytes hex). No se regenerará automáticamente para proteger las claves SSH.`,
          'FLEET_KEY_CORRUPT',
          500
        );
      }
      const key = Buffer.from(raw, 'hex');
      if (key.length !== 32) {
        throw createFleetError(`Clave maestra corrupta en ${this.keyFile}`, 'FLEET_KEY_CORRUPT', 500);
      }
      this._masterKey = key;
      return key;
    }

    // Anti-key-loss guard: check both primary and backup key vault files
    for (const candidate of [this.keysDataFile, `${this.keysDataFile}.bak`]) {
      if (!fs.existsSync(candidate)) continue;
      let existingData = '';
      try {
        existingData = fs.readFileSync(candidate, 'utf8');
      } catch (e) {
        continue;
      }
      if (existingData.includes('"v1:')) {
        throw createFleetError(
          `Falta el archivo de clave maestra ${this.keyFile} pero ${path.basename(candidate)} contiene claves SSH cifradas. Restaura .fleet.key desde tu copia segura.`,
          'FLEET_KEY_MISSING',
          500
        );
      }
    }

    ensureSecureDir(this.dataDir);
    const key = crypto.randomBytes(32);
    try {
      const fd = fs.openSync(this.keyFile, 'wx', 0o600);
      try {
        fs.writeSync(fd, key.toString('hex'), 0, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      if (process.platform !== 'win32') {
        try { fs.chmodSync(this.keyFile, 0o600); } catch (e) {}
      }
      this._masterKey = key;
      return key;
    } catch (err) {
      /** @type {any} */
      const e = err;
      if (e && e.code === 'EEXIST') {
        const raced = Buffer.from(fs.readFileSync(this.keyFile, 'utf8').trim(), 'hex');
        if (raced.length === 32) {
          this._masterKey = raced;
          return raced;
        }
      }
      throw err;
    }
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;

    const keysRes = loadJsonWithBackupSync(this.keysDataFile, {
      validate: (p) => p && typeof p === 'object' && Array.isArray(p.keys)
    });
    if (keysRes.ok && keysRes.data) {
      for (const k of keysRes.data.keys) {
        if (k && typeof k.id === 'string') {
          this._keys.set(k.id, k);
        }
      }
    }

    const serversRes = loadJsonWithBackupSync(this.serversDataFile, {
      validate: (p) => p && typeof p === 'object' && Array.isArray(p.servers)
    });
    if (serversRes.ok && serversRes.data) {
      for (const s of serversRes.data.servers) {
        if (s && typeof s.id === 'string' && s.id !== LOCAL_SERVER_ID) {
          s.maintenanceState = VALID_MAINTENANCE_STATES.has(s.maintenanceState) ? s.maintenanceState : 'active';
          s.maintenanceReason = typeof s.maintenanceReason === 'string' && s.maintenanceReason.trim() ? s.maintenanceReason : null;
          s.maintenanceSince = s.maintenanceState === 'active' ? null : (s.maintenanceSince || null);
          this._servers.set(s.id, s);
        }
      }
    }

    if (this._servers.size > 0 && this._autoMonitor) {
      this.startMonitor();
    }
  }

  _saveKeys() {
    atomicWriteJsonSync(
      this.keysDataFile,
      { version: 1, keys: Array.from(this._keys.values()) },
      { mode: 0o600, backup: true }
    );
  }

  _saveServers() {
    atomicWriteJsonSync(
      this.serversDataFile,
      { version: 1, servers: Array.from(this._servers.values()) },
      { mode: 0o600, backup: true }
    );
  }

  /**
   * @param {string} action
   * @param {string | null} resourceId
   * @param {Record<string, any>} [detail]
   */
  _audit(action, resourceId, detail = {}) {
    const logger = getAuditLogger();
    if (!logger || typeof logger.record !== 'function') return;
    try {
      logger.record({
        source: 'system',
        action,
        resourceId,
        detail
      });
    } catch (e) {}
  }

  // -------------------------------------------------------------------------
  // Sanitizers (NEVER expose privateKeyEnc or raw hostKeyLine)
  // -------------------------------------------------------------------------

  /**
   * @param {FleetKeyRecord} k
   */
  sanitizeKey(k) {
    return {
      id: k.id,
      name: k.name,
      teamId: k.teamId || DEFAULTS.teamId,
      keyType: k.keyType,
      publicKey: k.publicKey,
      fingerprint: k.fingerprint,
      createdAt: k.createdAt,
      updatedAt: k.updatedAt
    };
  }

  /**
   * @param {FleetServerRecord} s
   */
  sanitizeServer(s) {
    return {
      id: s.id,
      name: s.name,
      host: s.host,
      port: s.port,
      user: s.user,
      keyId: s.keyId,
      dockerSocketPath: s.dockerSocketPath,
      caddyAdminPort: s.caddyAdminPort,
      region: s.region,
      tags: Array.isArray(s.tags) ? [...s.tags] : [],
      teamId: s.teamId || DEFAULTS.teamId,
      hostKeyPolicy: s.hostKeyPolicy,
      expectedFingerprint: s.expectedFingerprint || null,
      hostKeyFingerprint: s.hostKeyFingerprint || null,
      hostKeyType: s.hostKeyType || null,
      hostKeyPinnedAt: s.hostKeyPinnedAt || null,
      status: s.status || 'pending',
      maintenanceState: VALID_MAINTENANCE_STATES.has(s.maintenanceState) ? s.maintenanceState : 'active',
      maintenanceReason: s.maintenanceReason || null,
      maintenanceSince: s.maintenanceState && s.maintenanceState !== 'active' ? (s.maintenanceSince || null) : null,
      statusReason: s.statusReason || null,
      statusFix: s.statusFix || null,
      warnings: Array.isArray(s.warnings) ? [...s.warnings] : [],
      lastProbedAt: s.lastProbedAt || null,
      resources: s.resources ? { ...s.resources } : null,
      consecutiveFailures: s.consecutiveFailures || 0,
      isLocal: false,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt
    };
  }

  _buildVirtualLocalServer() {
    const load = os.loadavg();
    return {
      id: LOCAL_SERVER_ID,
      name: 'Local Server (Primary)',
      host: '127.0.0.1',
      port: null,
      user: null,
      keyId: null,
      dockerSocketPath: this._platform === 'win32' ? '//./pipe/docker_engine' : '/var/run/docker.sock',
      caddyAdminPort: DEFAULTS.caddyAdminPort,
      region: 'local',
      tags: ['local', 'primary'],
      teamId: DEFAULTS.teamId,
      hostKeyPolicy: 'local',
      expectedFingerprint: null,
      hostKeyFingerprint: null,
      hostKeyType: null,
      hostKeyPinnedAt: null,
      status: 'online',
      maintenanceState: 'active',
      maintenanceReason: null,
      maintenanceSince: null,
      statusReason: null,
      statusFix: null,
      warnings: [],
      lastProbedAt: new Date().toISOString(),
      resources: {
        os: `${os.type()} ${os.release()}`,
        arch: os.arch(),
        cpus: os.cpus().length || 1,
        load1m: Number((load[0] || 0).toFixed(2)),
        memoryTotalMb: Math.round(os.totalmem() / (1024 * 1024)),
        memoryAvailableMb: Math.round(os.freemem() / (1024 * 1024)),
        diskTotalGb: null,
        diskAvailableGb: null,
        dockerVersion: null,
        dockerSockState: 'local',
        dockerReady: true,
        caddyAvailable: true,
        caddyVersion: null,
        caddyMode: 'local',
        latencyMs: 0
      },
      consecutiveFailures: 0,
      isLocal: true,
      createdAt: null,
      updatedAt: null
    };
  }

  // -------------------------------------------------------------------------
  // Ephemeral Key Materialization (0o600 'wx' + Immediate Zero-Wipe)
  // -------------------------------------------------------------------------

  /**
   * Materializes a decrypted SSH private key into `data/.fleet-tmp/k_<16hex>` (`0o600`, `'wx'`).
   * Caller MUST invoke `cleanup()` immediately after SSH handshake/exit.
   * @param {string} keyId
   * @returns {{ keyFile: string, cleanup: () => void }}
   */
  _materializeEphemeralKey(keyId) {
    this._ensureLoaded();
    const record = this._keys.get(keyId);
    if (!record) {
      throw createFleetError(`Clave SSH no encontrada en la bóveda: ${keyId}`, 'KEY_NOT_FOUND', 404);
    }
    const masterKey = this._loadOrCreateMasterKey();
    const plainPem = decryptPrivateKey(record.privateKeyEnc, record.id, masterKey);
    const normalizedPem = plainPem.endsWith('\n') ? plainPem : `${plainPem}\n`;

    ensureSecureDir(this.tmpDir);
    const keyFile = assertContainedPath(this.tmpDir, `k_${crypto.randomBytes(8).toString('hex')}`);

    const fd = fs.openSync(keyFile, 'wx', 0o600);
    try {
      const buf = Buffer.from(normalizedPem, 'utf8');
      try {
        fs.writeSync(fd, buf, 0, buf.length, 0);
        fs.fsyncSync(fd);
      } finally {
        buf.fill(0);
      }
    } catch (err) {
      try { fs.closeSync(fd); } catch (e) {}
      secureUnlinkFile(keyFile);
      throw err;
    }
    fs.closeSync(fd);
    if (process.platform !== 'win32') {
      try { fs.chmodSync(keyFile, 0o600); } catch (e) {}
    }

    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      secureUnlinkFile(keyFile);
    };
    return { keyFile, cleanup };
  }

  /**
   * Executes `fn(keyFile)` with a freshly materialized `0o600` key file,
   * guaranteeing zero-wipe & unlink in `finally`.
   * @template T
   * @param {string} keyId
   * @param {(keyFile: string) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async withEphemeralKey(keyId, fn) {
    const { keyFile, cleanup } = this._materializeEphemeralKey(keyId);
    try {
      return await fn(keyFile);
    } finally {
      cleanup();
    }
  }

  // -------------------------------------------------------------------------
  // SSH Key Vault CRUD
  // -------------------------------------------------------------------------

  /**
   * Generates a new ed25519 SSH keypair via `ssh-keygen`, encrypts the private key
   * with AES-256-GCM + AAD, zero-wipes temp files, and returns ONLY sanitized metadata + publicKey.
   * @param {{ name: string, teamId?: string }} input
   */
  async generateKeyPair(input) {
    this._ensureLoaded();
    const name = validateDisplayName(input && input.name, 'name');
    const teamId = validateTeamId(input && input.teamId);
    const masterKey = this._loadOrCreateMasterKey();

    const id = `fk_${crypto.randomBytes(8).toString('hex')}`;
    ensureSecureDir(this.tmpDir);
    const tmpPriv = assertContainedPath(this.tmpDir, `gen_${crypto.randomBytes(8).toString('hex')}`);
    const tmpPub = `${tmpPriv}.pub`;

    try {
      await this._execFile(
        'ssh-keygen',
        ['-t', 'ed25519', '-a', '16', '-N', '', '-C', `culkibo-${id}`, '-f', tmpPriv],
        { timeout: 15000 }
      );

      if (!fs.existsSync(tmpPriv) || !fs.existsSync(tmpPub)) {
        throw createFleetError('ssh-keygen no generó los archivos de clave esperados', 'KEYGEN_FAILED', 500);
      }

      const privatePem = fs.readFileSync(tmpPriv, 'utf8');
      const publicRaw = fs.readFileSync(tmpPub, 'utf8').trim();
      const fp = computeSshFingerprint(publicRaw);
      const privateKeyEnc = encryptPrivateKey(privatePem, id, masterKey);
      const now = new Date().toISOString();

      /** @type {FleetKeyRecord} */
      const record = {
        id,
        name,
        teamId,
        keyType: fp.keyType,
        publicKey: fp.normalizedLine,
        fingerprint: fp.fingerprint,
        privateKeyEnc,
        createdAt: now,
        updatedAt: now
      };

      this._keys.set(id, record);
      this._saveKeys();
      this._audit('fleet.key_generated', id, { name, teamId, keyType: fp.keyType, fingerprint: fp.fingerprint });
      return this.sanitizeKey(record);
    } catch (err) {
      /** @type {any} */
      const e = err;
      if (e && e.code && String(e.code).startsWith('FLEET_')) throw e;
      if (e && e.statusCode) throw e;
      throw createFleetError(
        `Error generando par de claves SSH ed25519: ${e && e.message ? e.message : String(e)}`,
        'KEYGEN_FAILED',
        500
      );
    } finally {
      secureUnlinkFile(tmpPriv);
      secureUnlinkFile(tmpPub);
    }
  }

  /**
   * Imports an existing unencrypted SSH private key (OpenSSH/PEM), validates it via `ssh-keygen -y -P ''`,
   * derives its public key & SHA-256 fingerprint, encrypts with AES-256-GCM + AAD, and zero-wipes temp files.
   * @param {{ name: string, privateKeyPem?: string, privateKey?: string, teamId?: string }} input
   */
  async importKey(input) {
    this._ensureLoaded();
    const name = validateDisplayName(input && input.name, 'name');
    const teamId = validateTeamId(input && input.teamId);
    const rawPem = String((input && (input.privateKeyPem ?? input.privateKey)) || '').trim();

    if (!rawPem || rawPem.length > 16384) {
      throw createFleetError('Clave privada SSH vacía o demasiado grande (máx. 16 KB)', 'INVALID_PRIVATE_KEY', 400);
    }
    if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/i.test(rawPem) || /Proc-Type:\s*4,\s*ENCRYPTED/i.test(rawPem)) {
      throw createFleetError(
        'Las claves SSH protegidas con passphrase no están soportadas; usa una clave dedicada sin passphrase.',
        'PASSPHRASE_UNSUPPORTED',
        400
      );
    }
    if (!/-----BEGIN (?:OPENSSH|RSA|EC|PRIVATE) PRIVATE KEY-----[\s\S]+-----END (?:OPENSSH|RSA|EC|PRIVATE) PRIVATE KEY-----/.test(rawPem)) {
      throw createFleetError('Formato PEM/OpenSSH de clave privada inválido', 'INVALID_PRIVATE_KEY', 400);
    }

    const masterKey = this._loadOrCreateMasterKey();
    const id = `fk_${crypto.randomBytes(8).toString('hex')}`;
    ensureSecureDir(this.tmpDir);
    const tmpPriv = assertContainedPath(this.tmpDir, `imp_${crypto.randomBytes(8).toString('hex')}`);

    try {
      const fd = fs.openSync(tmpPriv, 'wx', 0o600);
      try {
        const buf = Buffer.from(`${rawPem}\n`, 'utf8');
        try {
          fs.writeSync(fd, buf, 0, buf.length, 0);
          fs.fsyncSync(fd);
        } finally {
          buf.fill(0);
        }
      } finally {
        fs.closeSync(fd);
      }
      if (process.platform !== 'win32') {
        try { fs.chmodSync(tmpPriv, 0o600); } catch (e) {}
      }

      let pubOut;
      try {
        const res = await this._execFile('ssh-keygen', ['-y', '-P', '', '-f', tmpPriv], { timeout: 10000 });
        pubOut = res.stdout.trim();
      } catch (err) {
        /** @type {any} */
        const e = err;
        const msg = `${e && e.stderr ? e.stderr : ''} ${e && e.message ? e.message : ''}`;
        if (/passphrase|incorrect|decrypt/i.test(msg)) {
          throw createFleetError(
            'La clave SSH requiere passphrase o no se pudo leer; importa una clave dedicada sin passphrase.',
            'PASSPHRASE_UNSUPPORTED',
            400
          );
        }
        throw createFleetError('Clave privada SSH inválida o corrupta', 'INVALID_PRIVATE_KEY', 400);
      }

      const fp = computeSshFingerprint(pubOut);
      const privateKeyEnc = encryptPrivateKey(`${rawPem}\n`, id, masterKey);
      const now = new Date().toISOString();

      /** @type {FleetKeyRecord} */
      const record = {
        id,
        name,
        teamId,
        keyType: fp.keyType,
        publicKey: fp.normalizedLine,
        fingerprint: fp.fingerprint,
        privateKeyEnc,
        createdAt: now,
        updatedAt: now
      };

      this._keys.set(id, record);
      this._saveKeys();
      this._audit('fleet.key_imported', id, { name, teamId, keyType: fp.keyType, fingerprint: fp.fingerprint });
      return this.sanitizeKey(record);
    } finally {
      secureUnlinkFile(tmpPriv);
    }
  }

  /**
   * Lists sanitized SSH keys (never returns private key material).
   * @param {{ teamId?: string }} [filters]
   */
  listKeys(filters = {}) {
    this._ensureLoaded();
    const teamFilter = filters && filters.teamId ? String(filters.teamId).trim() : '';
    const out = [];
    for (const k of this._keys.values()) {
      if (teamFilter && k.teamId !== teamFilter) continue;
      out.push(this.sanitizeKey(k));
    }
    return out;
  }

  /** @param {string} keyId */
  getKey(keyId) {
    this._ensureLoaded();
    const k = this._keys.get(String(keyId || ''));
    return k ? this.sanitizeKey(k) : null;
  }

  /**
   * Deletes an SSH key unless referenced by any registered server.
   * @param {string} keyId
   */
  deleteKey(keyId) {
    this._ensureLoaded();
    const id = String(keyId || '').trim();
    if (!this._keys.has(id)) {
      throw createFleetError(`Clave SSH no encontrada: ${id}`, 'KEY_NOT_FOUND', 404);
    }
    const referencing = [];
    for (const s of this._servers.values()) {
      if (s.keyId === id) referencing.push(s.id);
    }
    if (referencing.length > 0) {
      throw createFleetError(
        `No se puede eliminar la clave "${id}" porque está en uso por los servidores: ${referencing.join(', ')}`,
        'KEY_IN_USE',
        409,
        { serverIds: referencing }
      );
    }
    this._keys.delete(id);
    this._saveKeys();
    this._audit('fleet.key_deleted', id);
    return { deleted: true, id };
  }

  // -------------------------------------------------------------------------
  // Server Fleet CRUD
  // -------------------------------------------------------------------------

  /**
   * Lists the virtual `'local'` node (by default) plus all remote fleet servers.
   * @param {{ teamId?: string, tag?: string, region?: string, includeLocal?: boolean }} [filters]
   */
  listServers(filters = {}) {
    this._ensureLoaded();
    const teamFilter = filters && filters.teamId ? String(filters.teamId).trim() : '';
    const tagFilter = filters && filters.tag ? String(filters.tag).trim().toLowerCase() : '';
    const regionFilter = filters && filters.region ? String(filters.region).trim().toLowerCase() : '';
    const includeLocal = filters.includeLocal !== false;

    const out = [];
    if (includeLocal) {
      const localNode = this._buildVirtualLocalServer();
      const matchesTag = !tagFilter || localNode.tags.includes(tagFilter);
      const matchesRegion = !regionFilter || localNode.region === regionFilter;
      if (matchesTag && matchesRegion) {
        out.push(localNode);
      }
    }

    for (const s of this._servers.values()) {
      if (teamFilter && s.teamId !== teamFilter) continue;
      if (regionFilter && s.region !== regionFilter) continue;
      if (tagFilter && !(s.tags || []).includes(tagFilter)) continue;
      out.push(this.sanitizeServer(s));
    }
    return out;
  }

  /** @param {string} serverId */
  getServer(serverId) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      return this._buildVirtualLocalServer();
    }
    const s = this._servers.get(id);
    return s ? this.sanitizeServer(s) : null;
  }

  /**
   * Registers a new remote SSH server in the fleet.
   * Supports referencing an existing `keyId`, generating a key (`generateKey: true`),
   * or importing a private key (`privateKeyPem` / `privateKey`).
   * @param {{
   *   id?: string,
   *   name: string,
   *   host: string,
   *   port?: number,
   *   user?: string,
   *   keyId?: string,
   *   generateKey?: boolean,
   *   privateKeyPem?: string,
   *   privateKey?: string,
   *   dockerSocketPath?: string,
   *   caddyAdminPort?: number,
   *   region?: string,
   *   tags?: string[],
   *   teamId?: string,
   *   hostKeyPolicy?: 'tofu' | 'strict',
   *   expectedFingerprint?: string | null,
   *   pinOnAdd?: boolean
   * }} input
   */
  async addServer(input) {
    this._ensureLoaded();
    if (!input || typeof input !== 'object') {
      throw createFleetError('Datos de servidor requeridos', 'INVALID_INPUT', 400);
    }

    const id = input.id != null && String(input.id).trim() !== ''
      ? validateServerId(input.id)
      : `srv_${crypto.randomBytes(6).toString('hex')}`;

    if (this._servers.has(id)) {
      throw createFleetError(`Ya existe un servidor con id "${id}"`, 'SERVER_EXISTS', 409);
    }

    const name = validateDisplayName(input.name, 'name');
    const { host, pinnedIp } = await assertSafeFleetHost(input.host, { resolveHost: this._resolveHost });
    const port = validatePort(input.port == null ? DEFAULTS.sshPort : input.port, 'port');
    const user = validateSshUser(input.user);
    const dockerSocketPath = validateDockerSocketPath(input.dockerSocketPath);
    const caddyAdminPort = validatePort(
      input.caddyAdminPort == null ? DEFAULTS.caddyAdminPort : input.caddyAdminPort,
      'caddyAdminPort'
    );
    const region = validateRegion(input.region);
    const tags = validateTags(input.tags);
    const teamId = validateTeamId(input.teamId);

    const policyRaw = String(input.hostKeyPolicy || DEFAULTS.hostKeyPolicy).trim().toLowerCase();
    if (policyRaw !== 'tofu' && policyRaw !== 'strict') {
      throw createFleetError('hostKeyPolicy inválido (usa "tofu" o "strict")', 'INVALID_HOST_KEY_POLICY', 400);
    }
    /** @type {'tofu' | 'strict'} */
    const hostKeyPolicy = policyRaw;

    /** @type {string | null} */
    let expectedFingerprint = null;
    if (input.expectedFingerprint != null && String(input.expectedFingerprint).trim() !== '') {
      expectedFingerprint = normalizeFingerprint(String(input.expectedFingerprint));
    }
    if (hostKeyPolicy === 'strict' && !expectedFingerprint) {
      throw createFleetError(
        'hostKeyPolicy="strict" requiere expectedFingerprint ("SHA256:...") al registrar el servidor',
        'EXPECTED_FINGERPRINT_REQUIRED',
        400
      );
    }

    // Resolve or create SSH key
    let keyId = input.keyId ? String(input.keyId).trim() : '';
    /** @type {{ id: string } | null} */
    let createdKeyRecord = null;
    if (keyId) {
      if (!KEY_ID_RE.test(keyId) || !this._keys.has(keyId)) {
        throw createFleetError(`Clave SSH no encontrada: ${keyId}`, 'KEY_NOT_FOUND', 404);
      }
      const existingKey = this._keys.get(keyId);
      const keyTeamId = (existingKey && existingKey.teamId) || DEFAULTS.teamId;
      if (keyTeamId !== teamId) {
        throw createFleetError(
          `La clave SSH "${keyId}" pertenece a otro equipo y no puede asignarse a este servidor`,
          'KEY_TEAM_MISMATCH',
          403
        );
      }
    } else if (input.privateKeyPem || input.privateKey) {
      createdKeyRecord = await this.importKey({
        name: `${name} key`,
        privateKeyPem: input.privateKeyPem || input.privateKey,
        teamId
      });
      keyId = createdKeyRecord.id;
    } else if (input.generateKey) {
      createdKeyRecord = await this.generateKeyPair({
        name: `${name} key`,
        teamId
      });
      keyId = createdKeyRecord.id;
    } else {
      throw createFleetError('Debes especificar keyId, privateKeyPem o generateKey: true', 'KEY_REQUIRED', 400);
    }

    const now = new Date().toISOString();
    /** @type {FleetServerRecord} */
    const record = {
      id,
      name,
      host,
      port,
      user,
      keyId,
      dockerSocketPath,
      caddyAdminPort,
      region,
      tags,
      teamId,
      hostKeyPolicy,
      expectedFingerprint,
      hostKeyFingerprint: null,
      hostKeyType: null,
      hostKeyLine: null,
      hostKeyPinnedAt: null,
      status: 'pending',
      maintenanceState: 'active',
      maintenanceReason: null,
      maintenanceSince: null,
      statusReason: null,
      statusFix: null,
      warnings: [],
      lastProbedAt: null,
      resources: null,
      consecutiveFailures: 0,
      createdAt: now,
      updatedAt: now
    };

    if (input.pinOnAdd) {
      try {
        await this._pinHostKeyOnRecord(record, pinnedIp, expectedFingerprint);
      } catch (err) {
        if (createdKeyRecord) {
          try { this.deleteKey(createdKeyRecord.id); } catch (e) {}
        }
        throw err;
      }
    }

    this._servers.set(id, record);
    this._saveServers();
    if (record.hostKeyLine) {
      this._writeKnownHostsFile(record);
    }

    if (this._autoMonitor && this._servers.size >= 1) {
      this.startMonitor();
    }

    this._audit('fleet.server_added', id, { name, host, port, user, region, teamId, hostKeyPolicy });
    const sanitized = this.sanitizeServer(record);
    this.emit('server:added', sanitized);
    const keyObj = this._keys.get(keyId);
    return keyObj
      ? { ...sanitized, publicKey: keyObj.publicKey, keyFingerprint: keyObj.fingerprint }
      : sanitized;
  }

  /**
   * Updates an existing remote server atomically (validates full cloned copy before committing).
   * Rotating key/endpoint gracefully drains active tunnels (never kills in-flight leases).
   * Changing host/port clears the pinned host key so the new endpoint is re-verified.
   * @param {string} serverId
   * @param {Record<string, any>} patch
   */
  async updateServer(serverId, patch) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('El servidor virtual "local" no puede modificarse', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }
    if (!patch || typeof patch !== 'object') {
      throw createFleetError('Datos de actualización requeridos', 'INVALID_INPUT', 400);
    }

    // Clone record first so any validation/async failure leaves `server` untouched (atomic update)
    /** @type {FleetServerRecord} */
    const next = {
      ...server,
      tags: Array.isArray(server.tags) ? [...server.tags] : [],
      warnings: Array.isArray(server.warnings) ? [...server.warnings] : [],
      resources: server.resources ? { ...server.resources } : null,
      maintenanceState: VALID_MAINTENANCE_STATES.has(server.maintenanceState) ? server.maintenanceState : 'active',
      maintenanceReason: server.maintenanceReason || null,
      maintenanceSince: server.maintenanceSince || null
    };

    let endpointChanged = false;
    let tunnelParamsChanged = false;

    if (patch.name !== undefined) {
      next.name = validateDisplayName(patch.name, 'name');
    }
    if (patch.host !== undefined) {
      const { host } = await assertSafeFleetHost(patch.host, { resolveHost: this._resolveHost });
      if (host !== next.host) {
        next.host = host;
        endpointChanged = true;
        tunnelParamsChanged = true;
      }
    }
    if (patch.port !== undefined) {
      const port = validatePort(patch.port, 'port');
      if (port !== next.port) {
        next.port = port;
        endpointChanged = true;
        tunnelParamsChanged = true;
      }
    }
    if (patch.user !== undefined) {
      const user = validateSshUser(patch.user);
      if (user !== next.user) {
        next.user = user;
        tunnelParamsChanged = true;
      }
    }
    if (patch.keyId !== undefined) {
      const keyId = String(patch.keyId || '').trim();
      if (!KEY_ID_RE.test(keyId) || !this._keys.has(keyId)) {
        throw createFleetError(`Clave SSH no encontrada: ${keyId}`, 'KEY_NOT_FOUND', 404);
      }
      const targetKey = this._keys.get(keyId);
      const keyTeamId = (targetKey && targetKey.teamId) || DEFAULTS.teamId;
      const serverTeamId = next.teamId || DEFAULTS.teamId;
      if (keyTeamId !== serverTeamId) {
        throw createFleetError(
          `La clave SSH "${keyId}" pertenece a otro equipo y no puede asignarse a este servidor`,
          'KEY_TEAM_MISMATCH',
          403
        );
      }
      if (keyId !== next.keyId) {
        next.keyId = keyId;
        tunnelParamsChanged = true;
      }
    }
    if (patch.dockerSocketPath !== undefined) {
      const sock = validateDockerSocketPath(patch.dockerSocketPath);
      if (sock !== next.dockerSocketPath) {
        next.dockerSocketPath = sock;
        tunnelParamsChanged = true;
      }
    }
    if (patch.caddyAdminPort !== undefined) {
      next.caddyAdminPort = validatePort(patch.caddyAdminPort, 'caddyAdminPort');
    }
    if (patch.region !== undefined) {
      next.region = validateRegion(patch.region);
    }
    if (patch.tags !== undefined) {
      next.tags = validateTags(patch.tags);
    }
    if (patch.hostKeyPolicy !== undefined) {
      const policyRaw = String(patch.hostKeyPolicy).trim().toLowerCase();
      if (policyRaw !== 'tofu' && policyRaw !== 'strict') {
        throw createFleetError('hostKeyPolicy inválido (usa "tofu" o "strict")', 'INVALID_HOST_KEY_POLICY', 400);
      }
      next.hostKeyPolicy = policyRaw;
    }
    if (patch.expectedFingerprint !== undefined) {
      next.expectedFingerprint = patch.expectedFingerprint
        ? normalizeFingerprint(String(patch.expectedFingerprint))
        : null;
    }
    if (patch.maintenanceState !== undefined) {
      const nextState = validateMaintenanceState(patch.maintenanceState);
      if (nextState !== next.maintenanceState) {
        next.maintenanceState = nextState;
        next.maintenanceSince = nextState === 'active' ? null : (next.maintenanceSince || new Date().toISOString());
        if (nextState === 'active') next.maintenanceReason = null;
      }
    }
    if (patch.maintenanceReason !== undefined) {
      next.maintenanceReason = next.maintenanceState === 'active'
        ? null
        : validateMaintenanceReason(patch.maintenanceReason);
    }

    if (endpointChanged) {
      next.hostKeyFingerprint = null;
      next.hostKeyType = null;
      next.hostKeyLine = null;
      next.hostKeyPinnedAt = null;
      next.status = 'pending';
      next.statusReason = null;
      next.statusFix = null;
    }

    if (next.hostKeyPolicy === 'strict' && !next.expectedFingerprint && !next.hostKeyFingerprint) {
      throw createFleetError(
        'hostKeyPolicy="strict" requiere expectedFingerprint ("SHA256:...")',
        'EXPECTED_FINGERPRINT_REQUIRED',
        400
      );
    }

    // Re-check server still exists after async DNS resolution before committing
    if (!this._servers.has(id)) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    next.updatedAt = new Date().toISOString();
    this._servers.set(id, next);
    if (endpointChanged) {
      this._deleteKnownHostsFile(id);
    }
    this._saveServers();

    if (tunnelParamsChanged) {
      this.drainServerTunnels(id);
    }

    this._audit('fleet.server_updated', id, { endpointChanged, tunnelParamsChanged });
    const sanitized = this.sanitizeServer(next);
    this.emit('server:updated', sanitized);
    return sanitized;
  }

  /**
   * Removes a remote server from the fleet.
   * Refuses deletion if assigned projects exist or a tunnel lease is active unless `force: true`.
   * Stops background monitor automatically when the last remote server is removed.
   * @param {string} serverId
   * @param {{ force?: boolean, assignedProjectIds?: string[] }} [opts]
   */
  async deleteServer(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('El servidor virtual "local" no puede eliminarse', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    if (!this._servers.has(id)) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const assigned = Array.isArray(opts.assignedProjectIds) ? opts.assignedProjectIds : [];
    if (assigned.length > 0 && !opts.force) {
      throw createFleetError(
        `El servidor "${id}" tiene ${assigned.length} proyecto(s) asignado(s). Muévelos o usa force: true.`,
        'SERVER_HAS_PROJECTS',
        409,
        { projectIds: assigned }
      );
    }

    const activeTunnel = this._dockerTunnels.get(id);
    if (activeTunnel && activeTunnel.refCount > 0 && !opts.force) {
      throw createFleetError(
        `El servidor "${id}" tiene un túnel Docker en uso (refCount=${activeTunnel.refCount}). Espera o usa force: true.`,
        'SERVER_TUNNEL_BUSY',
        409
      );
    }

    if (activeTunnel) {
      this._closeTunnelImmediate(activeTunnel);
    }
    for (const dt of Array.from(this._drainingTunnels)) {
      if (dt.serverId === id) {
        this._closeTunnelImmediate(dt);
      }
    }

    this._deleteKnownHostsFile(id);
    this._servers.delete(id);
    this._nextProbeAt.delete(id);
    this._recentRemotePorts.delete(id);
    this._saveServers();

    if (this._servers.size === 0) {
      this.stopMonitor();
    }

    this._audit('fleet.server_deleted', id, { force: Boolean(opts.force) });
    this.emit('server:deleted', { id });
    return { deleted: true, id };
  }

  // -------------------------------------------------------------------------
  // Node Maintenance / Drain Mode, Smart Placement & Hardened VPS Bootstrap
  // -------------------------------------------------------------------------

  /**
   * Transitions a remote node between `'active'`, `'draining'`, and `'maintenance'`.
   * - `'active'`: accepts new deployments & placement scheduling.
   * - `'draining'`: cordons node (blocks new deploys & placement) while existing containers keep running.
   * - `'maintenance'`: cordons node and gracefully drains idle/completed SSH tunnels.
   *
   * @param {string} serverId
   * @param {'active' | 'draining' | 'maintenance' | {
   *   state?: string,
   *   mode?: string,
   *   maintenanceState?: string,
   *   reason?: string | null,
   *   drainTunnels?: boolean
   * }} input
   */
  setServerMaintenance(serverId, input) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('El servidor virtual "local" no admite modo mantenimiento de nodo', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const opts = typeof input === 'string' ? { state: input } : (input && typeof input === 'object' ? input : {});
    const nextState = validateMaintenanceState(opts.maintenanceState ?? opts.state ?? opts.mode);
    const reason = nextState === 'active'
      ? null
      : (opts.reason !== undefined ? validateMaintenanceReason(opts.reason) : (server.maintenanceReason || null));

    const previousState = VALID_MAINTENANCE_STATES.has(server.maintenanceState) ? server.maintenanceState : 'active';
    const now = new Date().toISOString();

    server.maintenanceState = nextState;
    server.maintenanceReason = reason;
    server.maintenanceSince = nextState === 'active' ? null : (server.maintenanceSince || now);
    server.updatedAt = now;
    this._saveServers();

    const shouldDrainTunnels = opts.drainTunnels === true || (nextState === 'maintenance' && opts.drainTunnels !== false);
    if (shouldDrainTunnels) {
      this.drainServerTunnels(id);
    }

    this._audit('fleet.server_maintenance', id, {
      previousState,
      maintenanceState: nextState,
      reason,
      drainedTunnels: shouldDrainTunnels
    });
    const sanitized = this.sanitizeServer(server);
    this.emit('server:maintenance', {
      serverId: id,
      previousState,
      maintenanceState: nextState,
      reason,
      server: sanitized
    });
    return sanitized;
  }

  /**
   * Checks whether a server is eligible to receive new deployments.
   * @param {string} serverId
   * @returns {{ schedulable: boolean, code: string | null, reason: string | null }}
   */
  isServerSchedulable(serverId) {
    this._ensureLoaded();
    const id = String(serverId || '').trim() || LOCAL_SERVER_ID;
    const server = this.getServer(id);
    if (!server) {
      return { schedulable: false, code: 'SERVER_NOT_FOUND', reason: `Servidor no encontrado: ${id}` };
    }
    if (server.maintenanceState && server.maintenanceState !== 'active') {
      return {
        schedulable: false,
        code: 'SERVER_IN_MAINTENANCE',
        reason: `El servidor "${id}" está en modo "${server.maintenanceState}"${server.maintenanceReason ? ` (${server.maintenanceReason})` : ''}`
      };
    }
    if (server.status === 'host_key_mismatch') {
      return {
        schedulable: false,
        code: 'HOST_KEY_MISMATCH',
        reason: `El servidor "${id}" está bloqueado por cambio de clave de host SSH`
      };
    }
    if (server.status === 'offline' || server.status === 'degraded') {
      return {
        schedulable: false,
        code: 'SERVER_UNHEALTHY',
        reason: `El servidor "${id}" no está saludable (status=${server.status})`
      };
    }
    return { schedulable: true, code: null, reason: null };
  }

  /**
   * Smart placement scheduler: selects the healthiest schedulable fleet node
   * based on free RAM, CPU load, disk headroom, latency, region, tags, and workload spread.
   * Never selects nodes in `draining`/`maintenance` mode or `offline`/`degraded`/`host_key_mismatch`.
   *
   * @param {{
   *   minFreeRamMb?: number,
   *   minFreeDiskGb?: number,
   *   region?: string | null,
   *   preferRegion?: string | null,
   *   tags?: string[],
   *   preferredTags?: string[],
   *   teamId?: string | null,
   *   preferLocal?: boolean,
   *   includeLocal?: boolean,
   *   excludeServerIds?: string[],
   *   requireCaddy?: boolean,
   *   requireDocker?: boolean,
   *   strategy?: 'balanced' | 'most-free-ram' | 'least-loaded' | 'lowest-latency',
   *   projectCounts?: Record<string, number>
   * }} [criteria]
   */
  selectBestServer(criteria = {}) {
    this._ensureLoaded();
    const opts = criteria && typeof criteria === 'object' ? criteria : {};
    const strategyRaw = String(opts.strategy || 'balanced').trim().toLowerCase();
    if (!VALID_PLACEMENT_STRATEGIES.has(strategyRaw)) {
      throw createFleetError(
        'strategy inválida (usa "balanced", "most-free-ram", "least-loaded" o "lowest-latency")',
        'INVALID_PLACEMENT_STRATEGY',
        400
      );
    }
    /** @type {'balanced' | 'most-free-ram' | 'least-loaded' | 'lowest-latency'} */
    const strategy = /** @type {any} */ (strategyRaw);

    const minFreeRamMb = Math.max(0, Number(opts.minFreeRamMb) || 0);
    const minFreeDiskGb = Math.max(0, Number(opts.minFreeDiskGb) || 0);
    const requiredRegion = opts.region ? validateRegion(opts.region) : null;
    const preferRegion = opts.preferRegion ? validateRegion(opts.preferRegion) : null;
    const requiredTags = opts.tags ? validateTags(opts.tags) : [];
    const preferredTags = opts.preferredTags ? validateTags(opts.preferredTags) : [];
    const teamId = opts.teamId ? validateTeamId(opts.teamId) : null;
    const includeLocal = opts.includeLocal !== false;
    const preferLocal = Boolean(opts.preferLocal);
    const requireDocker = opts.requireDocker !== false;
    const requireCaddy = Boolean(opts.requireCaddy);
    const excludeSet = new Set(Array.isArray(opts.excludeServerIds) ? opts.excludeServerIds.map((x) => String(x || '').trim()) : []);
    const projectCounts = opts.projectCounts && typeof opts.projectCounts === 'object' ? opts.projectCounts : {};

    const allServers = this.listServers({ includeLocal });

    const weights = strategy === 'most-free-ram'
      ? { ram: 65, cpu: 15, disk: 10, latency: 10 }
      : strategy === 'least-loaded'
        ? { ram: 20, cpu: 60, disk: 10, latency: 10 }
        : strategy === 'lowest-latency'
          ? { ram: 15, cpu: 10, disk: 5, latency: 70 }
          : { ram: 40, cpu: 30, disk: 15, latency: 15 };

    /** @type {Array<{ serverId: string, name: string, region: string, score: number, breakdown: Record<string, number>, server: any }>} */
    const candidates = [];
    /** @type {Array<{ serverId: string, name: string, reasons: string[] }>} */
    const rejected = [];

    for (const srv of allServers) {
      /** @type {string[]} */
      const reasons = [];
      if (excludeSet.has(srv.id)) reasons.push('excluded');
      if (teamId && !srv.isLocal && srv.teamId !== teamId) reasons.push('team_mismatch');
      if (srv.maintenanceState && srv.maintenanceState !== 'active') {
        reasons.push(`maintenance_state:${srv.maintenanceState}`);
      }
      if (srv.status !== 'online') {
        reasons.push(`status:${srv.status || 'pending'}`);
      }
      if (requiredRegion && srv.region !== requiredRegion) {
        reasons.push(`region_mismatch:${srv.region}`);
      }
      const srvTags = Array.isArray(srv.tags) ? srv.tags : [];
      for (const reqTag of requiredTags) {
        if (!srvTags.includes(reqTag)) {
          reasons.push(`missing_tag:${reqTag}`);
        }
      }

      const res = srv.resources || null;
      if (requireDocker && (!res || !res.dockerReady)) {
        reasons.push('docker_not_ready');
      }
      if (requireCaddy && (!res || !res.caddyAvailable)) {
        reasons.push('caddy_unavailable');
      }
      const freeRamMb = res && Number.isFinite(res.memoryAvailableMb) ? res.memoryAvailableMb : 0;
      const totalRamMb = res && Number.isFinite(res.memoryTotalMb) ? res.memoryTotalMb : 0;
      if (minFreeRamMb > 0 && freeRamMb < minFreeRamMb) {
        reasons.push(`insufficient_ram:${freeRamMb}mb<${minFreeRamMb}mb`);
      }
      const freeDiskGb = res && res.diskAvailableGb != null && Number.isFinite(res.diskAvailableGb) ? res.diskAvailableGb : null;
      const totalDiskGb = res && res.diskTotalGb != null && Number.isFinite(res.diskTotalGb) ? res.diskTotalGb : null;
      if (minFreeDiskGb > 0) {
        if (freeDiskGb == null) {
          if (!srv.isLocal) reasons.push('disk_metric_missing');
        } else if (freeDiskGb < minFreeDiskGb) {
          reasons.push(`insufficient_disk:${freeDiskGb}gb<${minFreeDiskGb}gb`);
        }
      }

      if (reasons.length > 0) {
        rejected.push({ serverId: srv.id, name: srv.name, reasons });
        continue;
      }

      // Compute normalized resource scores
      const ramRatio = totalRamMb > 0 ? Math.max(0, Math.min(1, freeRamMb / totalRamMb)) : 0;
      const ramHeadroom = Math.max(0, Math.min(1, freeRamMb / 8192));
      const ramNorm = ramRatio * 0.6 + ramHeadroom * 0.4;

      const cpus = res && res.cpus > 0 ? res.cpus : 1;
      const load1m = res && Number.isFinite(res.load1m) && res.load1m >= 0 ? res.load1m : 0;
      const cpuNorm = Math.max(0, Math.min(1, 1 - (load1m / cpus)));

      const diskNorm = (totalDiskGb && totalDiskGb > 0 && freeDiskGb != null)
        ? Math.max(0, Math.min(1, freeDiskGb / totalDiskGb))
        : 0.6;

      const latencyMs = res && Number.isFinite(res.latencyMs) && res.latencyMs >= 0 ? res.latencyMs : 150;
      const latencyNorm = Math.max(0, Math.min(1, 1 - (latencyMs / 500)));

      const ramScore = Number((ramNorm * weights.ram).toFixed(2));
      const cpuScore = Number((cpuNorm * weights.cpu).toFixed(2));
      const diskScore = Number((diskNorm * weights.disk).toFixed(2));
      const latencyScore = Number((latencyNorm * weights.latency).toFixed(2));

      let affinityBonus = 0;
      if (preferLocal && srv.isLocal) affinityBonus += 8;
      if (preferRegion && srv.region === preferRegion) affinityBonus += 6;
      let tagHits = 0;
      for (const pt of preferredTags) {
        if (srvTags.includes(pt)) tagHits++;
      }
      affinityBonus += Math.min(9, tagHits * 3);

      const assignedCount = Math.max(0, Number(projectCounts[srv.id]) || 0);
      const spreadPenalty = Math.min(12, assignedCount * 2);

      const score = Number((ramScore + cpuScore + diskScore + latencyScore + affinityBonus - spreadPenalty).toFixed(2));
      candidates.push({
        serverId: srv.id,
        name: srv.name,
        region: srv.region,
        score,
        breakdown: {
          ramScore,
          cpuScore,
          diskScore,
          latencyScore,
          affinityBonus,
          spreadPenalty
        },
        server: srv
      });
    }

    candidates.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const ramDiff = (b.server.resources?.memoryAvailableMb || 0) - (a.server.resources?.memoryAvailableMb || 0);
      if (ramDiff !== 0) return ramDiff;
      const latDiff = (a.server.resources?.latencyMs ?? 9999) - (b.server.resources?.latencyMs ?? 9999);
      if (latDiff !== 0) return latDiff;
      return a.serverId.localeCompare(b.serverId);
    });

    const best = candidates[0] || null;
    return {
      selected: best ? best.server : null,
      serverId: best ? best.serverId : null,
      score: best ? best.score : null,
      strategy,
      candidates,
      rejected
    };
  }

  /**
   * Generates an auditable, idempotent 1-command hardened VPS bootstrap script
   * (Docker Engine + Caddy bound to 127.0.0.1:<caddyAdminPort> + non-root deploy user
   * + SSH key install + UFW with control-plane anti-LIMIT allowlist + sshd hardening).
   * Pure deterministic template generation — ZERO shell execution on the Culkibo host.
   *
   * @param {string} serverId
   * @param {{
   *   deployUser?: string,
   *   useRoot?: boolean,
   *   sshPort?: number,
   *   caddyAdminPort?: number,
   *   controlPlaneIp?: string | null,
   *   installCaddy?: boolean,
   *   configureUfw?: boolean,
   *   hardenSsh?: boolean,
   *   disableRootSsh?: boolean
   * }} [opts]
   */
  generateBootstrapScript(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('No se genera script de bootstrap VPS para el nodo "local"', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }
    const key = this._keys.get(server.keyId);
    if (!key) {
      throw createFleetError(`Clave SSH no encontrada para el servidor "${id}": ${server.keyId}`, 'KEY_NOT_FOUND', 404);
    }

    // Re-validate public key strictly so zero shell metacharacters can ever enter the template
    const parsedPub = computeSshFingerprint(key.publicKey);
    const safePubLine = `${parsedPub.keyType} ${parsedPub.keyBase64} culkibo-${server.id}`;

    const useRoot = Boolean(opts.useRoot);
    const defaultUser = useRoot ? 'root' : (server.user === 'root' ? 'deploy' : server.user);
    const deployUser = validateSshUser(opts.deployUser ?? defaultUser);
    const sshPort = validatePort(opts.sshPort ?? server.port, 'sshPort');
    const caddyAdminPort = validatePort(opts.caddyAdminPort ?? server.caddyAdminPort ?? DEFAULTS.caddyAdminPort, 'caddyAdminPort');
    const controlPlaneIp = validateControlPlaneCidr(opts.controlPlaneIp);
    const installCaddy = opts.installCaddy !== false;
    const configureUfw = opts.configureUfw !== false;
    const hardenSsh = opts.hardenSsh !== false;
    const disableRootSsh = Boolean(opts.disableRootSsh) && deployUser !== 'root';

    /** @type {string[]} */
    const steps = ['preflight', 'user_and_ssh_key', 'docker'];
    /** @type {string[]} */
    const lines = [
      '#!/usr/bin/env bash',
      '# Culkibo Hardened Fleet Node Bootstrap (auditable & idempotent)',
      `# Server ID: ${server.id} | SSH Port: ${sshPort} | Deploy User: ${deployUser}`,
      `# Vault Key: ${key.id} (${parsedPub.fingerprint})`,
      'set -euo pipefail',
      'umask 027',
      '',
      'if [ "$(id -u)" -ne 0 ]; then',
      '  echo "[culkibo-bootstrap] ERROR: ejecuta este script como root o con sudo." >&2',
      '  exit 1',
      'fi',
      '',
      `DEPLOY_USER='${deployUser}'`,
      `SSH_PORT='${sshPort}'`,
      `CADDY_ADMIN_PORT='${caddyAdminPort}'`,
      `PUB_KEY='${safePubLine}'`,
      '',
      'echo "[1/6] Preflight y paquetes base..."',
      'if command -v apt-get >/dev/null 2>&1; then',
      '  export DEBIAN_FRONTEND=noninteractive',
      '  apt-get update -qq',
      '  apt-get install -y -qq ca-certificates curl gnupg lsb-release sudo ufw >/dev/null',
      'fi',
      '',
      'echo "[2/6] Usuario de despliegue y clave SSH autorizada..."',
      'if [ "$DEPLOY_USER" != "root" ]; then',
      '  if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then',
      '    useradd -m -s /bin/bash "$DEPLOY_USER"',
      '  fi',
      '  USER_HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"',
      'else',
      '  USER_HOME="/root"',
      'fi',
      'install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "${USER_HOME}/.ssh"',
      'AUTH_KEYS="${USER_HOME}/.ssh/authorized_keys"',
      'touch "$AUTH_KEYS"',
      'grep -qxF "$PUB_KEY" "$AUTH_KEYS" || printf "%s\\n" "$PUB_KEY" >> "$AUTH_KEYS"',
      'chown "$DEPLOY_USER:$DEPLOY_USER" "$AUTH_KEYS"',
      'chmod 600 "$AUTH_KEYS"',
      '',
      'echo "[3/6] Instalando y verificando Docker Engine..."',
      'if ! command -v docker >/dev/null 2>&1; then',
      '  curl -fsSL https://get.docker.com | sh',
      'fi',
      'systemctl enable --now docker >/dev/null 2>&1 || true',
      'if [ "$DEPLOY_USER" != "root" ]; then',
      '  usermod -aG docker "$DEPLOY_USER"',
      'fi',
      ''
    ];

    if (installCaddy) {
      steps.push('caddy_loopback_admin');
      lines.push(
        'echo "[4/6] Instalando Caddy con Admin API restringida a 127.0.0.1:${CADDY_ADMIN_PORT}..."',
        'if ! command -v caddy >/dev/null 2>&1; then',
        '  if command -v apt-get >/dev/null 2>&1; then',
        '    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null',
        '    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg',
        '    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list',
        '    apt-get update -qq && apt-get install -y -qq caddy >/dev/null',
        '  fi',
        'fi',
        'install -d -m 755 /etc/caddy',
        'if [ ! -f /etc/caddy/Caddyfile ] || ! grep -q "admin 127.0.0.1:" /etc/caddy/Caddyfile; then',
        '  cat > /etc/caddy/Caddyfile <<CADDY_EOF',
        '{',
        `  admin 127.0.0.1:${caddyAdminPort}`,
        '}',
        'CADDY_EOF',
        'fi',
        'systemctl enable --now caddy >/dev/null 2>&1 || systemctl reload caddy >/dev/null 2>&1 || true',
        ''
      );
    }

    if (configureUfw) {
      steps.push('ufw');
      lines.push(
        'echo "[5/6] Configurando cortafuegos UFW (sin bloqueos LIMIT al plano de control)..."',
        'if command -v ufw >/dev/null 2>&1; then',
        '  ufw default deny incoming >/dev/null',
        '  ufw default allow outgoing >/dev/null',
        '  ufw allow 80/tcp comment "Culkibo HTTP" >/dev/null',
        '  ufw allow 443/tcp comment "Culkibo HTTPS" >/dev/null',
        '  ufw allow 443/udp comment "Culkibo HTTP3-QUIC" >/dev/null'
      );
      if (controlPlaneIp) {
        lines.push(
          `  ufw allow from ${controlPlaneIp} to any port "${sshPort}" proto tcp comment "Culkibo Control Plane SSH" >/dev/null`,
          `  ufw limit "${sshPort}/tcp" comment "SSH public rate-limit" >/dev/null`
        );
      } else {
        lines.push(
          `  ufw allow "${sshPort}/tcp" comment "Culkibo Fleet SSH" >/dev/null`
        );
      }
      lines.push(
        '  ufw --force enable >/dev/null',
        'fi',
        ''
      );
    }

    if (hardenSsh) {
      steps.push('sshd_hardening');
      const permitRoot = disableRootSsh ? 'no' : 'prohibit-password';
      lines.push(
        'echo "[6/6] Endureciendo sshd (solo llave pública, validación previa con sshd -t)..."',
        'install -d -m 755 /etc/ssh/sshd_config.d',
        'cat > /etc/ssh/sshd_config.d/99-culkibo-hardening.conf <<SSHD_EOF',
        '# Managed by Culkibo Fleet Bootstrap',
        `Port ${sshPort}`,
        'PasswordAuthentication no',
        'KbdInteractiveAuthentication no',
        'ChallengeResponseAuthentication no',
        'PubkeyAuthentication yes',
        `PermitRootLogin ${permitRoot}`,
        'X11Forwarding no',
        'AllowAgentForwarding no',
        'MaxAuthTries 4',
        'SSHD_EOF',
        'if sshd -t; then',
        '  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true',
        'else',
        '  rm -f /etc/ssh/sshd_config.d/99-culkibo-hardening.conf',
        '  echo "[culkibo-bootstrap] ERROR: sshd -t falló; revertido para evitar bloqueo." >&2',
        '  exit 1',
        'fi',
        ''
      );
    }

    steps.push('host_fingerprint');
    lines.push(
      'echo "=== Culkibo Fleet Node Ready ==="',
      'if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then',
      '  printf "HOST_KEY_SHA256=%s\\n" "$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk \'{print $2}\')"',
      'fi',
      'docker --version || true',
      'caddy version || true'
    );

    const script = lines.join('\n') + '\n';
    if (script.includes(BOOTSTRAP_SENTINEL)) {
      throw createFleetError('Error interno generando delimitador de bootstrap', 'BOOTSTRAP_GENERATION_FAILED', 500);
    }
    const sha256 = crypto.createHash('sha256').update(script, 'utf8').digest('hex');
    const oneLiner = `cat <<'${BOOTSTRAP_SENTINEL}' | sudo bash\n${script}${BOOTSTRAP_SENTINEL}`;

    this._audit('fleet.bootstrap_generated', id, {
      deployUser,
      sshPort,
      caddyAdminPort,
      hasControlPlaneIp: Boolean(controlPlaneIp),
      installCaddy,
      configureUfw,
      hardenSsh,
      sha256: sha256.slice(0, 16)
    });

    return {
      serverId: server.id,
      serverName: server.name,
      host: server.host,
      deployUser,
      sshPort,
      caddyAdminPort,
      controlPlaneIp,
      keyId: key.id,
      keyFingerprint: parsedPub.fingerprint,
      sha256,
      script,
      oneLiner,
      steps
    };
  }

  // -------------------------------------------------------------------------
  // TOFU & Strict Host-Key Pinning
  // -------------------------------------------------------------------------

  /** @param {string} serverId */
  _getKnownHostsPath(serverId) {
    validateServerId(serverId);
    return assertContainedPath(this.knownHostsDir, serverId);
  }

  /** @param {FleetServerRecord} server */
  _writeKnownHostsFile(server) {
    if (!server.hostKeyLine) return '';
    const khPath = this._getKnownHostsPath(server.id);
    writeTextAtomic0600(khPath, `${server.hostKeyLine.trim()}\n`);
    return khPath;
  }

  /** @param {string} serverId */
  _deleteKnownHostsFile(serverId) {
    try {
      const khPath = this._getKnownHostsPath(serverId);
      secureUnlinkFile(khPath);
    } catch (e) {}
  }

  /**
   * Builds normalized per-server `known_hosts` lines for `server.host` (matching `HostKeyAlias`).
   * @param {FleetServerRecord} server
   * @param {string} keyType
   * @param {string} keyBase64
   */
  _formatKnownHostsLines(server, keyType, keyBase64) {
    const lines = [`${server.host} ${keyType} ${keyBase64}`];
    if (server.port !== 22) {
      lines.push(`[${server.host}]:${server.port} ${keyType} ${keyBase64}`);
    }
    return lines.join('\n');
  }

  /**
   * Internal helper that runs `ssh-keyscan` against `pinnedIp` and validates against strict/existing pin.
   * @param {FleetServerRecord} server
   * @param {string} pinnedIp
   * @param {string | null} [explicitExpected]
   * @param {{ allowRepin?: boolean }} [opts]
   */
  async _pinHostKeyOnRecord(server, pinnedIp, explicitExpected = null, opts = {}) {
    const allowRepin = Boolean(opts.allowRepin);
    const scanArgs = ['-T', '5', '-p', String(server.port), '-t', 'ed25519,ecdsa,rsa', '--', pinnedIp];

    let stdout = '';
    try {
      const res = await this._execFile('ssh-keyscan', scanArgs, { timeout: 10000 });
      stdout = res.stdout;
    } catch (err) {
      /** @type {any} */
      const e = err;
      throw createFleetError(
        `No se pudo obtener la clave de host SSH con ssh-keyscan: ${e && e.message ? e.message : String(e)}`,
        'KEYSCAN_FAILED',
        502
      );
    }

    const scanned = parseBestKeyscanOutput(stdout);

    // Check explicit expectedFingerprint or strict policy expectation
    const requiredFp = explicitExpected
      ? normalizeFingerprint(explicitExpected)
      : (server.hostKeyPolicy === 'strict' && server.expectedFingerprint
        ? normalizeFingerprint(server.expectedFingerprint)
        : null);

    if (requiredFp && !fingerprintsEqual(scanned.fingerprint, requiredFp)) {
      throw createFleetError(
        `La huella SSH del servidor (${scanned.fingerprint}) no coincide con la esperada (${requiredFp})`,
        'HOST_KEY_MISMATCH',
        409,
        { expected: requiredFp, actual: scanned.fingerprint, serverId: server.id }
      );
    }

    // If already pinned and not explicitly repinning, verify equality!
    if (!allowRepin && server.hostKeyFingerprint && !fingerprintsEqual(scanned.fingerprint, server.hostKeyFingerprint)) {
      server.status = 'host_key_mismatch';
      server.statusReason = `Clave de host SSH cambiada inesperadamente (fijada: ${server.hostKeyFingerprint}, actual: ${scanned.fingerprint})`;
      server.statusFix = 'Verifica el cambio en el servidor y ejecuta repinHostKey() solo si es legítimo.';
      server.updatedAt = new Date().toISOString();
      if (this._servers.has(server.id)) {
        this._saveServers();
      }
      this._audit('fleet.host_key_mismatch', server.id, {
        expected: server.hostKeyFingerprint,
        actual: scanned.fingerprint
      });
      this.emit('server:host_key_mismatch', {
        serverId: server.id,
        expected: server.hostKeyFingerprint,
        actual: scanned.fingerprint
      });
      throw createFleetError(
        `Posible ataque MITM: la clave de host SSH de "${server.id}" cambió (${scanned.fingerprint} != ${server.hostKeyFingerprint})`,
        'HOST_KEY_MISMATCH',
        409,
        { expected: server.hostKeyFingerprint, actual: scanned.fingerprint, serverId: server.id }
      );
    }

    const now = new Date().toISOString();
    server.hostKeyFingerprint = scanned.fingerprint;
    server.hostKeyType = scanned.keyType;
    server.hostKeyLine = this._formatKnownHostsLines(server, scanned.keyType, scanned.keyBase64);
    server.hostKeyPinnedAt = now;
    server.updatedAt = now;
    return scanned;
  }

  /**
   * Performs TOFU or strict host-key pinning for a registered server.
   * Never saves a mismatched key or sends SSH credentials on mismatch.
   * @param {string} serverId
   * @param {{ expectedFingerprint?: string }} [opts]
   */
  async pinHostKey(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('El servidor local no usa clave de host SSH', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const { pinnedIp } = await assertSafeFleetHost(server.host, { resolveHost: this._resolveHost });
    const expected = opts && opts.expectedFingerprint ? normalizeFingerprint(opts.expectedFingerprint) : null;

    const scanned = await this._pinHostKeyOnRecord(server, pinnedIp, expected, { allowRepin: false });
    this._writeKnownHostsFile(server);
    this._saveServers();
    this._audit('fleet.host_key_pinned', id, {
      host: server.host,
      port: server.port,
      keyType: scanned.keyType,
      fingerprint: scanned.fingerprint,
      policy: server.hostKeyPolicy
    });
    return {
      serverId: id,
      fingerprint: scanned.fingerprint,
      keyType: scanned.keyType,
      pinnedAt: server.hostKeyPinnedAt
    };
  }

  /**
   * Explicitly re-pins a server's SSH host key (e.g., after legitimate VPS reinstall).
   * Clears `host_key_mismatch` lockdown and gracefully drains active tunnels.
   * @param {string} serverId
   * @param {{ expectedFingerprint?: string }} [opts]
   */
  async repinHostKey(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      throw createFleetError('El servidor local no usa clave de host SSH', 'LOCAL_SERVER_IMMUTABLE', 400);
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const expected = opts && opts.expectedFingerprint ? normalizeFingerprint(opts.expectedFingerprint) : null;
    if (server.hostKeyPolicy === 'strict' && !expected) {
      throw createFleetError(
        'En modo hostKeyPolicy="strict" debes proporcionar expectedFingerprint al re-fijar la clave',
        'EXPECTED_FINGERPRINT_REQUIRED',
        400
      );
    }

    const { pinnedIp } = await assertSafeFleetHost(server.host, { resolveHost: this._resolveHost });
    const previousFingerprint = server.hostKeyFingerprint;

    const scanned = await this._pinHostKeyOnRecord(server, pinnedIp, expected, { allowRepin: true });
    if (expected) {
      server.expectedFingerprint = expected;
    }
    server.status = 'pending';
    server.statusReason = null;
    server.statusFix = null;
    this._writeKnownHostsFile(server);
    this._saveServers();
    this.drainServerTunnels(id);

    this._audit('fleet.host_key_repinned', id, {
      previousFingerprint,
      fingerprint: scanned.fingerprint,
      keyType: scanned.keyType
    });
    const result = {
      serverId: id,
      previousFingerprint,
      fingerprint: scanned.fingerprint,
      keyType: scanned.keyType,
      pinnedAt: server.hostKeyPinnedAt
    };
    this.emit('server:host_key_repinned', result);
    return result;
  }

  /**
   * Ensures host key is pinned and `data/.fleet-known-hosts/<serverId>` exists before any SSH connection.
   * Rejects immediately if server is locked down in `host_key_mismatch`.
   * @param {FleetServerRecord} server
   * @param {string} pinnedIp
   * @returns {Promise<string>} Path to per-server known_hosts file
   */
  async _ensureHostKeyReady(server, pinnedIp) {
    if (server.status === 'host_key_mismatch') {
      throw createFleetError(
        `Servidor "${server.id}" bloqueado por cambio de clave de host SSH (HOST_KEY_MISMATCH). Verifica la huella y ejecuta repinHostKey().`,
        'HOST_KEY_MISMATCH',
        409,
        { serverId: server.id, expected: server.hostKeyFingerprint }
      );
    }

    if (!server.hostKeyLine || !server.hostKeyFingerprint) {
      await this._pinHostKeyOnRecord(server, pinnedIp, server.expectedFingerprint, { allowRepin: false });
      this._saveServers();
      this._audit('fleet.host_key_pinned', server.id, {
        host: server.host,
        port: server.port,
        keyType: server.hostKeyType,
        fingerprint: server.hostKeyFingerprint,
        policy: server.hostKeyPolicy
      });
    }

    const khPath = this._getKnownHostsPath(server.id);
    if (!fs.existsSync(khPath)) {
      this._writeKnownHostsFile(server);
    }
    return khPath;
  }

  /**
   * Marks server as locked down (`host_key_mismatch`) when OpenSSH rejects a changed host key.
   * @param {FleetServerRecord} server
   * @param {string} stderr
   */
  _triggerHostKeyMismatchLockdown(server, stderr) {
    server.status = 'host_key_mismatch';
    server.statusReason = 'OpenSSH rechazó la clave del servidor remoto (posible MITM o reinstalación del VPS)';
    server.statusFix = 'Verifica la huella SHA-256 en el VPS remoto y ejecuta repinHostKey() solo si el cambio es legítimo.';
    server.updatedAt = new Date().toISOString();
    this._saveServers();
    this.drainServerTunnels(server.id);
    this._audit('fleet.host_key_mismatch', server.id, {
      pinnedFingerprint: server.hostKeyFingerprint,
      detail: redactSensitiveOutput(stderr).slice(0, 240)
    });
    this.emit('server:host_key_mismatch', {
      serverId: server.id,
      expected: server.hostKeyFingerprint
    });
  }

  // -------------------------------------------------------------------------
  // Ref-Counted SSH Tunnel Manager (Docker + Caddy + App Health)
  // -------------------------------------------------------------------------

  /**
   * Computes a short POSIX Unix socket path (<90 bytes, well below 104/108B `sun_path` limit)
   * inside a `0o700` non-symlink directory.
   * @param {string} serverId
   * @param {string} tunnelId
   * @returns {string}
   */
  _allocatePosixSocketPath(serverId, tunnelId) {
    const uid = typeof process.getuid === 'function' ? String(process.getuid()) : 'user';
    const hash10 = crypto.createHash('sha256').update(`${serverId}:${tunnelId}`).digest('hex').slice(0, 10);
    const preferredBase = this._tmpSocketBaseDir || path.join(os.tmpdir(), `ck-fleet-${uid}`);
    let sockDir = preferredBase;
    let candidate = path.join(sockDir, `ck-${hash10}.sock`);

    if (Buffer.byteLength(candidate, 'utf8') >= 90 && !this._tmpSocketBaseDir) {
      sockDir = path.join('/tmp', `ck-fleet-${uid}`);
      candidate = path.join(sockDir, `ck-${hash10}.sock`);
    }

    ensureSecureDir(sockDir);
    secureUnlinkFile(candidate);
    return candidate;
  }

  /**
   * Terminates a tunnel child process and cleans up its socket/timers.
   * @param {ActiveDockerTunnel} tunnel
   */
  _closeTunnelImmediate(tunnel) {
    if (!tunnel) return;
    if (tunnel.idleTimer) {
      clearTimeout(tunnel.idleTimer);
      tunnel.idleTimer = null;
    }
    tunnel.alive = false;

    if (this._dockerTunnels.get(tunnel.serverId) === tunnel) {
      this._dockerTunnels.delete(tunnel.serverId);
    }
    this._drainingTunnels.delete(tunnel);

    if (tunnel.child && typeof tunnel.child.kill === 'function') {
      try { tunnel.child.kill('SIGTERM'); } catch (e) {}
    }
    if (tunnel.localSock) {
      secureUnlinkFile(tunnel.localSock);
    }
  }

  /**
   * Marks any active Docker tunnel for `serverId` as draining.
   * If `refCount === 0`, closes immediately; if `refCount > 0`, lets active builds finish safely.
   * Increments drain epoch so any in-flight connect opened with stale credentials drains upon completion.
   * @param {string} serverId
   */
  drainServerTunnels(serverId) {
    this._serverDrainEpoch.set(serverId, (this._serverDrainEpoch.get(serverId) || 0) + 1);
    const active = this._dockerTunnels.get(serverId);
    if (!active) return;
    active.draining = true;
    this._dockerTunnels.delete(serverId);
    if (active.refCount <= 0) {
      this._closeTunnelImmediate(active);
    } else {
      if (active.idleTimer) {
        clearTimeout(active.idleTimer);
        active.idleTimer = null;
      }
      this._drainingTunnels.add(active);
    }
  }

  /**
   * Inspects current Docker tunnel lease state for a server (diagnostics & tests).
   * @param {string} serverId
   */
  getTunnelState(serverId) {
    const active = this._dockerTunnels.get(serverId);
    const draining = Array.from(this._drainingTunnels).filter((t) => t.serverId === serverId);
    if (!active && draining.length === 0) return null;
    return {
      active: Boolean(active && active.alive),
      tunnelId: active ? active.id : null,
      dockerHost: active ? active.dockerHost : null,
      refCount: active ? active.refCount : 0,
      draining: active ? active.draining : true,
      idleTimerArmed: Boolean(active && active.idleTimer),
      drainingCount: draining.length,
      drainingRefCount: draining.reduce((acc, t) => acc + t.refCount, 0)
    };
  }

  /**
   * Opens a new Docker SSH tunnel for `server`.
   * Immediately wipes the ephemeral key file as soon as the tunnel connects (or fails).
   * @param {FleetServerRecord} server
   * @param {string} pinnedIp
   * @param {string} knownHostsFile
   * @param {{ connectTimeoutMs?: number, signal?: AbortSignal | null }} opts
   * @returns {Promise<ActiveDockerTunnel>}
   */
  async _openDockerTunnel(server, pinnedIp, knownHostsFile, opts = {}) {
    const startEpoch = this._serverDrainEpoch.get(server.id) || 0;
    const tunnelId = `tun_${crypto.randomBytes(6).toString('hex')}`;
    const isWin = this._platform === 'win32';
    /** @type {string | null} */
    let localSock = null;
    /** @type {number | null} */
    let localPort = null;
    let forwardSpec = '';
    let dockerHost = '';

    if (isWin) {
      localPort = await findFreeLoopbackPort();
      forwardSpec = `127.0.0.1:${localPort}:${server.dockerSocketPath}`;
      dockerHost = `tcp://127.0.0.1:${localPort}`;
    } else {
      localSock = this._allocatePosixSocketPath(server.id, tunnelId);
      forwardSpec = `${localSock}:${server.dockerSocketPath}`;
      dockerHost = `unix://${localSock}`;
    }

    const { keyFile, cleanup: cleanupKey } = this._materializeEphemeralKey(server.keyId);
    let stderrBuf = '';
    /** @type {any} */
    let child = null;

    try {
      const sshArgs = buildBaseSshArgs(server, {
        keyFile,
        knownHostsFile,
        pinnedIp,
        connectTimeoutSec: Math.max(1, Math.ceil((opts.connectTimeoutMs || DEFAULTS.tunnelConnectTimeoutMs) / 1000)),
        clearAllForwardings: false,
        platform: this._platform,
        extraArgs: ['-N', '-L', forwardSpec]
      });

      child = this._spawn('ssh', sshArgs, { stdio: ['ignore', 'ignore', 'pipe'] });
      if (child && child.stderr && typeof child.stderr.on === 'function') {
        child.stderr.on('data', (chunk) => {
          if (stderrBuf.length < 8192) {
            stderrBuf += String(chunk || '');
          }
        });
      }

      await this._waitForEndpoint(
        { localSock, localPort },
        child,
        {
          timeoutMs: opts.connectTimeoutMs ?? DEFAULTS.tunnelConnectTimeoutMs,
          signal: opts.signal || null,
          getStderr: () => stderrBuf
        }
      );

      // Handshake complete: wipe ephemeral private key file immediately!
      cleanupKey();

      /** @type {ActiveDockerTunnel} */
      const tunnel = {
        id: tunnelId,
        serverId: server.id,
        dockerHost,
        localSock,
        localPort,
        child,
        refCount: 0,
        draining: false,
        alive: true,
        idleTimer: null,
        createdAt: Date.now()
      };

      if (child && typeof child.once === 'function') {
        child.once('exit', () => {
          tunnel.alive = false;
          if (tunnel.idleTimer) {
            clearTimeout(tunnel.idleTimer);
            tunnel.idleTimer = null;
          }
          if (this._dockerTunnels.get(server.id) === tunnel) {
            this._dockerTunnels.delete(server.id);
          }
          this._drainingTunnels.delete(tunnel);
          if (tunnel.localSock) {
            secureUnlinkFile(tunnel.localSock);
          }
          this.emit('tunnel:closed', { serverId: server.id, tunnelId: tunnel.id });
        });
      }

      if ((this._serverDrainEpoch.get(server.id) || 0) !== startEpoch) {
        tunnel.draining = true;
        this._drainingTunnels.add(tunnel);
      } else {
        this._dockerTunnels.set(server.id, tunnel);
      }
      return tunnel;
    } catch (err) {
      cleanupKey();
      if (child && typeof child.kill === 'function') {
        try { child.kill('SIGTERM'); } catch (e) {}
      }
      if (localSock) {
        secureUnlinkFile(localSock);
      }
      /** @type {any} */
      const e = err;
      if ((e && e.code === 'HOST_KEY_MISMATCH') || isHostKeyErrorText(stderrBuf)) {
        this._triggerHostKeyMismatchLockdown(server, stderrBuf);
        throw createFleetError(
          `Verificación de clave de host SSH fallida para "${server.id}"`,
          'HOST_KEY_MISMATCH',
          409,
          { serverId: server.id }
        );
      }
      throw err;
    }
  }

  /**
   * Arms the idle teardown timer on an active tunnel when `refCount === 0`.
   * @param {ActiveDockerTunnel} tunnel
   */
  _armIdleTimer(tunnel) {
    if (!tunnel || tunnel.refCount > 0 || !tunnel.alive) return;
    if (tunnel.draining) {
      this._closeTunnelImmediate(tunnel);
      return;
    }
    if (tunnel.idleTimer) {
      clearTimeout(tunnel.idleTimer);
    }
    tunnel.idleTimer = setTimeout(() => {
      tunnel.idleTimer = null;
      if (tunnel.refCount === 0) {
        this._closeTunnelImmediate(tunnel);
      }
    }, this._tunnelIdleMs);
    if (tunnel.idleTimer.unref) tunnel.idleTimer.unref();
  }

  /**
   * Awaits a coalesced tunnel connect while isolating each caller's `AbortSignal`.
   * Aborting one caller NEVER cancels sibling waiters on the same connect; the underlying
   * SSH handshake is aborted ONLY when zero waiters remain.
   * @param {InFlightTunnelConnect} entry
   * @param {symbol} waiterToken
   * @param {AbortSignal | null} callerSignal
   * @returns {Promise<ActiveDockerTunnel>}
   */
  _awaitWithCallerAbort(entry, waiterToken, callerSignal) {
    if (!callerSignal) return entry.promise;
    if (callerSignal.aborted) {
      entry.waiters.delete(waiterToken);
      if (entry.waiters.size === 0) {
        entry.promise.catch(() => {});
        try { entry.internalController.abort(); } catch (e) {}
      }
      return Promise.reject(createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499));
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const onAbort = () => {
        if (settled) return;
        settled = true;
        entry.waiters.delete(waiterToken);
        if (entry.waiters.size === 0) {
          try { entry.internalController.abort(); } catch (e) {}
        }
        reject(createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499));
      };
      callerSignal.addEventListener('abort', onAbort, { once: true });
      entry.promise.then(
        (t) => {
          if (settled) {
            if (t && t.refCount === 0 && entry.waiters.size === 0) {
              if (t.draining || !t.alive) this._closeTunnelImmediate(t);
              else this._armIdleTimer(t);
            }
            return;
          }
          settled = true;
          callerSignal.removeEventListener('abort', onAbort);
          resolve(t);
        },
        (err) => {
          if (settled) return;
          settled = true;
          callerSignal.removeEventListener('abort', onAbort);
          reject(err);
        }
      );
    });
  }

  /**
   * Acquires a ref-counted Docker SSH tunnel lease.
   * - Never closes the tunnel while `refCount > 0`.
   * - Active liveness-checks cached tunnels and transparently reaps stale/zombie sockets.
   * - Coalesces concurrent connects with per-caller `AbortSignal` isolation.
   * - Never mutates `process.env.DOCKER_HOST`.
   * - Arms idle teardown timer ONLY when `refCount` drops to `0`.
   *
   * @param {string} serverId
   * @param {{ signal?: AbortSignal | null, connectTimeoutMs?: number, skipLivenessCheck?: boolean }} [opts]
   * @returns {Promise<{ serverId: string, dockerHost: string | null, tunnelId: string | null, isLocal: boolean, isAlive: () => boolean, release: () => Promise<void> }>}
   */
  async acquireDockerTunnel(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      return {
        serverId: LOCAL_SERVER_ID,
        dockerHost: null,
        tunnelId: null,
        isLocal: true,
        isAlive: () => true,
        release: async () => {}
      };
    }

    if (opts.signal && opts.signal.aborted) {
      throw createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499);
    }

    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    // Re-resolve & verify SSRF on every acquire (closes DNS-rebinding TOCTOU)
    const { pinnedIp } = await assertSafeFleetHost(server.host, { resolveHost: this._resolveHost });
    const knownHostsFile = await this._ensureHostKeyReady(server, pinnedIp);

    if (opts.signal && opts.signal.aborted) {
      throw createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499);
    }

    /** @type {ActiveDockerTunnel | null} */
    let tunnel = this._dockerTunnels.get(id) || null;
    if (tunnel) {
      const childDead = Boolean(tunnel.child && (tunnel.child.killed || tunnel.child.exitCode !== null));
      if (!tunnel.alive || tunnel.draining || childDead) {
        if (childDead || !tunnel.alive) {
          this._closeTunnelImmediate(tunnel);
        }
        tunnel = null;
      } else if (!opts.skipLivenessCheck) {
        const canProbe = this._customProbeEndpoint || !(tunnel.localSock && process.platform === 'win32');
        if (canProbe) {
          const healthy = await this._probeEndpoint({ localSock: tunnel.localSock, localPort: tunnel.localPort }, 400);
          if (!healthy) {
            this.emit('tunnel:stale_reaped', { serverId: id, tunnelId: tunnel.id });
            this._closeTunnelImmediate(tunnel);
            tunnel = null;
          } else if (!tunnel.alive || tunnel.draining) {
            tunnel = null;
          }
        }
      }
    }

    if (opts.signal && opts.signal.aborted) {
      throw createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499);
    }

    if (!tunnel) {
      const waiterToken = Symbol('tunnel_waiter');
      let entry = this._dockerTunnelConnects.get(id);
      if (!entry) {
        const internalController = new AbortController();
        /** @type {Set<symbol>} */
        const waiters = new Set();
        const promise = this._openDockerTunnel(server, pinnedIp, knownHostsFile, {
          connectTimeoutMs: opts.connectTimeoutMs,
          signal: internalController.signal
        }).finally(() => {
          if (this._dockerTunnelConnects.get(id) === entry) {
            this._dockerTunnelConnects.delete(id);
          }
        });
        entry = { promise, waiters, internalController };
        this._dockerTunnelConnects.set(id, entry);
      }
      entry.waiters.add(waiterToken);
      try {
        tunnel = await this._awaitWithCallerAbort(entry, waiterToken, opts.signal || null);
      } finally {
        entry.waiters.delete(waiterToken);
      }

      // If the coalesced tunnel became draining/dead while awaiting, close if unreferenced
      // and re-fetch the latest server record so rotated credentials/user/endpoint are used!
      if (!tunnel.alive || tunnel.draining) {
        if (tunnel.refCount === 0) {
          this._closeTunnelImmediate(tunnel);
        }
        if (opts.signal && opts.signal.aborted) {
          throw createFleetError('Solicitud de túnel cancelada', 'ABORTED', 499);
        }
        const freshServer = this._servers.get(id);
        if (!freshServer) {
          throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
        }
        const { pinnedIp: freshPinnedIp } = await assertSafeFleetHost(freshServer.host, { resolveHost: this._resolveHost });
        const freshKnownHosts = await this._ensureHostKeyReady(freshServer, freshPinnedIp);
        tunnel = await this._openDockerTunnel(freshServer, freshPinnedIp, freshKnownHosts, {
          connectTimeoutMs: opts.connectTimeoutMs,
          signal: opts.signal || null
        });
      }
    }

    if (tunnel.idleTimer) {
      clearTimeout(tunnel.idleTimer);
      tunnel.idleTimer = null;
    }
    tunnel.refCount++;

    const boundTunnel = tunnel;
    let released = false;
    const release = async () => {
      if (released) return;
      released = true;
      boundTunnel.refCount = Math.max(0, boundTunnel.refCount - 1);

      // NEVER close while refCount > 0!
      if (boundTunnel.refCount > 0) return;

      if (boundTunnel.draining || !boundTunnel.alive) {
        this._closeTunnelImmediate(boundTunnel);
        return;
      }

      this._armIdleTimer(boundTunnel);
    };

    return {
      serverId: id,
      dockerHost: boundTunnel.dockerHost,
      tunnelId: boundTunnel.id,
      isLocal: false,
      isAlive: () => Boolean(boundTunnel.alive && (!boundTunnel.child || (!boundTunnel.child.killed && boundTunnel.child.exitCode === null))),
      release
    };
  }

  /**
   * Runs `fn(lease)` inside a ref-counted Docker tunnel lease, guaranteeing `lease.release()`.
   * @template T
   * @param {string} serverId
   * @param {(lease: { serverId: string, dockerHost: string | null, tunnelId: string | null, isLocal: boolean, isAlive: () => boolean, release: () => Promise<void> }) => Promise<T>} fn
   * @param {{ signal?: AbortSignal | null, connectTimeoutMs?: number, skipLivenessCheck?: boolean }} [opts]
   * @returns {Promise<T>}
   */
  async withDockerTunnel(serverId, fn, opts = {}) {
    const lease = await this.acquireDockerTunnel(serverId, opts);
    try {
      return await fn(lease);
    } finally {
      await lease.release();
    }
  }

  /**
   * Force-invalidates a specific broken Docker tunnel so the next acquire opens a clean connection.
   * @param {string} serverId
   * @param {string | null} [tunnelId]
   */
  _invalidateBrokenTunnel(serverId, tunnelId = null) {
    const active = this._dockerTunnels.get(serverId);
    if (active && (!tunnelId || active.id === tunnelId)) {
      this._closeTunnelImmediate(active);
    }
    for (const dt of Array.from(this._drainingTunnels)) {
      if (dt.serverId === serverId && (!tunnelId || dt.id === tunnelId)) {
        this._closeTunnelImmediate(dt);
      }
    }
  }

  /**
   * Executes `fn(lease, meta)` over a liveness-verified Docker SSH tunnel with automatic
   * reconnect and bounded exponential backoff if the SSH tunnel drops transiently mid-flight.
   * NEVER retries security errors (`HOST_KEY_MISMATCH`, `SSRF_BLOCKED`, `ABORTED`, vault errors).
   *
   * @template T
   * @param {string} serverId
   * @param {(lease: { serverId: string, dockerHost: string | null, tunnelId: string | null, isLocal: boolean, isAlive: () => boolean, release: () => Promise<void> }, meta: { attempt: number, reconnected: boolean }) => Promise<T>} fn
   * @param {{
   *   maxRetries?: number,
   *   baseDelayMs?: number,
   *   maxDelayMs?: number,
   *   connectTimeoutMs?: number,
   *   signal?: AbortSignal | null,
   *   isRetryable?: (err: any, attempt: number) => boolean
   * }} [opts]
   * @returns {Promise<T>}
   */
  async withResilientDockerTunnel(serverId, fn, opts = {}) {
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      return this.withDockerTunnel(LOCAL_SERVER_ID, (lease) => fn(lease, { attempt: 0, reconnected: false }), opts);
    }

    const maxRetries = Math.max(0, Math.min(5, typeof opts.maxRetries === 'number' && Number.isInteger(opts.maxRetries) ? opts.maxRetries : 2));
    const baseDelayMs = Math.max(10, Math.min(10000, Number(opts.baseDelayMs) || 250));
    const maxDelayMs = Math.max(baseDelayMs, Math.min(30000, Number(opts.maxDelayMs) || 3000));
    const signal = opts.signal || null;

    /** @type {any} */
    let lastErr = null;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (signal && signal.aborted) {
        throw createFleetError('Operación cancelada', 'ABORTED', 499);
      }
      /** @type {any} */
      let lease = null;
      try {
        lease = await this.acquireDockerTunnel(id, {
          signal,
          connectTimeoutMs: opts.connectTimeoutMs
        });
        return await fn(lease, { attempt, reconnected: attempt > 0 });
      } catch (err) {
        lastErr = err;
        const tunnelDiedDuringOp = Boolean(lease && typeof lease.isAlive === 'function' && !lease.isAlive());
        const customRetry = typeof opts.isRetryable === 'function' ? Boolean(opts.isRetryable(err, attempt)) : false;
        const code = String(err && err.code ? err.code : '').toUpperCase();
        const isFatal = NON_RETRYABLE_TUNNEL_CODES.has(code);
        const canRetry = !isFatal && attempt < maxRetries && (tunnelDiedDuringOp || isRetryableTunnelError(err) || customRetry);

        if (lease) {
          const brokenId = lease.tunnelId;
          await lease.release().catch(() => {});
          lease = null;
          if (canRetry) {
            this._invalidateBrokenTunnel(id, brokenId);
          }
        } else if (canRetry) {
          this._invalidateBrokenTunnel(id, null);
        }

        if (!canRetry) {
          throw err;
        }

        const delayMs = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, attempt));
        this.emit('tunnel:reconnecting', {
          serverId: id,
          attempt: attempt + 1,
          maxRetries,
          delayMs,
          reason: redactSensitiveOutput(err && err.message ? err.message : String(err)).slice(0, 180)
        });
        await sleepWithAbort(delayMs, signal);
      } finally {
        if (lease) {
          await lease.release().catch(() => {});
        }
      }
    }
    throw lastErr;
  }

  /**
   * Opens a short-lived SSH port forward (`127.0.0.1:<localFreePort> -> 127.0.0.1:<remotePort>`),
   * wipes ephemeral key immediately after handshake, invokes `fn`, and tears down in `finally`.
   * Remote ports are NEVER exposed on public interfaces.
   *
   * @template T
   * @param {string} serverId
   * @param {number} remotePort
   * @param {(ctx: { localHost: string, localPort: number, url: string, isLocal: boolean }) => Promise<T>} fn
   * @param {{ connectTimeoutMs?: number, signal?: AbortSignal | null }} [opts]
   * @returns {Promise<T>}
   */
  async withPortTunnel(serverId, remotePort, fn, opts = {}) {
    this._ensureLoaded();
    const safeRemotePort = validatePort(remotePort, 'remotePort');
    const id = String(serverId || '').trim();

    if (id === LOCAL_SERVER_ID) {
      return fn({
        localHost: '127.0.0.1',
        localPort: safeRemotePort,
        url: `http://127.0.0.1:${safeRemotePort}`,
        isLocal: true
      });
    }

    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const { pinnedIp } = await assertSafeFleetHost(server.host, { resolveHost: this._resolveHost });
    const knownHostsFile = await this._ensureHostKeyReady(server, pinnedIp);
    const localPort = await findFreeLoopbackPort();
    const forwardSpec = `127.0.0.1:${localPort}:127.0.0.1:${safeRemotePort}`;

    const { keyFile, cleanup: cleanupKey } = this._materializeEphemeralKey(server.keyId);
    let stderrBuf = '';
    /** @type {any} */
    let child = null;

    try {
      const sshArgs = buildBaseSshArgs(server, {
        keyFile,
        knownHostsFile,
        pinnedIp,
        connectTimeoutSec: Math.max(1, Math.ceil((opts.connectTimeoutMs || DEFAULTS.tunnelConnectTimeoutMs) / 1000)),
        clearAllForwardings: false,
        platform: this._platform,
        extraArgs: ['-N', '-L', forwardSpec]
      });

      child = this._spawn('ssh', sshArgs, { stdio: ['ignore', 'ignore', 'pipe'] });
      this._ephemeralTunnelChildren.add(child);
      if (child && child.stderr && typeof child.stderr.on === 'function') {
        child.stderr.on('data', (chunk) => {
          if (stderrBuf.length < 8192) stderrBuf += String(chunk || '');
        });
      }

      await this._waitForEndpoint(
        { localPort },
        child,
        {
          timeoutMs: opts.connectTimeoutMs ?? DEFAULTS.tunnelConnectTimeoutMs,
          signal: opts.signal || null,
          getStderr: () => stderrBuf
        }
      );

      // Wipe ephemeral key immediately once handshake succeeds
      cleanupKey();

      return await fn({
        localHost: '127.0.0.1',
        localPort,
        url: `http://127.0.0.1:${localPort}`,
        isLocal: false
      });
    } catch (err) {
      /** @type {any} */
      const e = err;
      if ((e && e.code === 'HOST_KEY_MISMATCH') || isHostKeyErrorText(stderrBuf)) {
        this._triggerHostKeyMismatchLockdown(server, stderrBuf);
        throw createFleetError(
          `Verificación de clave de host SSH fallida para "${server.id}"`,
          'HOST_KEY_MISMATCH',
          409,
          { serverId: server.id }
        );
      }
      throw err;
    } finally {
      cleanupKey();
      if (child) {
        this._ephemeralTunnelChildren.delete(child);
        if (typeof child.kill === 'function') {
          try { child.kill('SIGTERM'); } catch (e) {}
        }
      }
    }
  }

  /**
   * Tunnels the remote Caddy Admin API (`127.0.0.1:<caddyAdminPort>`, default 2019)
   * and passes the tunneled `adminUrl` plus canonical `hostHeader`/`originHeader`
   * (`127.0.0.1:<caddyAdminPort>`) so Caddy's Host-enforcement never rejects ephemeral tunnel ports with 403.
   *
   * @template T
   * @param {string} serverId
   * @param {(adminUrl: string, meta: { localPort: number, adminUrl: string, remoteAdminPort: number, hostHeader: string, originHeader: string, isLocal: boolean }) => Promise<T>} fn
   * @param {{ connectTimeoutMs?: number, signal?: AbortSignal | null }} [opts]
   * @returns {Promise<T>}
   */
  async withCaddyTunnel(serverId, fn, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      const localAdmin = `http://127.0.0.1:${DEFAULTS.caddyAdminPort}`;
      return fn(localAdmin, {
        localPort: DEFAULTS.caddyAdminPort,
        adminUrl: localAdmin,
        remoteAdminPort: DEFAULTS.caddyAdminPort,
        hostHeader: `127.0.0.1:${DEFAULTS.caddyAdminPort}`,
        originHeader: localAdmin,
        isLocal: true
      });
    }
    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }
    const caddyPort = server.caddyAdminPort || DEFAULTS.caddyAdminPort;
    const hostHeader = `127.0.0.1:${caddyPort}`;
    const originHeader = `http://${hostHeader}`;
    return this.withPortTunnel(
      id,
      caddyPort,
      ({ url, localPort }) => fn(url, {
        localPort,
        adminUrl: url,
        remoteAdminPort: caddyPort,
        hostHeader,
        originHeader,
        isLocal: false
      }),
      opts
    );
  }

  /**
   * Lazily resolves `caddyManager` for remote worker Caddy sync without eager boot coupling.
   * @param {any} [override]
   */
  _getCaddyManager(override = null) {
    if (override) return override;
    if (!this._caddyManager) {
      this._caddyManager = require('./caddyManager');
    }
    return this._caddyManager;
  }

  /**
   * Synchronizes Caddy base config, TLS policy, and HTTP routes onto a remote fleet node
   * (or `'local'`) inside a single SSH Caddy tunnel, forwarding the canonical remote
   * `Host`/`Origin` (`127.0.0.1:<caddyAdminPort>`) to avoid HTTP 403 rejections.
   *
   * @param {string} serverId
   * @param {Array<Record<string, any>> | {
   *   routes?: Array<Record<string, any>>,
   *   removeProjectIds?: string[],
   *   bootstrapBaseConfig?: boolean,
   *   pruneStale?: boolean,
   *   tls?: Record<string, any> | null,
   *   continueOnError?: boolean
   * }} routesSpec
   * @param {{ connectTimeoutMs?: number, signal?: AbortSignal | null, _caddyManager?: any }} [opts]
   */
  async syncRemoteCaddy(serverId, routesSpec, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    const specObj = Array.isArray(routesSpec)
      ? { routes: routesSpec }
      : (routesSpec && typeof routesSpec === 'object' ? routesSpec : {});
    const routes = Array.isArray(specObj.routes) ? specObj.routes : [];
    const removeProjectIds = Array.isArray(specObj.removeProjectIds) ? specObj.removeProjectIds : [];
    const bootstrapBaseConfig = specObj.bootstrapBaseConfig !== false;
    const pruneStale = Boolean(specObj.pruneStale);
    const continueOnError = Boolean(specObj.continueOnError);
    const tlsOpts = specObj.tls && typeof specObj.tls === 'object' ? specObj.tls : null;

    const cm = this._getCaddyManager(opts._caddyManager);
    if (!cm || typeof cm.upsertRoute !== 'function') {
      throw createFleetError('caddyManager no disponible para sincronización remota', 'CADDY_MANAGER_UNAVAILABLE', 500);
    }

    return this.withCaddyTunnel(id, async (adminUrl, meta) => {
      const caddyReqOpts = meta.isLocal
        ? {}
        : {
            adminUrl,
            caddyAdminPort: meta.remoteAdminPort,
            remoteAdminPort: meta.remoteAdminPort,
            hostHeader: meta.hostHeader,
            originHeader: meta.originHeader
          };

      if (typeof cm.detect === 'function') {
        const detection = await cm.detect({ force: true, ...caddyReqOpts });
        if (!detection || !detection.available) {
          throw createFleetError(
            `Caddy Admin API no responde en nodo "${id}" (${detection && detection.reason ? detection.reason : adminUrl})`,
            'REMOTE_CADDY_UNAVAILABLE',
            503
          );
        }
      }

      let bootstrapped = false;
      if (bootstrapBaseConfig && typeof cm.getWithEtag === 'function' && typeof cm.write === 'function') {
        const existingSrv = await cm.getWithEtag('/config/apps/http/servers/culkibo', caddyReqOpts);
        if (!existingSrv || !existingSrv.found) {
          const base = typeof cm.buildBaseConfig === 'function'
            ? cm.buildBaseConfig(tlsOpts || {})
            : {
                admin: { listen: meta.hostHeader },
                apps: {
                  http: {
                    servers: {
                      culkibo: { listen: [':80', ':443'], routes: [] }
                    }
                  }
                }
              };
          const fullCfg = await cm.getWithEtag('/config/apps/http/servers', caddyReqOpts);
          if (fullCfg && fullCfg.found) {
            await cm.write('PUT', '/config/apps/http/servers/culkibo', base.apps.http.servers.culkibo, caddyReqOpts);
          } else {
            const httpCfg = await cm.getWithEtag('/config/apps/http', caddyReqOpts);
            if (httpCfg && httpCfg.found) {
              await cm.write('PUT', '/config/apps/http/servers', base.apps.http.servers, caddyReqOpts);
            } else if (typeof cm.adminRequest === 'function') {
              const loadRes = await cm.adminRequest('POST', '/load', {
                headers: {
                  'Content-Type': 'application/json',
                  ...(meta.isLocal ? {} : { Host: meta.hostHeader, Origin: meta.originHeader })
                },
                body: JSON.stringify(base),
                ...caddyReqOpts
              });
              if (!loadRes || !loadRes.ok) {
                throw createFleetError(
                  `No se pudo inicializar configuración base de Caddy en "${id}" (HTTP ${loadRes ? loadRes.status : 'unknown'})`,
                  'REMOTE_CADDY_BOOTSTRAP_FAILED',
                  502
                );
              }
            } else {
              await cm.write('PUT', '/config/apps/http', base.apps.http, caddyReqOpts);
            }
          }
          bootstrapped = true;
        }
      }

      let tlsSynced = false;
      if (tlsOpts && typeof cm.reconcileTls === 'function') {
        await cm.reconcileTls({ ...tlsOpts, ...caddyReqOpts });
        tlsSynced = true;
      }

      /** @type {Array<{ projectId: string, created: boolean, unchanged: boolean, id: string | null }>} */
      const synced = [];
      /** @type {Array<{ projectId: string, error: string }>} */
      const failed = [];
      /** @type {Set<string>} */
      const desiredRouteIds = new Set();

      for (const routeSpec of routes) {
        const pid = String((routeSpec && routeSpec.projectId) || '');
        if (!pid) {
          const msg = 'Ruta sin projectId válido';
          if (!continueOnError) throw createFleetError(msg, 'INVALID_ROUTE_SPEC', 400);
          failed.push({ projectId: '', error: msg });
          continue;
        }
        try {
          const res = await cm.upsertRoute(routeSpec, caddyReqOpts);
          const routeId = (res && res.id) || (typeof cm.routeId === 'function' ? cm.routeId(pid) : `culkibo_${pid}`);
          desiredRouteIds.add(routeId);
          synced.push({
            projectId: pid,
            created: Boolean(res && res.created),
            unchanged: Boolean(res && res.unchanged),
            id: routeId
          });
        } catch (err) {
          /** @type {any} */
          const e = err;
          if (!continueOnError) throw err;
          failed.push({ projectId: pid, error: redactSensitiveOutput(e && e.message ? e.message : String(e)) });
        }
      }

      /** @type {string[]} */
      const removed = [];
      if (typeof cm.removeRoute === 'function') {
        for (const pid of removeProjectIds) {
          const cleanPid = String(pid || '').trim();
          if (!cleanPid) continue;
          try {
            await cm.removeRoute(cleanPid, caddyReqOpts);
            removed.push(cleanPid);
          } catch (err) {
            if (!continueOnError) throw err;
            /** @type {any} */
            const e = err;
            failed.push({ projectId: cleanPid, error: redactSensitiveOutput(e && e.message ? e.message : String(e)) });
          }
        }

        if (pruneStale && typeof cm.listRoutes === 'function') {
          const existingRoutes = await cm.listRoutes(caddyReqOpts);
          const list = Array.isArray(existingRoutes) ? existingRoutes : [];
          for (const r of list) {
            const rid = r && typeof r['@id'] === 'string' ? r['@id'] : '';
            if (!rid.startsWith('culkibo_') || desiredRouteIds.has(rid)) continue;
            const staleProjectId = rid.slice('culkibo_'.length);
            if (!staleProjectId || removed.includes(staleProjectId)) continue;
            try {
              await cm.removeRoute(staleProjectId, caddyReqOpts);
              removed.push(staleProjectId);
            } catch (err) {
              if (!continueOnError) throw err;
              /** @type {any} */
              const e = err;
              failed.push({ projectId: staleProjectId, error: redactSensitiveOutput(e && e.message ? e.message : String(e)) });
            }
          }
        }
      }

      const result = {
        ok: failed.length === 0,
        serverId: id,
        isLocal: meta.isLocal,
        hostHeader: meta.hostHeader,
        bootstrapped,
        tlsSynced,
        syncedCount: synced.length,
        removedCount: removed.length,
        synced,
        removed,
        failed
      };
      this._audit('fleet.remote_caddy_synced', id, {
        bootstrapped,
        tlsSynced,
        syncedCount: synced.length,
        removedCount: removed.length,
        failedCount: failed.length
      });
      this.emit('server:caddy_synced', result);
      return result;
    }, { connectTimeoutMs: opts.connectTimeoutMs, signal: opts.signal });
  }

  // -------------------------------------------------------------------------
  // Tunneled Remote Container Operations (Logs, Stats, Exec — 0 Shell)
  // -------------------------------------------------------------------------

  /**
   * Reads or streams container logs from a remote fleet node (or `'local'`) over the
   * ref-counted SSH Docker tunnel (`shell: false`, strict container ref validation,
   * zero mutation of `process.env.DOCKER_HOST`).
   *
   * - Snapshot mode (`follow: false`, default): uses `withResilientDockerTunnel` auto-reconnect.
   * - Streaming mode (`follow: true`): holds a tunnel lease until `stop()` / `signal` / exit.
   *
   * @param {string} serverId
   * @param {string} containerId
   * @param {{
   *   tail?: number,
   *   since?: string | null,
   *   timestamps?: boolean,
   *   follow?: boolean,
   *   timeoutMs?: number,
   *   maxBytes?: number,
   *   signal?: AbortSignal | null,
   *   onChunk?: (ev: { stream: 'stdout' | 'stderr', chunk: string }) => void
   * }} [opts]
   */
  async remoteContainerLogs(serverId, containerId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim() || LOCAL_SERVER_ID;
    const ref = validateDockerRef(containerId, 'containerId');
    const tailNum = Number.isFinite(Number(opts.tail))
      ? Math.min(Math.max(parseInt(String(opts.tail), 10) || 100, 1), 10000)
      : 100;

    /** @type {string[]} */
    const args = ['logs', '--tail', String(tailNum)];
    if (opts.timestamps) args.push('--timestamps');
    if (opts.since != null && String(opts.since).trim() !== '') {
      const sinceVal = String(opts.since).trim();
      if (!DOCKER_SINCE_RE.test(sinceVal)) {
        throw createFleetError('Parámetro since inválido (usa ej. "10m", "2h" o RFC3339)', 'INVALID_INPUT', 400);
      }
      args.push('--since', sinceVal);
    }

    if (opts.follow) {
      args.push('--follow', ref);
      const lease = await this.acquireDockerTunnel(id, { signal: opts.signal || null });
      const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
      const maxBytes = Math.max(4096, Math.min(16 * 1024 * 1024, Number(opts.maxBytes) || 2 * 1024 * 1024));
      let child;
      try {
        child = this._spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], env });
      } catch (err) {
        await lease.release().catch(() => {});
        throw err;
      }

      let totalBytes = 0;
      let truncated = false;
      let stopped = false;

      const stop = async () => {
        if (stopped) return;
        stopped = true;
        if (child && typeof child.kill === 'function') {
          try { child.kill('SIGTERM'); } catch (e) {}
        }
        await lease.release().catch(() => {});
      };

      const onAbort = () => { stop().catch(() => {}); };
      if (opts.signal) {
        if (opts.signal.aborted) {
          await stop();
          throw createFleetError('Stream de logs cancelado', 'ABORTED', 499);
        }
        opts.signal.addEventListener('abort', onAbort, { once: true });
      }

      const emitChunk = (streamName, raw) => {
        if (stopped || truncated) return;
        const text = redactSensitiveOutput(Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw || ''));
        if (!text) return;
        totalBytes += Buffer.byteLength(text, 'utf8');
        if (totalBytes > maxBytes) {
          truncated = true;
          stop().catch(() => {});
          return;
        }
        if (typeof opts.onChunk === 'function') {
          try { opts.onChunk({ stream: streamName, chunk: text }); } catch (e) {}
        }
      };

      if (child && child.stdout && typeof child.stdout.on === 'function') {
        child.stdout.on('data', (chunk) => emitChunk('stdout', chunk));
      }
      if (child && child.stderr && typeof child.stderr.on === 'function') {
        child.stderr.on('data', (chunk) => emitChunk('stderr', chunk));
      }

      const done = new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = async () => {
          if (opts.signal && typeof opts.signal.removeEventListener === 'function') {
            opts.signal.removeEventListener('abort', onAbort);
          }
          await lease.release().catch(() => {});
        };
        if (child && typeof child.once === 'function') {
          child.once('error', (err) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => reject(err));
          });
          child.once('close', (code) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: code, truncated, isLocal: lease.isLocal }));
          });
          child.once('exit', (code) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: code, truncated, isLocal: lease.isLocal }));
          });
        } else {
          cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: 0, truncated, isLocal: lease.isLocal }));
        }
      });

      return { serverId: id, containerId: ref, isLocal: lease.isLocal, tail: tailNum, child, stop, done };
    }

    args.push(ref);
    const timeout = Math.max(1000, Math.min(60000, Number(opts.timeoutMs) || 10000));
    return this.withResilientDockerTunnel(id, async (lease, meta) => {
      const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
      const res = await this._execFile('docker', args, { timeout, env, maxBuffer: 4 * 1024 * 1024 });
      const combined = redactSensitiveOutput([res.stdout, res.stderr].filter(Boolean).join('\n'));
      const lines = combined ? combined.split(/\r?\n/) : [];
      return {
        serverId: id,
        containerId: ref,
        isLocal: lease.isLocal,
        reconnected: meta.reconnected,
        tail: tailNum,
        output: combined,
        lines
      };
    }, { signal: opts.signal || null });
  }

  /**
   * Collects or streams live container resource stats (`docker stats`) from a remote
   * fleet node (or `'local'`) over the ref-counted SSH Docker tunnel (`shell: false`).
   *
   * @param {string} serverId
   * @param {string | null} [containerId]
   * @param {{
   *   follow?: boolean,
   *   timeoutMs?: number,
   *   signal?: AbortSignal | null,
   *   onStats?: (sample: { serverId: string, containers: any[], collectedAt: string }) => void
   * }} [opts]
   */
  async remoteContainerStats(serverId, containerId = null, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim() || LOCAL_SERVER_ID;
    const ref = containerId ? validateDockerRef(containerId, 'containerId') : null;

    if (opts.follow) {
      const args = ['stats', '--format', '{{json .}}'];
      if (ref) args.push(ref);
      const lease = await this.acquireDockerTunnel(id, { signal: opts.signal || null });
      const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
      let child;
      try {
        child = this._spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], env });
      } catch (err) {
        await lease.release().catch(() => {});
        throw err;
      }

      let stopped = false;
      let lineBuf = '';
      const stop = async () => {
        if (stopped) return;
        stopped = true;
        if (child && typeof child.kill === 'function') {
          try { child.kill('SIGTERM'); } catch (e) {}
        }
        await lease.release().catch(() => {});
      };

      const onAbort = () => { stop().catch(() => {}); };
      if (opts.signal) {
        if (opts.signal.aborted) {
          await stop();
          throw createFleetError('Stream de estadísticas cancelado', 'ABORTED', 499);
        }
        opts.signal.addEventListener('abort', onAbort, { once: true });
      }

      if (child && child.stdout && typeof child.stdout.on === 'function') {
        child.stdout.on('data', (chunk) => {
          if (stopped) return;
          lineBuf += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk || '');
          const nlIdx = lineBuf.lastIndexOf('\n');
          if (nlIdx === -1) return;
          const complete = lineBuf.slice(0, nlIdx);
          lineBuf = lineBuf.slice(nlIdx + 1);
          const containers = parseDockerStatsLines(complete);
          if (containers.length > 0 && typeof opts.onStats === 'function') {
            try {
              opts.onStats({ serverId: id, containers, collectedAt: new Date().toISOString() });
            } catch (e) {}
          }
        });
      }

      const done = new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = async () => {
          if (opts.signal && typeof opts.signal.removeEventListener === 'function') {
            opts.signal.removeEventListener('abort', onAbort);
          }
          await lease.release().catch(() => {});
        };
        if (child && typeof child.once === 'function') {
          child.once('error', (err) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => reject(err));
          });
          child.once('close', (code) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: code, isLocal: lease.isLocal }));
          });
          child.once('exit', (code) => {
            if (settled) return;
            settled = true;
            cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: code, isLocal: lease.isLocal }));
          });
        } else {
          cleanup().finally(() => resolve({ serverId: id, containerId: ref, exitCode: 0, isLocal: lease.isLocal }));
        }
      });

      return { serverId: id, containerId: ref, isLocal: lease.isLocal, child, stop, done };
    }

    const args = ['stats', '--no-stream', '--format', '{{json .}}'];
    if (ref) args.push(ref);
    const timeout = Math.max(1000, Math.min(30000, Number(opts.timeoutMs) || 8000));

    return this.withResilientDockerTunnel(id, async (lease, meta) => {
      const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
      const res = await this._execFile('docker', args, { timeout, env, maxBuffer: 2 * 1024 * 1024 });
      const containers = parseDockerStatsLines(res.stdout);
      return {
        serverId: id,
        containerId: ref,
        isLocal: lease.isLocal,
        reconnected: meta.reconnected,
        stats: ref ? (containers[0] || null) : containers,
        containers,
        collectedAt: new Date().toISOString()
      };
    }, { signal: opts.signal || null });
  }

  /**
   * Executes a strict argv command inside a container on a remote fleet node (or `'local'`)
   * over the ref-counted SSH Docker tunnel (`shell: false`, zero shell string interpolation).
   *
   * @param {string} serverId
   * @param {string} containerId
   * @param {string[]} command
   * @param {{
   *   workdir?: string | null,
   *   user?: string | null,
   *   env?: Record<string, string> | null,
   *   timeoutMs?: number,
   *   maxOutputBytes?: number,
   *   signal?: AbortSignal | null,
   *   onChunk?: (ev: { stream: 'stdout' | 'stderr', chunk: string }) => void
   * }} [opts]
   */
  async remoteContainerExec(serverId, containerId, command, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim() || LOCAL_SERVER_ID;
    const ref = validateDockerRef(containerId, 'containerId');
    const argv = validateDockerExecCommand(command);

    /** @type {string[]} */
    const dockerArgs = ['exec'];
    if (opts.workdir != null && String(opts.workdir).trim() !== '') {
      const wd = String(opts.workdir).trim();
      if (!DOCKER_WORKDIR_RE.test(wd) || wd.includes('..')) {
        throw createFleetError('workdir inválido (debe ser ruta absoluta POSIX sin "..")', 'INVALID_INPUT', 400);
      }
      dockerArgs.push('-w', wd);
    }
    if (opts.user != null && String(opts.user).trim() !== '') {
      const u = String(opts.user).trim();
      if (!DOCKER_USER_RE.test(u) || u.startsWith('-')) {
        throw createFleetError('user de contenedor inválido', 'INVALID_INPUT', 400);
      }
      dockerArgs.push('-u', u);
    }
    if (opts.env && typeof opts.env === 'object') {
      const entries = Object.entries(opts.env);
      if (entries.length > 32) {
        throw createFleetError('Máximo 32 variables env en remoteContainerExec', 'INVALID_INPUT', 400);
      }
      for (const [k, v] of entries) {
        if (!DOCKER_ENV_KEY_RE.test(k)) {
          throw createFleetError(`Nombre de variable env inválido: "${String(k).slice(0, 32)}"`, 'INVALID_INPUT', 400);
        }
        const strVal = String(v == null ? '' : v);
        if (strVal.includes('\0') || strVal.length > 4096) {
          throw createFleetError(`Valor inválido para variable env "${k}"`, 'INVALID_INPUT', 400);
        }
        dockerArgs.push('-e', `${k}=${strVal}`);
      }
    }
    dockerArgs.push(ref, ...argv);

    const timeoutMs = Math.max(1000, Math.min(300000, Number(opts.timeoutMs) || 30000));
    const maxOutputBytes = Math.max(4096, Math.min(4 * 1024 * 1024, Number(opts.maxOutputBytes) || 512 * 1024));
    const started = Date.now();

    const onChunkCb = typeof opts.onChunk === 'function' ? opts.onChunk : null;
    if (onChunkCb) {
      return this.withDockerTunnel(id, async (lease) => {
        const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
        const child = this._spawn('docker', dockerArgs, { stdio: ['ignore', 'pipe', 'pipe'], env });
        let stdout = '';
        let stderr = '';
        let bytes = 0;
        let truncated = false;
        let timedOut = false;

        return new Promise((resolve, reject) => {
          let settled = false;
          const finish = (err, exitCode = 0) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (opts.signal && typeof opts.signal.removeEventListener === 'function') {
              opts.signal.removeEventListener('abort', onAbort);
            }
            if (err) return reject(err);
            resolve({
              serverId: id,
              containerId: ref,
              isLocal: lease.isLocal,
              ok: exitCode === 0 && !timedOut,
              exitCode,
              timedOut,
              truncated,
              stdout: redactSensitiveOutput(stdout),
              stderr: redactSensitiveOutput(stderr),
              durationMs: Date.now() - started
            });
          };

          const onAbort = () => {
            if (child && typeof child.kill === 'function') {
              try { child.kill('SIGTERM'); } catch (e) {}
            }
            finish(createFleetError('Ejecución remota cancelada', 'ABORTED', 499));
          };

          const timer = setTimeout(() => {
            timedOut = true;
            if (child && typeof child.kill === 'function') {
              try { child.kill('SIGTERM'); } catch (e) {}
            }
            finish(createFleetError(`remoteContainerExec excedió ${timeoutMs} ms`, 'TIMEOUT', 504));
          }, timeoutMs);
          if (timer.unref) timer.unref();

          if (opts.signal) {
            if (opts.signal.aborted) return onAbort();
            opts.signal.addEventListener('abort', onAbort, { once: true });
          }

          const pushData = (streamName, raw) => {
            const text = redactSensitiveOutput(Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw || ''));
            if (!text) return;
            const len = Buffer.byteLength(text, 'utf8');
            if (bytes + len > maxOutputBytes) {
              truncated = true;
              const remaining = Math.max(0, maxOutputBytes - bytes);
              const slice = remaining > 0 ? text.slice(0, remaining) : '';
              if (slice) {
                if (streamName === 'stdout') stdout += slice;
                else stderr += slice;
                try { onChunkCb({ stream: streamName, chunk: slice }); } catch (e) {}
              }
              bytes = maxOutputBytes;
              return;
            }
            bytes += len;
            if (streamName === 'stdout') stdout += text;
            else stderr += text;
            try { onChunkCb({ stream: streamName, chunk: text }); } catch (e) {}
          };

          if (child && child.stdout && typeof child.stdout.on === 'function') {
            child.stdout.on('data', (c) => pushData('stdout', c));
          }
          if (child && child.stderr && typeof child.stderr.on === 'function') {
            child.stderr.on('data', (c) => pushData('stderr', c));
          }
          if (child && typeof child.once === 'function') {
            child.once('error', (err) => finish(err));
            child.once('close', (code) => finish(null, typeof code === 'number' ? code : 1));
            child.once('exit', (code) => finish(null, typeof code === 'number' ? code : 1));
          } else {
            finish(null, 0);
          }
        });
      }, { signal: opts.signal || null });
    }

    return this.withResilientDockerTunnel(id, async (lease, meta) => {
      const env = lease.dockerHost ? { ...process.env, DOCKER_HOST: lease.dockerHost } : { ...process.env };
      try {
        const res = await this._execFile('docker', dockerArgs, { timeout: timeoutMs, env, maxBuffer: maxOutputBytes });
        return {
          serverId: id,
          containerId: ref,
          isLocal: lease.isLocal,
          reconnected: meta.reconnected,
          ok: true,
          exitCode: 0,
          stdout: redactSensitiveOutput(res.stdout),
          stderr: redactSensitiveOutput(res.stderr),
          durationMs: Date.now() - started
        };
      } catch (err) {
        /** @type {any} */
        const e = err;
        // Rethrow tunnel/daemon transport failures so withResilientDockerTunnel can reconnect
        if (isRetryableTunnelError(e) || (typeof lease.isAlive === 'function' && !lease.isAlive())) {
          throw err;
        }
        const exitCode = typeof e.code === 'number' ? e.code : 1;
        return {
          serverId: id,
          containerId: ref,
          isLocal: lease.isLocal,
          reconnected: meta.reconnected,
          ok: false,
          exitCode,
          stdout: redactSensitiveOutput(e.stdout || ''),
          stderr: redactSensitiveOutput(e.stderr || e.message || ''),
          durationMs: Date.now() - started
        };
      }
    }, { signal: opts.signal || null });
  }

  /**
   * Allocates a free host port on a remote server by inspecting `docker ps -a --format '{{.Ports}}'`
   * over the tunneled `DOCKER_HOST` (without mutating `process.env.DOCKER_HOST`).
   *
   * @param {string} serverId
   * @param {{ dockerHost?: string | null } | null} [lease]
   * @param {{ minPort?: number, maxPort?: number, reservedPorts?: number[] }} [opts]
   * @returns {Promise<number>}
   */
  async allocateRemotePort(serverId, lease = null, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    const minPort = validatePort(opts.minPort ?? DEFAULTS.remotePortMin, 'minPort');
    const maxPort = validatePort(opts.maxPort ?? DEFAULTS.remotePortMax, 'maxPort');
    if (minPort > maxPort) {
      throw createFleetError('Rango de puertos inválido (minPort > maxPort)', 'INVALID_PORT_RANGE', 400);
    }

    /** @param {string | null} dockerHost */
    const pickWithDockerHost = async (dockerHost) => {
      const env = { ...process.env };
      if (dockerHost) {
        env.DOCKER_HOST = dockerHost;
      }
      const res = await this._execFile(
        'docker',
        ['ps', '-a', '--format', '{{.Ports}}'],
        { timeout: 10000, env }
      );
      const used = parseDockerPublishedPorts(res.stdout);

      if (Array.isArray(opts.reservedPorts)) {
        for (const p of opts.reservedPorts) {
          const n = Number(p);
          if (Number.isInteger(n)) used.add(n);
        }
      }

      const now = Date.now();
      let recentMap = this._recentRemotePorts.get(id);
      if (!recentMap) {
        recentMap = new Map();
        this._recentRemotePorts.set(id, recentMap);
      }
      for (const [portNum, expiresAt] of recentMap.entries()) {
        if (expiresAt <= now) {
          recentMap.delete(portNum);
        } else {
          used.add(portNum);
        }
      }

      for (let port = minPort; port <= maxPort; port++) {
        if (!used.has(port)) {
          recentMap.set(port, now + 120000);
          return port;
        }
      }
      throw createFleetError(
        `No hay puertos libres en el rango ${minPort}-${maxPort} en el servidor "${id}"`,
        'NO_FREE_REMOTE_PORT',
        503
      );
    };

    if (id === LOCAL_SERVER_ID) {
      return pickWithDockerHost(null);
    }
    if (lease && lease.dockerHost) {
      return pickWithDockerHost(lease.dockerHost);
    }
    return this.withDockerTunnel(id, (acquired) => pickWithDockerHost(acquired.dockerHost));
  }

  // -------------------------------------------------------------------------
  // Single-Roundtrip Static POSIX Probe & Lazy Background Health Monitor
  // -------------------------------------------------------------------------

  /**
   * Probes a fleet node in a single SSH roundtrip using static constant `PROBE_CMD`
   * (zero user input interpolation). Coalesces concurrent probes per `serverId` and caches for 15s.
   *
   * @param {string} serverId
   * @param {{ force?: boolean, timeoutMs?: number }} [opts]
   */
  async probeServer(serverId, opts = {}) {
    this._ensureLoaded();
    const id = String(serverId || '').trim();
    if (id === LOCAL_SERVER_ID) {
      const localNode = this._buildVirtualLocalServer();
      return {
        ok: true,
        cached: false,
        status: localNode.status,
        resources: localNode.resources,
        warnings: [],
        server: localNode
      };
    }

    const server = this._servers.get(id);
    if (!server) {
      throw createFleetError(`Servidor no encontrado: ${id}`, 'SERVER_NOT_FOUND', 404);
    }

    const force = Boolean(opts.force);
    if (
      !force &&
      server.status !== 'host_key_mismatch' &&
      server.lastProbedAt &&
      server.resources &&
      (Date.now() - Date.parse(server.lastProbedAt)) < this._probeTtlMs
    ) {
      return {
        ok: server.status === 'online' || server.status === 'degraded',
        cached: true,
        status: server.status,
        resources: { ...server.resources },
        warnings: [...(server.warnings || [])],
        server: this.sanitizeServer(server)
      };
    }

    const existing = this._inFlightProbes.get(id);
    if (existing) return existing;

    const promise = this._runSingleProbe(server, opts.timeoutMs ?? DEFAULTS.probeTimeoutMs)
      .finally(() => {
        if (this._inFlightProbes.get(id) === promise) {
          this._inFlightProbes.delete(id);
        }
      });
    this._inFlightProbes.set(id, promise);
    return promise;
  }

  /**
   * @param {FleetServerRecord} server
   * @param {number} timeoutMs
   */
  async _runSingleProbe(server, timeoutMs) {
    const { pinnedIp } = await assertSafeFleetHost(server.host, { resolveHost: this._resolveHost });
    const knownHostsFile = await this._ensureHostKeyReady(server, pinnedIp);

    const started = Date.now();
    try {
      const { stdout } = await this.withEphemeralKey(server.keyId, async (keyFile) => {
        const sshArgs = buildBaseSshArgs(server, {
          keyFile,
          knownHostsFile,
          pinnedIp,
          connectTimeoutSec: Math.max(1, Math.min(30, Math.ceil(timeoutMs / 1000))),
          clearAllForwardings: true,
          platform: this._platform
        });
        sshArgs.push(PROBE_CMD);
        return this._execFile('ssh', sshArgs, { timeout: timeoutMs });
      });

      const latencyMs = Date.now() - started;
      const parsed = parseProbeOutput(stdout, latencyMs, server.user);

      server.resources = parsed.resources;
      server.status = /** @type {'online' | 'degraded'} */ (parsed.status);
      server.statusReason = parsed.statusReason;
      server.statusFix = parsed.statusFix;
      server.warnings = parsed.warnings;
      server.consecutiveFailures = 0;
      server.lastProbedAt = new Date().toISOString();
      server.updatedAt = server.lastProbedAt;
      this._nextProbeAt.set(server.id, Date.now() + this._monitorIntervalMs);
      this._saveServers();

      const sanitized = this.sanitizeServer(server);
      this.emit('server:probed', sanitized);
      return {
        ok: true,
        cached: false,
        status: server.status,
        resources: { ...parsed.resources },
        warnings: [...parsed.warnings],
        server: sanitized
      };
    } catch (err) {
      /** @type {any} */
      const e = err;
      const combinedErr = `${e && e.stderr ? e.stderr : ''}\n${e && e.message ? e.message : ''}`;

      if ((e && e.code === 'HOST_KEY_MISMATCH') || isHostKeyErrorText(combinedErr)) {
        this._triggerHostKeyMismatchLockdown(server, combinedErr);
        throw createFleetError(
          `Clave de host SSH modificada en "${server.id}" (HOST_KEY_MISMATCH). Conexión abortada por seguridad.`,
          'HOST_KEY_MISMATCH',
          409,
          { serverId: server.id, expected: server.hostKeyFingerprint }
        );
      }

      if (e && (e.code === 'SSRF_BLOCKED' || e.code === 'KEY_NOT_FOUND' || e.code === 'FLEET_KEY_MISSING' || e.code === 'CRYPTO_DECRYPT_FAILED')) {
        throw e;
      }

      server.consecutiveFailures = (server.consecutiveFailures || 0) + 1;
      server.status = 'offline';
      server.statusReason = redactSensitiveOutput(e && (e.stderr || e.message) ? (e.stderr || e.message) : 'Error de conexión SSH').trim().slice(0, 240);
      server.statusFix = 'Verifica conectividad SSH, firewall/puerto y que la clave pública esté en ~/.ssh/authorized_keys del servidor remoto.';
      server.lastProbedAt = new Date().toISOString();
      server.updatedAt = server.lastProbedAt;

      // Exponential backoff: 60s -> 120s -> 300s
      const backoffMs = server.consecutiveFailures === 1
        ? Math.max(this._monitorIntervalMs, 60000)
        : (server.consecutiveFailures === 2 ? 120000 : 300000);
      this._nextProbeAt.set(server.id, Date.now() + backoffMs);
      this._saveServers();

      const sanitized = this.sanitizeServer(server);
      this.emit('server:probed', sanitized);
      return {
        ok: false,
        cached: false,
        status: 'offline',
        error: server.statusReason,
        resources: server.resources ? { ...server.resources } : null,
        warnings: [server.statusReason],
        server: sanitized
      };
    }
  }

  /**
   * Starts the lazy background health monitor ONLY when `>= 1` remote server exists.
   * Uses a jittered `.unref()` timer with per-server exponential backoff (`60s -> 120s -> 300s`).
   * @returns {boolean} Whether the monitor is active
   */
  startMonitor() {
    this._ensureLoaded();
    if (this._servers.size === 0) {
      this.stopMonitor();
      return false;
    }
    if (this._monitorRunning) return true;
    this._monitorRunning = true;
    this._scheduleNextMonitorTick();
    return true;
  }

  _scheduleNextMonitorTick() {
    if (!this._monitorRunning) return;
    if (this._monitorTimer) {
      clearTimeout(this._monitorTimer);
      this._monitorTimer = null;
    }
    if (this._servers.size === 0) {
      this._monitorRunning = false;
      return;
    }
    const jitter = Math.round((Math.random() * 0.2 - 0.1) * this._monitorIntervalMs);
    const delay = Math.max(1000, this._monitorIntervalMs + jitter);
    this._monitorTimer = setTimeout(() => {
      this._monitorTimer = null;
      this._runMonitorTick()
        .catch(() => {})
        .finally(() => {
          if (this._monitorRunning) {
            this._scheduleNextMonitorTick();
          }
        });
    }, delay);
    if (this._monitorTimer.unref) this._monitorTimer.unref();
  }

  async _runMonitorTick() {
    if (!this._monitorRunning || this._servers.size === 0) return;
    const now = Date.now();
    const servers = Array.from(this._servers.values());
    for (const s of servers) {
      if (!this._monitorRunning) break;
      if (s.status === 'host_key_mismatch') continue;
      const dueAt = this._nextProbeAt.get(s.id) || 0;
      if (now < dueAt) continue;
      try {
        await this.probeServer(s.id, { force: true });
      } catch (e) {
        // Security/network failures already recorded on server record
      }
    }
  }

  stopMonitor() {
    this._monitorRunning = false;
    if (this._monitorTimer) {
      clearTimeout(this._monitorTimer);
      this._monitorTimer = null;
    }
  }

  // -------------------------------------------------------------------------
  // Fleet Summaries (for MCP Resource & System Doctor)
  // -------------------------------------------------------------------------

  getFleetSummary() {
    this._ensureLoaded();
    const servers = this.listServers({ includeLocal: true });
    const remotes = servers.filter((s) => !s.isLocal);
    const onlineCount = remotes.filter((s) => s.status === 'online').length;
    const degradedCount = remotes.filter((s) => s.status === 'degraded').length;
    const offlineCount = remotes.filter((s) => s.status === 'offline').length;
    const mismatchCount = remotes.filter((s) => s.status === 'host_key_mismatch').length;
    const pendingCount = remotes.filter((s) => s.status === 'pending').length;
    const drainingCount = remotes.filter((s) => s.maintenanceState === 'draining').length;
    const maintenanceCount = remotes.filter((s) => s.maintenanceState === 'maintenance').length;
    const schedulableCount = servers.filter((s) => s.status === 'online' && (!s.maintenanceState || s.maintenanceState === 'active')).length;

    return {
      totalServers: servers.length,
      remoteCount: remotes.length,
      onlineCount,
      degradedCount,
      offlineCount,
      mismatchCount,
      pendingCount,
      drainingCount,
      maintenanceCount,
      schedulableCount,
      keysCount: this._keys.size,
      activeTunnels: this._dockerTunnels.size + this._drainingTunnels.size,
      monitorActive: this._monitorRunning,
      servers
    };
  }

  getDoctorSummary() {
    const summary = this.getFleetSummary();
    let status = 'ok';
    let message = summary.remoteCount === 0
      ? 'Modo nodo único local (0 nodos SSH remotos, 0 sobrecarga en reposo).'
      : `${summary.onlineCount}/${summary.remoteCount} nodos remotos online`;

    if (summary.mismatchCount > 0) {
      status = 'error';
      message = `${summary.mismatchCount} nodo(s) bloqueado(s) por HOST_KEY_MISMATCH (requiere verificación manual y repinHostKey).`;
    } else if (summary.offlineCount > 0 || summary.degradedCount > 0) {
      status = 'warn';
      message = `Flota remota: ${summary.onlineCount} online, ${summary.degradedCount} degradado(s), ${summary.offlineCount} offline.`;
    } else if (summary.drainingCount > 0 || summary.maintenanceCount > 0) {
      message = `${summary.onlineCount}/${summary.remoteCount} nodos remotos online (${summary.drainingCount} drenando, ${summary.maintenanceCount} en mantenimiento).`;
    }

    return {
      ok: status === 'ok',
      status,
      message,
      remoteCount: summary.remoteCount,
      onlineCount: summary.onlineCount,
      degradedCount: summary.degradedCount,
      offlineCount: summary.offlineCount,
      mismatchCount: summary.mismatchCount,
      drainingCount: summary.drainingCount,
      maintenanceCount: summary.maintenanceCount,
      schedulableCount: summary.schedulableCount,
      activeTunnels: summary.activeTunnels,
      keysCount: summary.keysCount
    };
  }

  // -------------------------------------------------------------------------
  // Clean Shutdown
  // -------------------------------------------------------------------------

  async shutdown() {
    this.stopMonitor();

    for (const entry of Array.from(this._dockerTunnelConnects.values())) {
      if (entry && entry.internalController && typeof entry.internalController.abort === 'function') {
        if (entry.promise && typeof entry.promise.catch === 'function') entry.promise.catch(() => {});
        try { entry.internalController.abort(); } catch (e) {}
      }
    }
    this._dockerTunnelConnects.clear();

    for (const tunnel of Array.from(this._dockerTunnels.values())) {
      this._closeTunnelImmediate(tunnel);
    }
    for (const tunnel of Array.from(this._drainingTunnels)) {
      this._closeTunnelImmediate(tunnel);
    }
    for (const child of Array.from(this._ephemeralTunnelChildren)) {
      if (child && typeof child.kill === 'function') {
        try { child.kill('SIGTERM'); } catch (e) {}
      }
      this._ephemeralTunnelChildren.delete(child);
    }

    this._inFlightProbes.clear();

    if (fs.existsSync(this.tmpDir)) {
      try { this.sweepTmpDir(); } catch (e) {}
    }
    try { this.sweepStaleSockets(); } catch (e) {}
  }
}

const singleton = new ServerFleetManager();

module.exports = Object.assign(singleton, {
  ServerFleetManager,
  LOCAL_SERVER_ID,
  PROBE_CMD,
  DEFAULTS,
  VALID_MAINTENANCE_STATES,
  helpers: {
    encryptPrivateKey,
    decryptPrivateKey,
    computeSshFingerprint,
    normalizeFingerprint,
    fingerprintsEqual,
    validateHostSyntax,
    parseIpv6Bytes,
    isBlockedFleetIp,
    assertSafeFleetHost,
    validatePort,
    validateSshUser,
    validateDockerSocketPath,
    validateDockerRef,
    validateDockerExecCommand,
    validateServerId,
    validateRegion,
    validateTags,
    validateDisplayName,
    validateTeamId,
    validateMaintenanceState,
    validateMaintenanceReason,
    validateControlPlaneCidr,
    buildBaseSshArgs,
    parseProbeOutput,
    parseDockerPublishedPorts,
    parseDockerStatsLines,
    parseBestKeyscanOutput,
    isRetryableTunnelError,
    defaultProbeEndpoint,
    redactSensitiveOutput,
    secureUnlinkFile,
    ensureSecureDir,
    isHostKeyErrorText
  }
});
