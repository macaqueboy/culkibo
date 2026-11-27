'use strict';

/**
 * Culkibo Zero-Dep FIDO2 WebAuthn Passkeys Service (ZERO `@simplewebauthn` / external deps).
 *
 * Implements:
 *  - Clean RFC 8949 CBOR decoder (`decodeCbor`, `decodeCborAt`) with recursion & length caps.
 *  - WebAuthn authenticatorData parser (`parseAuthenticatorData`) & COSE key converter
 *    (`coseKeyToKeyObject`) supporting ES256 (`alg: -7`, EC2 P-256) and Ed25519 (`alg: -8`, OKP).
 *  - Replay-proof single-use 32-byte challenges (120s TTL, bounded LRU, atomic consumption).
 *  - Full registration & authentication verification (`origin`, `rpIdHash`, `UP`/`UV` flags,
 *    native `node:crypto` signature check, strict monotonic `signCount` anti-cloning).
 *  - Atomic `0o600` credential persistence in isolated `CULKIBO_DATA_DIR/data/passkeys.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CHALLENGE_TTL_MS = 120 * 1000; // 120 seconds
const MAX_ACTIVE_CHALLENGES = 1024;
const MAX_CBOR_DEPTH = 16;
const MAX_CBOR_ITEMS = 4096;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SUPPORTED_ALGS = Object.freeze([-7, -8]);

/**
 * Atomically writes UTF-8 content to disk with `0o600` permissions.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Normalizes a Buffer, Uint8Array, or base64url/base64 string into a Buffer.
 * @param {Buffer | Uint8Array | string} input
 * @returns {Buffer}
 */
function toBuffer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  if (typeof input === 'string') {
    const clean = input.trim();
    if (!clean) return Buffer.alloc(0);
    // Support both base64url and standard base64
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(normalized, 'base64');
  }
  throw new Error('Expected Buffer, Uint8Array, or base64/base64url string');
}

/**
 * Reads an RFC 8949 CBOR additional-info integer argument starting at `offset`.
 * @param {Buffer} buf
 * @param {number} offset
 * @param {number} ai
 * @returns {{ value: number, nextOffset: number }}
 */
function readCborArg(buf, offset, ai) {
  if (ai < 24) return { value: ai, nextOffset: offset };
  if (ai === 24) {
    if (offset + 1 > buf.length) throw new Error('CBOR truncated uint8');
    return { value: buf.readUInt8(offset), nextOffset: offset + 1 };
  }
  if (ai === 25) {
    if (offset + 2 > buf.length) throw new Error('CBOR truncated uint16');
    return { value: buf.readUInt16BE(offset), nextOffset: offset + 2 };
  }
  if (ai === 26) {
    if (offset + 4 > buf.length) throw new Error('CBOR truncated uint32');
    return { value: buf.readUInt32BE(offset), nextOffset: offset + 4 };
  }
  if (ai === 27) {
    if (offset + 8 > buf.length) throw new Error('CBOR truncated uint64');
    const big = buf.readBigUInt64BE(offset);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('CBOR uint64 exceeds MAX_SAFE_INTEGER');
    }
    return { value: Number(big), nextOffset: offset + 8 };
  }
  throw new Error(`Unsupported CBOR additional info: ${ai}`);
}

/**
 * Decodes IEEE 754 half-precision float16.
 * @param {number} half
 * @returns {number}
 */
function decodeFloat16(half) {
  const sign = (half & 0x8000) ? -1 : 1;
  const exp = (half >> 10) & 0x1f;
  const frac = half & 0x03ff;
  if (exp === 0) return sign * Math.pow(2, -14) * (frac / 1024);
  if (exp === 0x1f) return frac ? NaN : sign * Infinity;
  return sign * Math.pow(2, exp - 15) * (1 + frac / 1024);
}

/**
 * Decodes one RFC 8949 CBOR value from `buf` at `offset`, returning `{ value, nextOffset }`.
 * Maps preserve arbitrary keys (including negative COSE integers) as `Map<any, any>`.
 *
 * @param {Buffer | Uint8Array} input
 * @param {number} [offset]
 * @param {number} [depth]
 * @returns {{ value: any, nextOffset: number }}
 */
function decodeCborAt(input, offset = 0, depth = 0) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (depth > MAX_CBOR_DEPTH) throw new Error('CBOR nesting depth exceeded');
  if (offset >= buf.length) throw new Error('CBOR unexpected end of input');

  const initial = buf.readUInt8(offset);
  const major = initial >> 5;
  const ai = initial & 0x1f;
  let pos = offset + 1;

  if (major === 0) {
    const { value, nextOffset } = readCborArg(buf, pos, ai);
    return { value, nextOffset };
  }

  if (major === 1) {
    const { value, nextOffset } = readCborArg(buf, pos, ai);
    return { value: -1 - value, nextOffset };
  }

  if (major === 2) {
    if (ai === 31) throw new Error('Indefinite-length CBOR byte strings are not permitted');
    const { value: len, nextOffset } = readCborArg(buf, pos, ai);
    pos = nextOffset;
    if (pos + len > buf.length) throw new Error('CBOR byte string out of bounds');
    return { value: Buffer.from(buf.subarray(pos, pos + len)), nextOffset: pos + len };
  }

  if (major === 3) {
    if (ai === 31) throw new Error('Indefinite-length CBOR text strings are not permitted');
    const { value: len, nextOffset } = readCborArg(buf, pos, ai);
    pos = nextOffset;
    if (pos + len > buf.length) throw new Error('CBOR text string out of bounds');
    return { value: buf.subarray(pos, pos + len).toString('utf8'), nextOffset: pos + len };
  }

  if (major === 4) {
    if (ai === 31) throw new Error('Indefinite-length CBOR arrays are not permitted');
    const { value: count, nextOffset } = readCborArg(buf, pos, ai);
    if (count > MAX_CBOR_ITEMS) throw new Error('CBOR array exceeds max item count');
    pos = nextOffset;
    const arr = new Array(count);
    for (let i = 0; i < count; i++) {
      const item = decodeCborAt(buf, pos, depth + 1);
      arr[i] = item.value;
      pos = item.nextOffset;
    }
    return { value: arr, nextOffset: pos };
  }

  if (major === 5) {
    if (ai === 31) throw new Error('Indefinite-length CBOR maps are not permitted');
    const { value: count, nextOffset } = readCborArg(buf, pos, ai);
    if (count > MAX_CBOR_ITEMS) throw new Error('CBOR map exceeds max entry count');
    pos = nextOffset;
    const map = new Map();
    for (let i = 0; i < count; i++) {
      const k = decodeCborAt(buf, pos, depth + 1);
      const v = decodeCborAt(buf, k.nextOffset, depth + 1);
      map.set(k.value, v.value);
      pos = v.nextOffset;
    }
    return { value: map, nextOffset: pos };
  }

  if (major === 6) {
    const { nextOffset } = readCborArg(buf, pos, ai);
    return decodeCborAt(buf, nextOffset, depth + 1);
  }

  if (major === 7) {
    if (ai === 20) return { value: false, nextOffset: pos };
    if (ai === 21) return { value: true, nextOffset: pos };
    if (ai === 22) return { value: null, nextOffset: pos };
    if (ai === 23) return { value: undefined, nextOffset: pos };
    if (ai === 24) {
      if (pos + 1 > buf.length) throw new Error('CBOR truncated simple value');
      return { value: buf.readUInt8(pos), nextOffset: pos + 1 };
    }
    if (ai === 25) {
      if (pos + 2 > buf.length) throw new Error('CBOR truncated float16');
      return { value: decodeFloat16(buf.readUInt16BE(pos)), nextOffset: pos + 2 };
    }
    if (ai === 26) {
      if (pos + 4 > buf.length) throw new Error('CBOR truncated float32');
      return { value: buf.readFloatBE(pos), nextOffset: pos + 4 };
    }
    if (ai === 27) {
      if (pos + 8 > buf.length) throw new Error('CBOR truncated float64');
      return { value: buf.readDoubleBE(pos), nextOffset: pos + 8 };
    }
    throw new Error(`Unsupported CBOR major-7 simple/float ai=${ai}`);
  }

  throw new Error(`Unsupported CBOR major type: ${major}`);
}

/**
 * Decodes a full RFC 8949 CBOR buffer.
 * @param {Buffer | Uint8Array | string} input
 * @returns {any}
 */
function decodeCbor(input) {
  const buf = toBuffer(input);
  if (buf.length === 0) throw new Error('Empty CBOR input');
  return decodeCborAt(buf, 0, 0).value;
}

/**
 * Reads a key from either a CBOR `Map` or a plain JS object.
 * @param {Map<any, any> | Record<string, any>} container
 * @param {string | number} key
 * @returns {any}
 */
function getMapField(container, key) {
  if (container instanceof Map) {
    if (container.has(key)) return container.get(key);
    return container.get(String(key));
  }
  if (container && typeof container === 'object') {
    if (Object.prototype.hasOwnProperty.call(container, key)) return container[key];
    return container[String(key)];
  }
  return undefined;
}

/**
 * Parses a raw WebAuthn `authenticatorData` buffer (WebAuthn Level 2 §6.1).
 * Extracts `rpIdHash`, `flags` (`up`, `uv`, `be`, `bs`, `at`, `ed`), `signCount`,
 * and (when `AT` bit is set) `aaguid`, `credentialId`, and `cosePublicKey`.
 *
 * @param {Buffer | Uint8Array | string} rawAuthData
 */
function parseAuthenticatorData(rawAuthData) {
  const buf = toBuffer(rawAuthData);
  if (buf.length < 37) {
    throw new Error(`authenticatorData too short (${buf.length} bytes, minimum 37)`);
  }

  const rpIdHash = Buffer.from(buf.subarray(0, 32));
  const flagsByte = buf.readUInt8(32);
  const signCount = buf.readUInt32BE(33);

  const flags = {
    raw: flagsByte,
    up: Boolean(flagsByte & 0x01),
    uv: Boolean(flagsByte & 0x04),
    be: Boolean(flagsByte & 0x08),
    bs: Boolean(flagsByte & 0x10),
    at: Boolean(flagsByte & 0x40),
    ed: Boolean(flagsByte & 0x80)
  };

  /** @type {string | null} */
  let aaguid = null;
  /** @type {Buffer | null} */
  let credentialId = null;
  /** @type {string | null} */
  let credentialIdB64Url = null;
  /** @type {any} */
  let cosePublicKey = null;
  /** @type {Buffer | null} */
  let cosePublicKeyBytes = null;

  if (flags.at && buf.length > 37) {
    if (buf.length < 55) {
      throw new Error('authenticatorData AT flag set but attestedCredentialData is truncated');
    }
    const aaguidHex = buf.subarray(37, 53).toString('hex');
    aaguid = `${aaguidHex.slice(0, 8)}-${aaguidHex.slice(8, 12)}-${aaguidHex.slice(12, 16)}-${aaguidHex.slice(16, 20)}-${aaguidHex.slice(20)}`;
    const credIdLen = buf.readUInt16BE(53);
    const credEnd = 55 + credIdLen;
    if (credEnd > buf.length) {
      throw new Error('authenticatorData credentialId extends past buffer end');
    }
    credentialId = Buffer.from(buf.subarray(55, credEnd));
    credentialIdB64Url = credentialId.toString('base64url');

    if (credEnd < buf.length) {
      const decoded = decodeCborAt(buf, credEnd, 0);
      cosePublicKey = decoded.value;
      cosePublicKeyBytes = Buffer.from(buf.subarray(credEnd, decoded.nextOffset));
    }
  }

  return {
    rpIdHash,
    rpIdHashHex: rpIdHash.toString('hex'),
    flags,
    signCount,
    aaguid,
    credentialId,
    credentialIdB64Url,
    cosePublicKey,
    cosePublicKeyBytes
  };
}

/**
 * Converts a COSE public key (`Map` or plain object) into a native Node `crypto.KeyObject`
 * + SPKI PEM. Supports:
 *  - ES256 (`alg: -7`, `kty: 2` EC2, `crv: 1` P-256)
 *  - Ed25519 (`alg: -8`, `kty: 1` OKP, `crv: 6` Ed25519)
 *
 * @param {Map<any, any> | Record<string, any> | Buffer} coseInput
 */
function coseKeyToKeyObject(coseInput) {
  const coseMap = Buffer.isBuffer(coseInput) ? decodeCbor(coseInput) : coseInput;
  if (!coseMap || (typeof coseMap !== 'object' && !(coseMap instanceof Map))) {
    throw new Error('Invalid COSE public key');
  }

  const kty = Number(getMapField(coseMap, 1));
  const alg = Number(getMapField(coseMap, 3));
  const crv = Number(getMapField(coseMap, -1));

  // ES256: EC2 P-256
  if (alg === -7 && kty === 2 && crv === 1) {
    const rawX = getMapField(coseMap, -2);
    const rawY = getMapField(coseMap, -3);
    const xBuf = toBuffer(rawX);
    const yBuf = toBuffer(rawY);
    if (xBuf.length !== 32 || yBuf.length !== 32) {
      throw new Error(`Invalid P-256 COSE coordinates (x=${xBuf.length}B, y=${yBuf.length}B)`);
    }
    const keyObject = crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: xBuf.toString('base64url'),
        y: yBuf.toString('base64url')
      },
      format: 'jwk'
    });
    const publicKeyPem = String(keyObject.export({ type: 'spki', format: 'pem' }));
    return { keyObject, alg: -7, algName: 'ES256', publicKeyPem };
  }

  // EdDSA: OKP Ed25519
  if (alg === -8 && kty === 1 && crv === 6) {
    const rawX = getMapField(coseMap, -2);
    const xBuf = toBuffer(rawX);
    if (xBuf.length !== 32) {
      throw new Error(`Invalid Ed25519 COSE public key length (${xBuf.length}B, expected 32B)`);
    }
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, xBuf]);
    const keyObject = crypto.createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki'
    });
    const publicKeyPem = String(keyObject.export({ type: 'spki', format: 'pem' }));
    return { keyObject, alg: -8, algName: 'Ed25519', publicKeyPem };
  }

  throw new Error(`Unsupported COSE key parameters (kty=${kty}, alg=${alg}, crv=${crv}); supported: ES256 (-7), Ed25519 (-8)`);
}

/**
 * Constant-time string equality check.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeStrEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Cryptographically verifies a WebAuthn `webauthn.get` assertion against a stored public key.
 * Enforces `type`, `challenge`, `origin`, `rpIdHash`, `UP` (and `UV` if requested),
 * ES256/Ed25519 signature verification, and strict monotonic `signCount` anti-cloning.
 *
 * @param {{
 *   publicKeyPem: string,
 *   alg: number,
 *   clientDataJSON: Buffer | string,
 *   authenticatorData: Buffer | string,
 *   signature: Buffer | string,
 *   expectedChallenge: string,
 *   expectedOrigin: string,
 *   expectedRpId: string,
 *   requireUv?: boolean,
 *   storedSignCount?: number
 * }} opts
 */
function verifyWebAuthnAssertion(opts) {
  const clientDataBuf = toBuffer(opts.clientDataJSON);
  const authDataBuf = toBuffer(opts.authenticatorData);
  const sigBuf = toBuffer(opts.signature);

  /** @type {any} */
  let clientData;
  try {
    clientData = JSON.parse(clientDataBuf.toString('utf8'));
  } catch (e) {
    return { valid: false, reason: 'INVALID_CLIENT_DATA_JSON' };
  }

  if (!clientData || clientData.type !== 'webauthn.get') {
    return { valid: false, reason: 'INVALID_CLIENT_DATA_TYPE' };
  }
  if (!timingSafeStrEqual(clientData.challenge, opts.expectedChallenge)) {
    return { valid: false, reason: 'CHALLENGE_MISMATCH' };
  }
  if (String(clientData.origin || '') !== String(opts.expectedOrigin || '')) {
    return { valid: false, reason: 'ORIGIN_MISMATCH' };
  }

  let parsedAuth;
  try {
    parsedAuth = parseAuthenticatorData(authDataBuf);
  } catch (e) {
    return { valid: false, reason: 'INVALID_AUTH_DATA' };
  }

  const expectedRpHash = crypto.createHash('sha256').update(String(opts.expectedRpId || ''), 'utf8').digest();
  if (!crypto.timingSafeEqual(parsedAuth.rpIdHash, expectedRpHash)) {
    return { valid: false, reason: 'RP_ID_HASH_MISMATCH' };
  }
  if (!parsedAuth.flags.up) {
    return { valid: false, reason: 'USER_NOT_PRESENT' };
  }
  if (opts.requireUv && !parsedAuth.flags.uv) {
    return { valid: false, reason: 'USER_NOT_VERIFIED' };
  }

  const storedCount = Number(opts.storedSignCount) || 0;
  if (storedCount > 0 && parsedAuth.signCount <= storedCount) {
    return {
      valid: false,
      reason: 'SIGN_COUNT_REGRESSION',
      storedSignCount: storedCount,
      receivedSignCount: parsedAuth.signCount
    };
  }

  const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
  const signedData = Buffer.concat([authDataBuf, clientDataHash]);

  let keyObj;
  try {
    keyObj = crypto.createPublicKey(opts.publicKeyPem);
  } catch (e) {
    return { valid: false, reason: 'INVALID_PUBLIC_KEY' };
  }

  let sigValid = false;
  try {
    if (opts.alg === -8) {
      sigValid = crypto.verify(null, signedData, keyObj, sigBuf);
    } else if (opts.alg === -7) {
      sigValid = crypto.verify('sha256', signedData, keyObj, sigBuf);
      if (!sigValid && sigBuf.length === 64) {
        sigValid = crypto.verify('sha256', signedData, { key: keyObj, dsaEncoding: 'ieee-p1363' }, sigBuf);
      }
    } else {
      return { valid: false, reason: 'UNSUPPORTED_ALGORITHM' };
    }
  } catch (e) {
    sigValid = false;
  }

  if (!sigValid) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  return {
    valid: true,
    reason: 'OK',
    signCount: parsedAuth.signCount,
    flags: parsedAuth.flags,
    origin: clientData.origin,
    rpIdHashHex: parsedAuth.rpIdHashHex
  };
}

class PasskeyService {
  /**
   * @param {{ dataDir?: string | null, challengeTtlMs?: number }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
    this.challengeTtlMs = Number.isFinite(Number(opts.challengeTtlMs)) && Number(opts.challengeTtlMs) >= 1000
      ? Math.round(Number(opts.challengeTtlMs))
      : CHALLENGE_TTL_MS;

    /** @type {Map<string, { challengeId: string, kind: 'registration' | 'authentication', userId: string | null, username: string | null, rpId: string, origin: string | null, challenge: string, expiresAtMs: number }>} */
    this._challenges = new Map();
  }

  /** @returns {string} */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'passkeys.json');
  }

  /** @returns {Array<any>} */
  _loadCredentials() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && Array.isArray(parsed.credentials)) return parsed.credentials;
      return [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} credentials */
  _saveCredentials(credentials) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), credentials }, null, 2) + '\n'
    );
  }

  _pruneExpiredChallenges() {
    const now = Date.now();
    for (const [id, rec] of this._challenges.entries()) {
      if (rec.expiresAtMs <= now) this._challenges.delete(id);
    }
  }

  /**
   * Atomically consumes a single-use challenge (replay-proof).
   * @param {string} challengeId
   * @param {'registration' | 'authentication'} expectedKind
   */
  _consumeChallenge(challengeId, expectedKind) {
    this._pruneExpiredChallenges();
    const key = String(challengeId || '').trim();
    if (!key) return { ok: false, reason: 'MISSING_CHALLENGE_ID', record: null };
    const rec = this._challenges.get(key);
    if (!rec) return { ok: false, reason: 'CHALLENGE_NOT_FOUND_OR_REPLAYED', record: null };
    // Delete BEFORE checking kind/expiry so replaying a consumed ID is impossible
    this._challenges.delete(key);
    if (rec.kind !== expectedKind) return { ok: false, reason: 'CHALLENGE_KIND_MISMATCH', record: null };
    if (Date.now() > rec.expiresAtMs) return { ok: false, reason: 'CHALLENGE_EXPIRED', record: null };
    return { ok: true, reason: 'OK', record: rec };
  }

  /**
   * Begins WebAuthn Passkey registration, returning single-use `publicKey` creation options.
   * @param {{ userId: string, username: string, rpId?: string, rpName?: string, origin?: string | null }} opts
   */
  beginRegistration(opts) {
    if (!opts || !opts.userId || !opts.username) {
      throw new Error('beginRegistration requires userId and username');
    }
    this._pruneExpiredChallenges();
    if (this._challenges.size >= MAX_ACTIVE_CHALLENGES) {
      const oldest = this._challenges.keys().next().value;
      if (oldest) this._challenges.delete(oldest);
    }

    const userId = String(opts.userId).trim();
    const username = String(opts.username).trim();
    const rpId = String(opts.rpId || 'localhost').trim().toLowerCase();
    const rpName = String(opts.rpName || 'Culkibo').trim();
    const origin = opts.origin ? String(opts.origin).trim() : null;

    const challengeId = `pkreg_${crypto.randomBytes(12).toString('hex')}`;
    const challenge = crypto.randomBytes(32).toString('base64url');
    const expiresAtMs = Date.now() + this.challengeTtlMs;

    this._challenges.set(challengeId, {
      challengeId,
      kind: 'registration',
      userId,
      username,
      rpId,
      origin,
      challenge,
      expiresAtMs
    });

    const existing = this._loadCredentials().filter((c) => c.userId === userId);
    const excludeCredentials = existing.map((c) => ({
      type: 'public-key',
      id: c.id
    }));

    return {
      challengeId,
      challenge,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      publicKey: {
        challenge,
        rp: { id: rpId, name: rpName },
        user: {
          id: Buffer.from(userId, 'utf8').toString('base64url'),
          name: username,
          displayName: username
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -8 }
        ],
        timeout: this.challengeTtlMs,
        attestation: 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred'
        },
        excludeCredentials
      }
    };
  }

  /**
   * Completes WebAuthn registration: atomically consumes challenge, validates clientDataJSON,
   * origin, rpIdHash, extracts COSE public key from attestationObject, and persists credential.
   *
   * @param {{
   *   userId?: string,
   *   challengeId: string,
   *   credentialId?: string,
   *   clientDataJSON: Buffer | string,
   *   attestationObject?: Buffer | string,
   *   publicKeyCose?: Map<any, any> | Record<string, any> | Buffer,
   *   label?: string,
   *   expectedOrigin?: string,
   *   expectedRpId?: string
   * }} opts
   */
  finishRegistration(opts) {
    if (!opts || typeof opts !== 'object') {
      return { ok: false, valid: false, reason: 'INVALID_REQUEST' };
    }
    const consumed = this._consumeChallenge(opts.challengeId, 'registration');
    if (!consumed.ok || !consumed.record) {
      return { ok: false, valid: false, reason: consumed.reason };
    }
    const chRec = consumed.record;
    if (opts.userId && String(opts.userId).trim() !== chRec.userId) {
      return { ok: false, valid: false, reason: 'USER_MISMATCH' };
    }

    const expectedOrigin = String(opts.expectedOrigin || chRec.origin || '').trim();
    const expectedRpId = String(opts.expectedRpId || chRec.rpId || 'localhost').trim().toLowerCase();

    /** @type {any} */
    let clientData;
    try {
      clientData = JSON.parse(toBuffer(opts.clientDataJSON).toString('utf8'));
    } catch (e) {
      return { ok: false, valid: false, reason: 'INVALID_CLIENT_DATA_JSON' };
    }

    if (!clientData || clientData.type !== 'webauthn.create') {
      return { ok: false, valid: false, reason: 'INVALID_CLIENT_DATA_TYPE' };
    }
    if (!timingSafeStrEqual(clientData.challenge, chRec.challenge)) {
      return { ok: false, valid: false, reason: 'CHALLENGE_MISMATCH' };
    }
    if (expectedOrigin && String(clientData.origin || '') !== expectedOrigin) {
      return { ok: false, valid: false, reason: 'ORIGIN_MISMATCH' };
    }

    /** @type {ReturnType<typeof parseAuthenticatorData> | null} */
    let parsedAuth = null;
    if (opts.attestationObject) {
      try {
        const attObj = decodeCbor(opts.attestationObject);
        const authDataRaw = getMapField(attObj, 'authData');
        if (!authDataRaw) return { ok: false, valid: false, reason: 'MISSING_AUTH_DATA' };
        parsedAuth = parseAuthenticatorData(authDataRaw);
      } catch (e) {
        return { ok: false, valid: false, reason: 'INVALID_ATTESTATION_OBJECT' };
      }

      if (!parsedAuth) return { ok: false, valid: false, reason: 'INVALID_ATTESTATION_OBJECT' };
      const expectedRpHash = crypto.createHash('sha256').update(expectedRpId, 'utf8').digest();
      if (!crypto.timingSafeEqual(parsedAuth.rpIdHash, expectedRpHash)) {
        return { ok: false, valid: false, reason: 'RP_ID_HASH_MISMATCH' };
      }
      if (!parsedAuth.flags.up) {
        return { ok: false, valid: false, reason: 'USER_NOT_PRESENT' };
      }
    }

    const coseKey = (parsedAuth && parsedAuth.cosePublicKey) || opts.publicKeyCose;
    if (!coseKey) {
      return { ok: false, valid: false, reason: 'MISSING_PUBLIC_KEY_COSE' };
    }

    let keyInfo;
    try {
      keyInfo = coseKeyToKeyObject(coseKey);
    } catch (e) {
      return { ok: false, valid: false, reason: 'UNSUPPORTED_COSE_KEY', error: e && /** @type {any} */ (e).message };
    }

    const credId = String((parsedAuth && parsedAuth.credentialIdB64Url) || opts.credentialId || '').trim();
    if (!credId || credId.length > 512) {
      return { ok: false, valid: false, reason: 'MISSING_CREDENTIAL_ID' };
    }

    const credentials = this._loadCredentials();
    if (credentials.some((c) => c.id === credId)) {
      return { ok: false, valid: false, reason: 'CREDENTIAL_ALREADY_REGISTERED' };
    }

    const nowIso = new Date().toISOString();
    const record = {
      id: credId,
      userId: chRec.userId,
      username: chRec.username,
      label: String(opts.label || `Passkey (${keyInfo.algName})`).trim().slice(0, 80),
      rpId: expectedRpId,
      alg: keyInfo.alg,
      algName: keyInfo.algName,
      publicKeyPem: keyInfo.publicKeyPem,
      signCount: parsedAuth ? parsedAuth.signCount : 0,
      aaguid: parsedAuth ? parsedAuth.aaguid : null,
      createdAt: nowIso,
      lastUsedAt: null
    };

    credentials.push(record);
    this._saveCredentials(credentials);

    return {
      ok: true,
      valid: true,
      credential: record
    };
  }

  /**
   * Begins WebAuthn Passkey authentication, returning single-use challenge & allowCredentials.
   * @param {{ userId?: string | null, rpId?: string, origin?: string | null }} [opts]
   */
  beginAuthentication(opts = {}) {
    this._pruneExpiredChallenges();
    if (this._challenges.size >= MAX_ACTIVE_CHALLENGES) {
      const oldest = this._challenges.keys().next().value;
      if (oldest) this._challenges.delete(oldest);
    }

    const userId = opts.userId ? String(opts.userId).trim() : null;
    const rpId = String(opts.rpId || 'localhost').trim().toLowerCase();
    const origin = opts.origin ? String(opts.origin).trim() : null;
    const challengeId = `pkauth_${crypto.randomBytes(12).toString('hex')}`;
    const challenge = crypto.randomBytes(32).toString('base64url');
    const expiresAtMs = Date.now() + this.challengeTtlMs;

    this._challenges.set(challengeId, {
      challengeId,
      kind: 'authentication',
      userId,
      username: null,
      rpId,
      origin,
      challenge,
      expiresAtMs
    });

    const creds = this._loadCredentials();
    const allowCredentials = (userId ? creds.filter((c) => c.userId === userId) : creds).map((c) => ({
      type: 'public-key',
      id: c.id
    }));

    return {
      challengeId,
      challenge,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      publicKey: {
        challenge,
        rpId,
        timeout: this.challengeTtlMs,
        userVerification: 'preferred',
        allowCredentials
      }
    };
  }

  /**
   * Verifies a WebAuthn authentication assertion, enforcing single-use challenge,
   * origin, rpIdHash, cryptographic signature, and strict monotonic `signCount`.
   *
   * @param {{
   *   challengeId: string,
   *   credentialId: string,
   *   clientDataJSON: Buffer | string,
   *   authenticatorData: Buffer | string,
   *   signature: Buffer | string,
   *   expectedOrigin?: string,
   *   expectedRpId?: string,
   *   requireUv?: boolean
   * }} opts
   */
  finishAuthentication(opts) {
    if (!opts || typeof opts !== 'object') {
      return { ok: false, valid: false, reason: 'INVALID_REQUEST' };
    }
    const consumed = this._consumeChallenge(opts.challengeId, 'authentication');
    if (!consumed.ok || !consumed.record) {
      return { ok: false, valid: false, reason: consumed.reason };
    }
    const chRec = consumed.record;

    const credId = String(opts.credentialId || '').trim();
    const credentials = this._loadCredentials();
    const idx = credentials.findIndex((c) => c.id === credId);
    if (idx === -1) {
      return { ok: false, valid: false, reason: 'CREDENTIAL_NOT_FOUND' };
    }
    const cred = credentials[idx];
    if (chRec.userId && cred.userId !== chRec.userId) {
      return { ok: false, valid: false, reason: 'CREDENTIAL_USER_MISMATCH' };
    }

    const expectedOrigin = String(opts.expectedOrigin || chRec.origin || '').trim();
    const expectedRpId = String(opts.expectedRpId || chRec.rpId || cred.rpId || 'localhost').trim().toLowerCase();

    const verification = verifyWebAuthnAssertion({
      publicKeyPem: cred.publicKeyPem,
      alg: cred.alg,
      clientDataJSON: opts.clientDataJSON,
      authenticatorData: opts.authenticatorData,
      signature: opts.signature,
      expectedChallenge: chRec.challenge,
      expectedOrigin,
      expectedRpId,
      requireUv: Boolean(opts.requireUv),
      storedSignCount: Number(cred.signCount) || 0
    });

    if (!verification.valid) {
      return { ok: false, valid: false, reason: verification.reason };
    }

    cred.signCount = verification.signCount;
    cred.lastUsedAt = new Date().toISOString();
    credentials[idx] = cred;
    this._saveCredentials(credentials);

    return {
      ok: true,
      valid: true,
      reason: 'OK',
      credentialId: cred.id,
      userId: cred.userId,
      username: cred.username,
      alg: cred.alg,
      algName: cred.algName,
      signCount: cred.signCount,
      lastUsedAt: cred.lastUsedAt
    };
  }

  /**
   * Lists registered passkeys (optionally filtered by `userId`).
   * @param {string | null | undefined} [userId]
   */
  listPasskeys(userId) {
    const all = this._loadCredentials();
    const filtered = userId ? all.filter((c) => c.userId === String(userId).trim()) : all;
    return filtered.map((c) => ({
      id: c.id,
      userId: c.userId,
      username: c.username,
      label: c.label,
      rpId: c.rpId,
      alg: c.alg,
      algName: c.algName,
      signCount: c.signCount,
      aaguid: c.aaguid || null,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt || null
    }));
  }

  /**
   * Revokes a registered passkey by `credentialId` (enforcing `userId` ownership when provided).
   * @param {string} credentialId
   * @param {string | null | undefined} [userId]
   */
  revokePasskey(credentialId, userId) {
    const targetId = String(credentialId || '').trim();
    if (!targetId) return { revoked: false, reason: 'MISSING_CREDENTIAL_ID' };
    const all = this._loadCredentials();
    const idx = all.findIndex((c) => c.id === targetId && (!userId || c.userId === String(userId).trim()));
    if (idx === -1) return { revoked: false, reason: 'NOT_FOUND' };
    const [removed] = all.splice(idx, 1);
    this._saveCredentials(all);
    return { revoked: true, credentialId: removed.id, userId: removed.userId };
  }
}

const defaultPasskeyService = new PasskeyService();

const exported = Object.assign(defaultPasskeyService, {
  PasskeyService,
  decodeCbor,
  decodeCborAt,
  parseAuthenticatorData,
  coseKeyToKeyObject,
  verifyWebAuthnAssertion,
  CHALLENGE_TTL_MS,
  SUPPORTED_ALGS
});

module.exports = exported;
