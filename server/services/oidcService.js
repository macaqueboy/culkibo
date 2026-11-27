const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');

const { safeFetch, atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Motor OIDC / OAuth2 PKCE + Verificación criptográfica JWKS (cero dependencias npm, cero shell).
 *
 * Compatible con GitHub, Google, Authentik, Keycloak y cualquier proveedor OpenID Connect 1.0:
 *  - Carga perezosa: `require('./oidcService')` NO lee disco ni crea temporizadores (0 MB RAM en reposo).
 *  - PKCE S256 obligatorio (`code_verifier` CSPRNG 32 B + `code_challenge = base64url(SHA-256)`).
 *  - `state` + `nonce` criptográficos de un solo uso con TTL de 5 min (consumo atómico antes de red).
 *  - Todas las llamadas salientes (discovery, token exchange, JWKS, userinfo) usan `ssrfGuard.safeFetch`.
 *  - Verificación de `id_token` con Node `crypto.createPublicKey({ key: jwk, format: 'jwk' })` +
 *    `crypto.verify()`: soporta RS256/384/512, PS256/384/512, ES256/384/512 (`ieee-p1363`) y EdDSA;
 *    rechaza explícitamente `alg: "none"` y `HS*` (inmune a confusión de algoritmos RSA->HMAC).
 *  - Exige `email_verified === true` (corta secuestro de cuenta por correo sin verificar) y
 *    prohíbe auto-aprovisionar con rol `owner`.
 *  - `clientSecret` cifrado en reposo con AES-256-GCM + AAD (`data/.oidc.key`, `0o600`).
 */

const DATA_FILE_NAME = 'oidc.json';
const KEY_FILE_NAME = '.oidc.key';
const PENDING_STATE_TTL_MS = 5 * 60 * 1000;
const PENDING_STATE_CAP = 500;
const DISCOVERY_CACHE_TTL_MS = 15 * 60 * 1000;
const JWKS_CACHE_TTL_MS = 15 * 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 5000;
const JWKS_STALE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CLOCK_SKEW_SEC = 60;

const COMPARE_HMAC_KEY = crypto.randomBytes(32);

const PROVIDER_ID_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const ALLOWED_DEFAULT_ROLES = Object.freeze(['viewer', 'developer', 'admin']);
/** @type {Record<string, number>} */
const OIDC_ROLE_RANK = Object.freeze({ viewer: 1, developer: 2, admin: 3 });
const FORBIDDEN_CLAIM_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_GROUP_ROLE_ENTRIES = 64;

/**
 * Valida y sanea `groupsClaim` (p. ej. `'groups'`, `'roles'`, `'realm_access.roles'`).
 * @param {any} rawClaim
 * @returns {string}
 */
function sanitizeGroupsClaim(rawClaim) {
  if (rawClaim === undefined || rawClaim === null || String(rawClaim).trim() === '') {
    return 'groups';
  }
  const clean = String(rawClaim).trim();
  if (clean.length > 128 || /[\r\n\0]/.test(clean)) {
    throw oidcError('groupsClaim inválido', 400, 'INVALID_GROUPS_CLAIM');
  }
  const segments = clean.split('.');
  if (segments.length > 4 || segments.some((s) => !s || FORBIDDEN_CLAIM_SEGMENTS.has(s))) {
    throw oidcError('groupsClaim contiene segmentos reservados o demasiada profundidad', 400, 'INVALID_GROUPS_CLAIM');
  }
  return clean;
}

/**
 * Valida y sanea el mapa `groupRoleMap` (`{ "<idpGroup>": "viewer"|"developer"|"admin" }`).
 * Nunca permite mapear a `owner` (invariante de seguridad SSO).
 * @param {any} rawMap
 * @returns {Record<string, 'viewer' | 'developer' | 'admin'>}
 */
function sanitizeGroupRoleMap(rawMap) {
  if (rawMap === undefined || rawMap === null) return {};
  if (typeof rawMap !== 'object' || Array.isArray(rawMap)) {
    throw oidcError('groupRoleMap debe ser un objeto clave-valor { grupo: rol }', 400, 'INVALID_GROUP_ROLE_MAP');
  }
  const entries = Object.entries(rawMap);
  if (entries.length > MAX_GROUP_ROLE_ENTRIES) {
    throw oidcError(`groupRoleMap admite un máximo de ${MAX_GROUP_ROLE_ENTRIES} entradas`, 400, 'INVALID_GROUP_ROLE_MAP');
  }
  /** @type {Record<string, 'viewer' | 'developer' | 'admin'>} */
  const out = {};
  for (const [rawGroup, rawRole] of entries) {
    const group = String(rawGroup || '').trim();
    if (!group || group.length > 128 || /[\x00-\x1f\x7f]/.test(group) || FORBIDDEN_CLAIM_SEGMENTS.has(group)) {
      throw oidcError(`Nombre de grupo OIDC inválido en groupRoleMap: "${group.slice(0, 40)}"`, 400, 'INVALID_GROUP_ROLE_MAP');
    }
    const role = String(rawRole || '').trim().toLowerCase();
    if (role === 'owner') {
      throw oidcError('groupRoleMap jamás puede asignar rol owner vía SSO', 403, 'OWNER_PROVISION_FORBIDDEN');
    }
    if (!ALLOWED_DEFAULT_ROLES.includes(role)) {
      throw oidcError(`Rol inválido en groupRoleMap para "${group}": ${role}`, 400, 'INVALID_ROLE');
    }
    out[group] = /** @type {'viewer' | 'developer' | 'admin'} */ (role);
  }
  return out;
}

/**
 * Extrae una lista normalizada de grupos desde los claims JWT/UserInfo respetando rutas punteadas seguras.
 * @param {Record<string, any> | null | undefined} claims
 * @param {string} [claimPath]
 * @returns {string[]}
 */
function extractGroupsFromClaims(claims, claimPath = 'groups') {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return [];
  const pathStr = String(claimPath || 'groups').trim() || 'groups';
  /** @type {any} */
  let rawVal;
  if (Object.prototype.hasOwnProperty.call(claims, pathStr)) {
    rawVal = claims[pathStr];
  } else {
    const segs = pathStr.split('.');
    if (segs.length > 4 || segs.some((s) => !s || FORBIDDEN_CLAIM_SEGMENTS.has(s))) return [];
    let cur = /** @type {any} */ (claims);
    for (const seg of segs) {
      if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, seg)) {
        cur = cur[seg];
      } else {
        cur = undefined;
        break;
      }
    }
    rawVal = cur;
  }
  if (typeof rawVal === 'string') {
    const t = rawVal.trim();
    return t ? [t] : [];
  }
  if (!Array.isArray(rawVal)) return [];
  /** @type {string[]} */
  const groups = [];
  for (const item of rawVal.slice(0, 200)) {
    if (typeof item === 'string') {
      const t = item.trim();
      if (t) groups.push(t);
    }
  }
  return Array.from(new Set(groups));
}

/**
 * Resuelve el rol RBAC efectivo desde los claims OIDC del proveedor usando `groupRoleMap`.
 * Política:
 *  - Resolución estricta al mayor privilegio entre los grupos mapeados (`admin > developer > viewer`).
 *  - Jamás escala a `owner` ni fuera de los roles declarados en `groupRoleMap` / `defaultRole`.
 *  - Si ningún grupo coincide (o `groupRoleMap` está vacío), aplica `defaultRole` acotado a `ALLOWED_DEFAULT_ROLES`.
 *
 * @param {any} provider
 * @param {Record<string, any> | null | undefined} claims
 * @returns {{ role: 'viewer' | 'developer' | 'admin', matchedGroups: string[], groups: string[], source: 'group_map' | 'default_role' }}
 */
function resolveRoleFromClaims(provider, claims) {
  const rawDefault = String((provider && provider.defaultRole) || 'viewer').trim().toLowerCase();
  const safeDefault = /** @type {'viewer' | 'developer' | 'admin'} */ (
    ALLOWED_DEFAULT_ROLES.includes(rawDefault) ? rawDefault : 'viewer'
  );
  const claimPath = String((provider && provider.groupsClaim) || 'groups').trim() || 'groups';
  const map = (provider && provider.groupRoleMap && typeof provider.groupRoleMap === 'object' && !Array.isArray(provider.groupRoleMap))
    ? provider.groupRoleMap
    : {};
  const groups = extractGroupsFromClaims(claims, claimPath);

  /** @type {'viewer' | 'developer' | 'admin' | null} */
  let bestRole = null;
  let bestRank = 0;
  /** @type {string[]} */
  const matchedGroups = [];

  for (const group of groups) {
    if (!Object.prototype.hasOwnProperty.call(map, group)) continue;
    const candidate = String(map[group] || '').trim().toLowerCase();
    // Defensa en profundidad: aunque el disco fuera manipulado con "owner", se ignora siempre
    if (!ALLOWED_DEFAULT_ROLES.includes(candidate)) continue;
    matchedGroups.push(group);
    const rank = OIDC_ROLE_RANK[candidate] || 0;
    if (rank > bestRank) {
      bestRank = rank;
      bestRole = /** @type {'viewer' | 'developer' | 'admin'} */ (candidate);
    }
  }

  if (bestRole) {
    return { role: bestRole, matchedGroups, groups, source: 'group_map' };
  }
  return { role: safeDefault, matchedGroups: [], groups, source: 'default_role' };
}

/**
 * Algoritmos JWS asimétricos permitidos (NUNCA `none` ni `HS256`/`HS384`/`HS512`).
 * @type {Record<string, { kty: string, hash: string | null, pss?: boolean, ecdsa?: boolean }>}
 */
const ALLOWED_JWS_ALGS = Object.freeze({
  RS256: { kty: 'RSA', hash: 'sha256' },
  RS384: { kty: 'RSA', hash: 'sha384' },
  RS512: { kty: 'RSA', hash: 'sha512' },
  PS256: { kty: 'RSA', hash: 'sha256', pss: true },
  PS384: { kty: 'RSA', hash: 'sha384', pss: true },
  PS512: { kty: 'RSA', hash: 'sha512', pss: true },
  ES256: { kty: 'EC', hash: 'sha256', ecdsa: true },
  ES384: { kty: 'EC', hash: 'sha384', ecdsa: true },
  ES512: { kty: 'EC', hash: 'sha512', ecdsa: true },
  EdDSA: { kty: 'OKP', hash: null }
});

/** Preajustes listos para usar (GitHub, Google, Authentik, Keycloak, OIDC genérico). */
const PROVIDER_PRESETS = Object.freeze({
  github: Object.freeze({
    type: 'github',
    protocol: 'oauth2',
    name: 'GitHub',
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userinfoEndpoint: 'https://api.github.com/user',
    emailsEndpoint: 'https://api.github.com/user/emails',
    scopes: ['read:user', 'user:email']
  }),
  google: Object.freeze({
    type: 'google',
    protocol: 'oidc',
    name: 'Google',
    issuerUrl: 'https://accounts.google.com',
    scopes: ['openid', 'email', 'profile']
  }),
  authentik: Object.freeze({
    type: 'authentik',
    protocol: 'oidc',
    name: 'Authentik',
    scopes: ['openid', 'email', 'profile']
  }),
  keycloak: Object.freeze({
    type: 'keycloak',
    protocol: 'oidc',
    name: 'Keycloak',
    scopes: ['openid', 'email', 'profile']
  }),
  oidc: Object.freeze({
    type: 'oidc',
    protocol: 'oidc',
    name: 'OpenID Connect',
    scopes: ['openid', 'email', 'profile']
  })
});

/** @param {string} message @param {number} [status] @param {string} [code] */
function oidcError(message, status = 400, code = 'OIDC_ERROR') {
  /** @type {Error & { status?: number, code?: string }} */
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

/** @param {string} a @param {string} b */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHmac('sha256', COMPARE_HMAC_KEY).update(a, 'utf8').digest();
  const hb = crypto.createHmac('sha256', COMPARE_HMAC_KEY).update(b, 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Genera un par PKCE S256 conforme a RFC 7636. */
function generatePkcePair() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  return { codeVerifier, codeChallenge, method: 'S256' };
}

/** @param {string} urlStr */
function stripTrailingSlash(urlStr) {
  return String(urlStr || '').trim().replace(/\/+$/, '');
}

/**
 * Verifica criptográficamente un OIDC `id_token` JWT contra un conjunto JWKS usando
 * exclusivamente Node `crypto` (0 dependencias externas).
 *
 * Protecciones:
 *  - Rechaza `alg: "none"`, `HS256`/`HS384`/`HS512` y cualquier algoritmo fuera de `ALLOWED_JWS_ALGS`.
 *  - Verifica coincidencia estricta entre `jwk.kty` y `header.alg`.
 *  - Verifica firma RSA/PSS/ECDSA (`ieee-p1363` RFC 7515)/EdDSA mediante `crypto.verify`.
 *  - Valida `iss`, `aud` (+ `azp` si múltiples audiencias), `exp`, `nbf`, `iat` y `nonce`.
 *
 * @param {string} idToken
 * @param {{
 *   jwks: { keys: any[] },
 *   expectedIssuer: string,
 *   expectedAudience: string,
 *   expectedNonce?: string | null,
 *   nowSec?: number,
 *   clockSkewSec?: number
 * }} opts
 * @returns {{ header: Record<string, any>, claims: Record<string, any> }}
 */
function verifyIdToken(idToken, opts) {
  if (typeof idToken !== 'string' || !idToken || idToken.length > 16384) {
    throw oidcError('id_token JWT inválido o vacío', 401, 'OIDC_INVALID_ID_TOKEN');
  }
  const parts = idToken.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw oidcError('Formato de id_token JWT malformado', 401, 'OIDC_INVALID_ID_TOKEN');
  }
  const [rawHeader, rawPayload, rawSig] = parts;

  /** @type {any} */
  let header;
  /** @type {any} */
  let claims;
  try {
    header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(rawPayload, 'base64url').toString('utf8'));
  } catch (e) {
    throw oidcError('No se pudo decodificar el id_token JWT', 401, 'OIDC_INVALID_ID_TOKEN');
  }

  if (!header || typeof header !== 'object' || !claims || typeof claims !== 'object') {
    throw oidcError('Cabecera o payload JWT inválido', 401, 'OIDC_INVALID_ID_TOKEN');
  }

  const alg = String(header.alg || '');
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_JWS_ALGS, alg)) {
    throw oidcError(`Algoritmo JWT no permitido o inseguro: ${alg || 'none'}`, 401, 'OIDC_UNSUPPORTED_ALG');
  }
  const algSpec = ALLOWED_JWS_ALGS[alg];

  const keys = opts && opts.jwks && Array.isArray(opts.jwks.keys) ? opts.jwks.keys : [];
  if (keys.length === 0) {
    throw oidcError('El conjunto JWKS del proveedor está vacío', 401, 'OIDC_EMPTY_JWKS');
  }

  // Seleccionar clave candidata por kid (o única clave compatible si kid ausente)
  const kid = header.kid ? String(header.kid) : null;
  /** @type {any} */
  let jwk = null;
  if (kid) {
    jwk = keys.find((k) => k && k.kid === kid && (!k.use || k.use === 'sig')) || null;
  } else {
    const compat = keys.filter((k) => k && k.kty === algSpec.kty && (!k.use || k.use === 'sig'));
    if (compat.length === 1) jwk = compat[0];
  }
  if (!jwk) {
    throw oidcError(`Clave pública JWKS no encontrada para kid=${kid || '(none)'}`, 401, 'OIDC_UNKNOWN_KID');
  }
  if (jwk.kty !== algSpec.kty) {
    throw oidcError(`Incompatibilidad de tipo de clave JWK (${jwk.kty}) para algoritmo ${alg}`, 401, 'OIDC_KEY_ALG_MISMATCH');
  }
  if (jwk.alg && jwk.alg !== alg) {
    throw oidcError(`La clave JWK restringe alg=${jwk.alg} pero el token usa ${alg}`, 401, 'OIDC_KEY_ALG_MISMATCH');
  }

  // Importar JWK públicamente con Node crypto nativo y verificar firma
  let pubKey;
  try {
    // Filtrar solo propiedades públicas estándar para evitar objetos maliciosos
    const safeJwk = { ...jwk };
    delete safeJwk.d;
    delete safeJwk.p;
    delete safeJwk.q;
    delete safeJwk.dp;
    delete safeJwk.dq;
    delete safeJwk.qi;
    pubKey = crypto.createPublicKey({ key: safeJwk, format: 'jwk' });
  } catch (e) {
    throw oidcError(`Clave pública JWK inválida: ${e.message}`, 401, 'OIDC_INVALID_JWK');
  }

  const signingInput = Buffer.from(`${rawHeader}.${rawPayload}`, 'ascii');
  const sigBuf = Buffer.from(rawSig, 'base64url');
  /** @type {any} */
  const verifyKey = algSpec.pss
    ? { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
    : algSpec.ecdsa
      ? { key: pubKey, dsaEncoding: 'ieee-p1363' }
      : pubKey;

  let sigOk = false;
  try {
    sigOk = crypto.verify(algSpec.hash, signingInput, verifyKey, sigBuf);
  } catch (e) {
    sigOk = false;
  }
  if (!sigOk) {
    throw oidcError('Firma criptográfica del id_token inválida', 401, 'OIDC_INVALID_SIGNATURE');
  }

  // Validación estricta de claims OIDC (iss, aud, azp, exp, nbf, iat, nonce)
  const nowSec = typeof opts.nowSec === 'number' && Number.isFinite(opts.nowSec)
    ? opts.nowSec
    : Math.floor(Date.now() / 1000);
  const skew = Math.max(0, Math.min(300, Number(opts.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC)));

  const expectedIss = stripTrailingSlash(opts.expectedIssuer);
  const actualIss = stripTrailingSlash(claims.iss);
  if (!expectedIss || !actualIss || actualIss !== expectedIss) {
    throw oidcError('Emisor (iss) del id_token no coincide', 401, 'OIDC_ISSUER_MISMATCH');
  }

  const expectedAud = String(opts.expectedAudience || '');
  const audList = Array.isArray(claims.aud) ? claims.aud.map(String) : (claims.aud ? [String(claims.aud)] : []);
  if (!expectedAud || !audList.includes(expectedAud)) {
    throw oidcError('Audiencia (aud) del id_token no coincide con clientId', 401, 'OIDC_AUDIENCE_MISMATCH');
  }
  if (audList.length > 1 && String(claims.azp || '') !== expectedAud) {
    throw oidcError('Authorized party (azp) requerido cuando aud tiene múltiples valores', 401, 'OIDC_AZP_MISMATCH');
  }

  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || nowSec >= claims.exp + skew) {
    throw oidcError('El id_token ha caducado (exp)', 401, 'OIDC_TOKEN_EXPIRED');
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || nowSec + skew < claims.nbf)) {
    throw oidcError('El id_token aún no es válido (nbf)', 401, 'OIDC_TOKEN_NOT_YET_VALID');
  }
  if (claims.iat !== undefined && (typeof claims.iat !== 'number' || claims.iat > nowSec + skew)) {
    throw oidcError('Marca de emisión (iat) del id_token en el futuro', 401, 'OIDC_INVALID_IAT');
  }

  if (opts.expectedNonce) {
    if (typeof claims.nonce !== 'string' || !safeEqual(claims.nonce, String(opts.expectedNonce))) {
      throw oidcError('Nonce del id_token no coincide (posible replay)', 401, 'OIDC_NONCE_MISMATCH');
    }
  }

  if (!claims.sub || typeof claims.sub !== 'string') {
    throw oidcError('El id_token carece de subject (sub)', 401, 'OIDC_MISSING_SUB');
  }

  return { header, claims };
}

function resolveDefaultDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.join(__dirname, '..', '..', 'data');
}

class OidcService extends EventEmitter {
  /**
   * @param {{ dataDir?: string, dataFile?: string, keyFile?: string, fetchImpl?: Function }} [options]
   */
  constructor(options = {}) {
    super();
    this._explicitDataDir = options.dataDir ? path.resolve(options.dataDir) : null;
    this._explicitDataFile = options.dataFile ? path.resolve(options.dataFile) : null;
    this._explicitKeyFile = options.keyFile ? path.resolve(options.keyFile) : null;
    this._fetchImpl = typeof options.fetchImpl === 'function' ? options.fetchImpl : null;

    /** @type {{ version: number, providers: Record<string, any>, settings?: { disablePasswordLogin?: boolean } } | null} */
    this._state = null;
    /** @type {Buffer | null} */
    this._encKey = null;
    /** @type {Map<string, any>} */
    this._pendingFlows = new Map();
    /** @type {Map<string, { at: number, doc: any }>} */
    this._discoveryCache = new Map();
    /** @type {Map<string, { at: number, jwks: any }>} */
    this._jwksCache = new Map();
    /** Alias público para diagnóstico y stale-while-revalidate fallback (arcane#3855, Cosmos#625). */
    this.jwksCache = this._jwksCache;
    this._jwksStaleFallbackCount = 0;
  }

  _getPaths() {
    const dataDir = this._explicitDataDir || resolveDefaultDataDir();
    return {
      dataDir,
      dataFile: this._explicitDataFile || path.join(dataDir, DATA_FILE_NAME),
      keyFile: this._explicitKeyFile || path.join(dataDir, KEY_FILE_NAME)
    };
  }

  _ensureLoaded(forWrite = false) {
    if (this._state) return this._state;
    const { dataFile } = this._getPaths();
    const loaded = loadJsonWithBackupSync(dataFile, {
      validate: (p) => Boolean(p && typeof p === 'object' && p.providers && typeof p.providers === 'object')
    });
    if (loaded.corrupt) {
      throw oidcError(`Configuración OIDC corrupta en ${dataFile}`, 500, 'OIDC_STORE_CORRUPT');
    }
    if (loaded.ok && loaded.data) {
      this._state = loaded.data;
      return this._state;
    }
    if (!forWrite) return null;
    this._state = { version: 1, providers: {}, settings: { disablePasswordLogin: false } };
    return this._state;
  }

  _ensureEncKey() {
    if (this._encKey) return this._encKey;
    const { keyFile, dataFile } = this._getPaths();
    if (fs.existsSync(keyFile)) {
      const raw = fs.readFileSync(keyFile, 'utf8').trim();
      const buf = Buffer.from(raw, 'hex');
      if (buf.length !== 32 || buf.toString('hex') !== raw.toLowerCase()) {
        throw oidcError(`Clave de cifrado OIDC corrupta en ${keyFile}`, 500, 'OIDC_KEY_CORRUPT');
      }
      this._encKey = buf;
      return buf;
    }
    if (this._state && Object.keys(this._state.providers || {}).length > 0 && fs.existsSync(dataFile)) {
      throw oidcError(`Falta ${keyFile} mientras existen proveedores OIDC configurados`, 500, 'OIDC_KEY_MISSING');
    }
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    const fresh = crypto.randomBytes(32);
    try {
      fs.writeFileSync(keyFile, fresh.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      try { fs.chmodSync(keyFile, 0o600); } catch (e) {}
      this._encKey = fresh;
      return fresh;
    } catch (err) {
      if (err && /** @type {any} */ (err).code === 'EEXIST') {
        const raced = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
        if (raced.length === 32) {
          this._encKey = raced;
          return raced;
        }
      }
      throw err;
    }
  }

  /** @param {string} providerId @param {string} plaintext */
  _encryptSecret(providerId, plaintext) {
    const key = this._ensureEncKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(`oidc:${providerId}`, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
  }

  /** @param {string} providerId @param {string} encStr */
  _decryptSecret(providerId, encStr) {
    if (!encStr) return '';
    if (!String(encStr).startsWith('v1:')) {
      throw oidcError('clientSecret cifrado corrupto', 500, 'OIDC_SECRET_CORRUPT');
    }
    const parts = String(encStr).split(':');
    if (parts.length !== 4) throw oidcError('clientSecret cifrado corrupto', 500, 'OIDC_SECRET_CORRUPT');
    const key = this._ensureEncKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[1], 'base64'));
    decipher.setAAD(Buffer.from(`oidc:${providerId}`, 'utf8'));
    decipher.setAuthTag(Buffer.from(parts[2], 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
  }

  _save() {
    if (!this._state) return;
    const { dataFile } = this._getPaths();
    atomicWriteJsonSync(dataFile, this._state, { mode: 0o600, pretty: true, backup: true });
  }

  /** @param {any} p */
  sanitizeProvider(p) {
    if (!p) return null;
    return {
      id: p.id,
      type: p.type,
      protocol: p.protocol,
      name: p.name,
      enabled: Boolean(p.enabled),
      issuerUrl: p.issuerUrl || null,
      clientId: p.clientId,
      hasClientSecret: Boolean(p.clientSecretEnc),
      redirectUri: p.redirectUri,
      scopes: Array.isArray(p.scopes) ? [...p.scopes] : [],
      autoProvision: Boolean(p.autoProvision),
      defaultRole: p.defaultRole || 'viewer',
      groupsClaim: p.groupsClaim || 'groups',
      groupRoleMap: (p.groupRoleMap && typeof p.groupRoleMap === 'object' && !Array.isArray(p.groupRoleMap)) ? { ...p.groupRoleMap } : {},
      teamId: p.teamId || 'team_default',
      allowedDomains: Array.isArray(p.allowedDomains) ? [...p.allowedDomains] : [],
      enforceLocal2fa: Boolean(p.enforceLocal2fa),
      allowInsecureLocal: Boolean(p.allowInsecureLocal),
      createdAt: p.createdAt,
      updatedAt: p.updatedAt
    };
  }

  /**
   * Devuelve si el inicio de sesión con contraseña está deshabilitado por política SSO.
   * Por seguridad anti-lockout, solo se considera activo cuando existe al menos un proveedor SSO habilitado.
   */
  isPasswordLoginDisabled() {
    const state = this._ensureLoaded(false);
    if (!state || !state.settings || !state.settings.disablePasswordLogin) return false;
    const hasEnabled = Object.values(state.providers || {}).some((p) => p && p.enabled);
    return hasEnabled;
  }

  /** Devuelve configuración global de seguridad SSO (`disablePasswordLogin`). */
  getSecuritySettings() {
    const state = this._ensureLoaded(false);
    const hasEnabledProvider = Boolean(state && Object.values(state.providers || {}).some((p) => p && p.enabled));
    return {
      disablePasswordLogin: Boolean(state && state.settings && state.settings.disablePasswordLogin),
      effectivePasswordLoginDisabled: Boolean(state && state.settings && state.settings.disablePasswordLogin && hasEnabledProvider),
      hasEnabledProvider
    };
  }

  /**
   * Actualiza la política global SSO (`disablePasswordLogin`).
   * Impide bloquear el login con contraseña si no hay al menos un proveedor SSO activo.
   * @param {{ disablePasswordLogin?: boolean }} input
   */
  setSecuritySettings(input = {}) {
    const state = this._ensureLoaded(true);
    if (!state) throw oidcError('Almacenamiento OIDC no disponible', 500, 'OIDC_STORE_ERROR');
    if (!state.settings || typeof state.settings !== 'object') {
      state.settings = { disablePasswordLogin: false };
    }
    if (input && input.disablePasswordLogin !== undefined) {
      const wantDisable = Boolean(input.disablePasswordLogin);
      if (wantDisable) {
        const hasEnabled = Object.values(state.providers || {}).some((p) => p && p.enabled);
        if (!hasEnabled) {
          throw oidcError(
            'No puedes deshabilitar el login con contraseña sin tener al menos un proveedor SSO/OIDC habilitado',
            400,
            'OIDC_LOCKOUT_PREVENTED'
          );
        }
      }
      state.settings.disablePasswordLogin = wantDisable;
    }
    this._save();
    return this.getSecuritySettings();
  }

  /**
   * Resuelve el rol efectivo RBAC desde los claims OIDC de un proveedor.
   * @param {any} provider
   * @param {Record<string, any> | null | undefined} claims
   */
  resolveRoleFromClaims(provider, claims) {
    return resolveRoleFromClaims(provider, claims);
  }

  /** Lista pública (sin secretos ni `clientId`) para pintar los botones SSO en la pantalla de login. */
  listPublicProviders() {
    const state = this._ensureLoaded(false);
    if (!state) return [];
    return Object.values(state.providers)
      .filter((p) => p && p.enabled)
      .map((p) => ({ id: p.id, type: p.type, name: p.name }));
  }

  /** Lista administrativa (sanitizada, jamás devuelve `clientSecret`). */
  listProviders() {
    const state = this._ensureLoaded(false);
    if (!state) return [];
    return Object.values(state.providers).map((p) => this.sanitizeProvider(p));
  }

  /**
   * Crea o actualiza un proveedor OIDC/OAuth2 PKCE (GitHub, Google, Authentik, Keycloak, genérico).
   * @param {{
   *   id: string,
   *   type?: 'github' | 'google' | 'authentik' | 'keycloak' | 'oidc',
   *   name?: string,
   *   enabled?: boolean,
   *   issuerUrl?: string,
   *   authorizationEndpoint?: string,
   *   tokenEndpoint?: string,
   *   jwksUri?: string,
   *   userinfoEndpoint?: string,
   *   emailsEndpoint?: string,
   *   clientId: string,
   *   clientSecret?: string,
   *   redirectUri: string,
   *   scopes?: string[],
   *   autoProvision?: boolean,
   *   defaultRole?: string,
   *   groupsClaim?: string,
   *   groupRoleMap?: Record<string, string>,
   *   disablePasswordLogin?: boolean,
   *   teamId?: string,
   *   allowedDomains?: string[],
   *   enforceLocal2fa?: boolean,
   *   allowInsecureLocal?: boolean
   * }} input
   */
  configureProvider(input) {
    if (!input || typeof input !== 'object') {
      throw oidcError('Configuración de proveedor OIDC inválida', 400, 'INVALID_OIDC_CONFIG');
    }
    const id = String(input.id || '').trim().toLowerCase();
    if (!PROVIDER_ID_RE.test(id)) {
      throw oidcError('id de proveedor OIDC inválido (usa minúsculas, números, guiones)', 400, 'INVALID_PROVIDER_ID');
    }
    const type = String(input.type || (Object.prototype.hasOwnProperty.call(PROVIDER_PRESETS, id) ? id : 'oidc')).trim().toLowerCase();
    const preset = PROVIDER_PRESETS[type] || PROVIDER_PRESETS.oidc;

    const clientId = String(input.clientId || '').trim();
    if (!clientId || clientId.length > 256) {
      throw oidcError('clientId es obligatorio', 400, 'INVALID_CLIENT_ID');
    }

    const redirectUri = String(input.redirectUri || '').trim();
    let parsedRedirect;
    try {
      parsedRedirect = new URL(redirectUri);
    } catch (e) {
      throw oidcError('redirectUri malformada', 400, 'INVALID_REDIRECT_URI');
    }
    if (parsedRedirect.protocol !== 'https:' && parsedRedirect.protocol !== 'http:') {
      throw oidcError('redirectUri debe usar https:// o http://', 400, 'INVALID_REDIRECT_URI');
    }

    const allowInsecureLocal = Boolean(input.allowInsecureLocal);
    const issuerUrl = stripTrailingSlash(input.issuerUrl || preset.issuerUrl || '');
    if (preset.protocol === 'oidc') {
      if (!issuerUrl) {
        throw oidcError('issuerUrl es obligatorio para proveedores OIDC', 400, 'INVALID_ISSUER_URL');
      }
      let parsedIss;
      try {
        parsedIss = new URL(issuerUrl);
      } catch (e) {
        throw oidcError('issuerUrl malformada', 400, 'INVALID_ISSUER_URL');
      }
      if (parsedIss.protocol !== 'https:' && !(allowInsecureLocal && parsedIss.protocol === 'http:')) {
        throw oidcError('issuerUrl debe usar HTTPS', 400, 'INSECURE_ISSUER_URL');
      }
    }

    const defaultRole = String(input.defaultRole || 'viewer').trim().toLowerCase();
    if (defaultRole === 'owner') {
      throw oidcError('Un proveedor SSO jamás puede auto-aprovisionar con rol owner', 403, 'OWNER_PROVISION_FORBIDDEN');
    }
    if (!ALLOWED_DEFAULT_ROLES.includes(defaultRole)) {
      throw oidcError(`defaultRole inválido: ${defaultRole}`, 400, 'INVALID_ROLE');
    }

    const groupsClaim = sanitizeGroupsClaim(input.groupsClaim);
    const groupRoleMap = sanitizeGroupRoleMap(input.groupRoleMap);

    const allowedDomains = Array.isArray(input.allowedDomains)
      ? Array.from(new Set(input.allowedDomains.map((d) => String(d || '').trim().toLowerCase().replace(/^@/, '')).filter(Boolean)))
      : [];

    const state = this._ensureLoaded(true);
    if (!state) throw oidcError('Almacenamiento OIDC no disponible', 500, 'OIDC_STORE_ERROR');
    if (!state.settings || typeof state.settings !== 'object') {
      state.settings = { disablePasswordLogin: false };
    }
    const existing = state.providers[id] || null;
    const nowIso = new Date().toISOString();

    let clientSecretEnc = existing ? existing.clientSecretEnc : null;
    if (typeof input.clientSecret === 'string' && input.clientSecret.trim()) {
      clientSecretEnc = this._encryptSecret(id, input.clientSecret.trim());
    }

    const scopes = Array.isArray(input.scopes) && input.scopes.length > 0
      ? input.scopes.map((s) => String(s || '').trim()).filter(Boolean)
      : [...preset.scopes];

    const record = {
      id,
      type: preset.type,
      protocol: preset.protocol,
      name: String(input.name || preset.name || id).trim().slice(0, 64),
      enabled: input.enabled !== undefined ? Boolean(input.enabled) : true,
      issuerUrl: issuerUrl || null,
      authorizationEndpoint: input.authorizationEndpoint || preset.authorizationEndpoint || null,
      tokenEndpoint: input.tokenEndpoint || preset.tokenEndpoint || null,
      jwksUri: input.jwksUri || null,
      userinfoEndpoint: input.userinfoEndpoint || preset.userinfoEndpoint || null,
      emailsEndpoint: input.emailsEndpoint || preset.emailsEndpoint || null,
      clientId,
      clientSecretEnc,
      redirectUri,
      scopes,
      autoProvision: Boolean(input.autoProvision),
      defaultRole,
      groupsClaim,
      groupRoleMap,
      teamId: String(input.teamId || 'team_default').trim() || 'team_default',
      allowedDomains,
      enforceLocal2fa: Boolean(input.enforceLocal2fa),
      allowInsecureLocal,
      createdAt: existing ? existing.createdAt : nowIso,
      updatedAt: nowIso
    };

    state.providers[id] = record;
    if (input.disablePasswordLogin !== undefined) {
      const wantDisable = Boolean(input.disablePasswordLogin);
      if (wantDisable && !Object.values(state.providers).some((p) => p && p.enabled)) {
        throw oidcError(
          'No puedes deshabilitar el login con contraseña sin tener al menos un proveedor SSO/OIDC habilitado',
          400,
          'OIDC_LOCKOUT_PREVENTED'
        );
      }
      state.settings.disablePasswordLogin = wantDisable;
    }
    this._discoveryCache.delete(id);
    this._jwksCache.delete(id);
    this._save();
    return this.sanitizeProvider(record);
  }

  /** @param {string} id */
  deleteProvider(id) {
    const state = this._ensureLoaded(false);
    if (!state || !state.providers[id]) return { deleted: false };
    delete state.providers[id];
    this._discoveryCache.delete(id);
    this._jwksCache.delete(id);
    this._save();
    return { deleted: true, id };
  }

  /** Ejecuta HTTP seguro vía `ssrfGuard.safeFetch` (o `fetchImpl` inyectado en pruebas). */
  async _httpFetch(url, provider, opts = {}) {
    const fn = opts.fetchImpl || this._fetchImpl;
    if (typeof fn === 'function') {
      return await fn(url, opts);
    }
    return await safeFetch(url, {
      method: opts.method || 'GET',
      headers: opts.headers || {},
      body: opts.body || null,
      timeoutMs: opts.timeoutMs || 8000,
      maxRedirects: 2,
      maxBytes: 1024 * 1024,
      requireHttps: !provider.allowInsecureLocal,
      allowLoopback: Boolean(provider.allowInsecureLocal),
      allowPrivate: false
    });
  }

  /**
   * Obtiene (y cachea 15 min) el documento `.well-known/openid-configuration` del proveedor.
   * @param {any} provider
   * @param {Function | null} [fetchImpl]
   */
  async _getDiscovery(provider, fetchImpl = null) {
    if (provider.protocol !== 'oidc') {
      return {
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        userinfo_endpoint: provider.userinfoEndpoint
      };
    }
    if (provider.authorizationEndpoint && provider.tokenEndpoint && provider.jwksUri) {
      return {
        issuer: provider.issuerUrl,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        jwks_uri: provider.jwksUri,
        userinfo_endpoint: provider.userinfoEndpoint || null
      };
    }
    const cached = this._discoveryCache.get(provider.id);
    if (cached && (Date.now() - cached.at) < DISCOVERY_CACHE_TTL_MS) {
      return cached.doc;
    }
    const discUrl = `${stripTrailingSlash(provider.issuerUrl)}/.well-known/openid-configuration`;
    const res = await this._httpFetch(discUrl, provider, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      fetchImpl
    });
    if (!res || !res.ok) {
      throw oidcError(`Error al consultar OIDC Discovery en ${discUrl} (HTTP ${res?.status || 0})`, 502, 'OIDC_DISCOVERY_FAILED');
    }
    const doc = typeof res.json === 'function' ? await res.json() : res.body;
    if (!doc || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
      throw oidcError('Documento OIDC Discovery incompleto (faltan endpoints o jwks_uri)', 502, 'OIDC_DISCOVERY_INVALID');
    }
    this._discoveryCache.set(provider.id, { at: Date.now(), doc });
    return doc;
  }

  /**
   * Obtiene (y cachea 15 min) las claves públicas JWKS del proveedor con timeout acotado de 5 s
   * y fallback stale-while-revalidate sobre `jwksCache` (hasta 24 h) si el IdP tarda o cae
   * temporalmente (cura arcane#3855/#1485/#3620 y Cosmos#625).
   * @param {any} provider
   * @param {string} jwksUri
   * @param {{ forceRefresh?: boolean, fetchImpl?: Function | null, timeoutMs?: number, allowStaleFallback?: boolean }} [opts]
   */
  async _getJwks(provider, jwksUri, { forceRefresh = false, fetchImpl = null, timeoutMs = JWKS_FETCH_TIMEOUT_MS, allowStaleFallback = true } = {}) {
    const cached = this._jwksCache.get(provider.id);
    const now = Date.now();
    if (!forceRefresh && cached && (now - cached.at) < JWKS_CACHE_TTL_MS) {
      return cached.jwks;
    }
    const effectiveTimeoutMs = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
      ? Math.min(Math.max(50, Number(timeoutMs)), 30000)
      : JWKS_FETCH_TIMEOUT_MS;

    /** @type {any} */
    let timer = null;
    try {
      const fetchPromise = this._httpFetch(jwksUri, provider, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        timeoutMs: effectiveTimeoutMs,
        fetchImpl
      });
      const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(oidcError(`Timeout (${effectiveTimeoutMs}ms) descargando JWKS desde ${jwksUri}`, 502, 'OIDC_JWKS_TIMEOUT'));
        }, effectiveTimeoutMs);
      });
      const res = await Promise.race([fetchPromise, timeoutPromise]);
      if (!res || !res.ok) {
        throw oidcError(`Error al descargar JWKS desde ${jwksUri} (HTTP ${res?.status || 0})`, 502, 'OIDC_JWKS_FAILED');
      }
      const jwks = typeof res.json === 'function' ? await res.json() : res.body;
      if (!jwks || !Array.isArray(jwks.keys)) {
        throw oidcError('Respuesta JWKS inválida', 502, 'OIDC_JWKS_INVALID');
      }
      this._jwksCache.set(provider.id, { at: Date.now(), jwks });
      return jwks;
    } catch (err) {
      if (allowStaleFallback !== false && cached && cached.jwks && (Date.now() - cached.at) < JWKS_STALE_MAX_AGE_MS) {
        this._jwksStaleFallbackCount++;
        /** @type {any} */
        const e = err;
        this.emit('jwks_stale_fallback', {
          providerId: provider.id,
          jwksUri,
          ageMs: Date.now() - cached.at,
          reason: (e && e.code) || (e && e.message) || 'OIDC_JWKS_FAILED'
        });
        return cached.jwks;
      }
      throw err;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Genera la URL de autorización OAuth2/OIDC con PKCE S256, `state` y `nonce` single-use.
   * @param {string} providerId
   * @param {{ redirectUri?: string, teamId?: string, ip?: string, fetchImpl?: Function }} [opts]
   */
  async createAuthorizationUrl(providerId, opts = {}) {
    const state = this._ensureLoaded(false);
    const provider = state ? state.providers[String(providerId || '').toLowerCase()] : null;
    if (!provider || !provider.enabled) {
      throw oidcError('Proveedor SSO no encontrado o deshabilitado', 404, 'OIDC_PROVIDER_NOT_FOUND');
    }

    const discovery = await this._getDiscovery(provider, opts.fetchImpl || null);
    const pkce = generatePkcePair();
    const stateToken = crypto.randomBytes(24).toString('base64url');
    const nonce = crypto.randomBytes(24).toString('base64url');
    const now = Date.now();
    const expiresAtMs = now + PENDING_STATE_TTL_MS;

    // Barrido de flujos caducados + cota LRU (evita crecimiento sin límite en memoria)
    if (this._pendingFlows.size >= PENDING_STATE_CAP) {
      for (const [k, v] of this._pendingFlows.entries()) {
        if (v.expiresAt <= now) this._pendingFlows.delete(k);
        if (this._pendingFlows.size < PENDING_STATE_CAP) break;
      }
      if (this._pendingFlows.size >= PENDING_STATE_CAP) {
        const oldest = this._pendingFlows.keys().next().value;
        if (oldest) this._pendingFlows.delete(oldest);
      }
    }

    const redirectUri = opts.redirectUri || provider.redirectUri;
    this._pendingFlows.set(stateToken, {
      providerId: provider.id,
      codeVerifier: pkce.codeVerifier,
      nonce,
      redirectUri,
      teamId: opts.teamId || provider.teamId || 'team_default',
      ip: opts.ip ? String(opts.ip).slice(0, 64) : null,
      createdAt: now,
      expiresAt: expiresAtMs
    });

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', provider.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', (provider.scopes || ['openid', 'email', 'profile']).join(' '));
    authUrl.searchParams.set('state', stateToken);
    authUrl.searchParams.set('code_challenge', pkce.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    if (provider.protocol === 'oidc') {
      authUrl.searchParams.set('nonce', nonce);
    }

    return {
      providerId: provider.id,
      url: authUrl.toString(),
      state: stateToken,
      expiresAt: new Date(expiresAtMs).toISOString()
    };
  }

  /**
   * Completa el callback OAuth2/OIDC: consume `state` atómicamente (single-use), intercambia
   * `code` + PKCE `code_verifier`, verifica firma JWKS del `id_token` (o `/user/emails` en GitHub),
   * exige `emailVerified === true` y valida `allowedDomains`.
   *
   * @param {{ state: string, code: string, ip?: string, fetchImpl?: Function, nowSec?: number }} input
   */
  async handleCallback(input) {
    const stateToken = typeof (input && input.state) === 'string' ? input.state.trim() : '';
    const code = typeof (input && input.code) === 'string' ? input.code.trim() : '';
    if (!stateToken || !code) {
      throw oidcError('Faltan parámetros obligatorios state o code en el callback SSO', 400, 'OIDC_MISSING_PARAMS');
    }

    // Consumo atómico ANTES de cualquier I/O de red (elimina carreras de replay)
    const pending = this._pendingFlows.get(stateToken);
    if (!pending) {
      throw oidcError('Estado SSO (state) inválido o ya utilizado', 401, 'OIDC_INVALID_STATE');
    }
    this._pendingFlows.delete(stateToken);

    if (Date.now() >= pending.expiresAt) {
      throw oidcError('La solicitud de inicio de sesión SSO ha caducado', 401, 'OIDC_STATE_EXPIRED');
    }
    if (pending.ip && input.ip && pending.ip !== String(input.ip).slice(0, 64)) {
      throw oidcError('La dirección IP del callback SSO no coincide con la sesión que inició el flujo', 403, 'OIDC_IP_MISMATCH');
    }

    const store = this._ensureLoaded(false);
    const provider = store ? store.providers[pending.providerId] : null;
    if (!provider || !provider.enabled) {
      throw oidcError('Proveedor SSO deshabilitado o eliminado', 404, 'OIDC_PROVIDER_NOT_FOUND');
    }

    const fetchImpl = (input && input.fetchImpl) || null;
    const discovery = await this._getDiscovery(provider, fetchImpl);
    const clientSecret = provider.clientSecretEnc ? this._decryptSecret(provider.id, provider.clientSecretEnc) : '';

    // Intercambio de código con PKCE code_verifier
    const form = new URLSearchParams();
    form.set('grant_type', 'authorization_code');
    form.set('code', code);
    form.set('redirect_uri', pending.redirectUri);
    form.set('client_id', provider.clientId);
    form.set('code_verifier', pending.codeVerifier);
    if (clientSecret) form.set('client_secret', clientSecret);

    const tokRes = await this._httpFetch(discovery.token_endpoint, provider, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: form.toString(),
      fetchImpl
    });
    if (!tokRes || !tokRes.ok) {
      throw oidcError(`Error al intercambiar código OAuth2/OIDC (HTTP ${tokRes?.status || 0})`, 401, 'OIDC_TOKEN_EXCHANGE_FAILED');
    }
    const tokenData = typeof tokRes.json === 'function' ? await tokRes.json() : tokRes.body;
    if (!tokenData || tokenData.error) {
      throw oidcError(`El proveedor rechazó el intercambio de token: ${tokenData?.error || 'unknown'}`, 401, 'OIDC_TOKEN_EXCHANGE_FAILED');
    }

    let subject = '';
    let email = '';
    let emailVerified = false;
    let name = '';
    /** @type {Record<string, any>} */
    let mergedClaims = {};

    if (provider.protocol === 'oidc') {
      if (!tokenData.id_token) {
        throw oidcError('El proveedor OIDC no devolvió un id_token', 401, 'OIDC_MISSING_ID_TOKEN');
      }
      let jwks = await this._getJwks(provider, discovery.jwks_uri, { fetchImpl });
      let verified;
      try {
        verified = verifyIdToken(tokenData.id_token, {
          jwks,
          expectedIssuer: discovery.issuer || provider.issuerUrl,
          expectedAudience: provider.clientId,
          expectedNonce: pending.nonce,
          nowSec: input && input.nowSec
        });
      } catch (err) {
        // Reintento único refrescando JWKS si rotó el `kid`
        if (err && /** @type {any} */ (err).code === 'OIDC_UNKNOWN_KID') {
          jwks = await this._getJwks(provider, discovery.jwks_uri, { forceRefresh: true, fetchImpl });
          verified = verifyIdToken(tokenData.id_token, {
            jwks,
            expectedIssuer: discovery.issuer || provider.issuerUrl,
            expectedAudience: provider.clientId,
            expectedNonce: pending.nonce,
            nowSec: input && input.nowSec
          });
        } else {
          throw err;
        }
      }
      const c = verified.claims;
      mergedClaims = { ...c };
      subject = String(c.sub);
      email = typeof c.email === 'string' ? c.email.trim().toLowerCase() : '';
      emailVerified = c.email_verified === true;
      name = String(c.name || c.preferred_username || (email ? email.split('@')[0] : 'SSO User'));

      const hasGroupMap = provider.groupRoleMap && Object.keys(provider.groupRoleMap).length > 0;
      const hasGroupsInToken = extractGroupsFromClaims(mergedClaims, provider.groupsClaim || 'groups').length > 0;

      // Si falta correo o faltan grupos configurados en id_token y existe userinfo_endpoint + access_token, consultar userinfo
      if ((!email || (hasGroupMap && !hasGroupsInToken)) && discovery.userinfo_endpoint && tokenData.access_token) {
        const uiRes = await this._httpFetch(discovery.userinfo_endpoint, provider, {
          method: 'GET',
          headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/json' },
          fetchImpl
        });
        if (uiRes && uiRes.ok) {
          const ui = typeof uiRes.json === 'function' ? await uiRes.json() : uiRes.body;
          if (ui && ui.sub && String(ui.sub) !== subject) {
            throw oidcError('El subject de userinfo no coincide con id_token', 401, 'OIDC_SUB_MISMATCH');
          }
          if (ui && typeof ui === 'object' && !Array.isArray(ui)) {
            mergedClaims = { ...ui, ...mergedClaims };
          }
          if (!email && ui && typeof ui.email === 'string') {
            email = ui.email.trim().toLowerCase();
            emailVerified = ui.email_verified === true;
          }
          if (ui && ui.name && !name) name = String(ui.name);
        }
      }
    } else if (provider.type === 'github') {
      if (!tokenData.access_token) {
        throw oidcError('GitHub no devolvió access_token', 401, 'OIDC_MISSING_ACCESS_TOKEN');
      }
      const ghHeaders = {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Culkibo-OIDC'
      };
      const userRes = await this._httpFetch(provider.userinfoEndpoint || PROVIDER_PRESETS.github.userinfoEndpoint, provider, {
        method: 'GET',
        headers: ghHeaders,
        fetchImpl
      });
      if (!userRes || !userRes.ok) {
        throw oidcError('Error al consultar perfil de usuario en GitHub', 401, 'OIDC_USERINFO_FAILED');
      }
      const ghUser = typeof userRes.json === 'function' ? await userRes.json() : userRes.body;
      subject = ghUser && ghUser.id != null ? String(ghUser.id) : '';
      name = String((ghUser && (ghUser.name || ghUser.login)) || 'GitHub User');

      const emailsRes = await this._httpFetch(provider.emailsEndpoint || PROVIDER_PRESETS.github.emailsEndpoint, provider, {
        method: 'GET',
        headers: ghHeaders,
        fetchImpl
      });
      if (!emailsRes || !emailsRes.ok) {
        throw oidcError('Error al consultar correos verificados en GitHub', 401, 'OIDC_EMAILS_FAILED');
      }
      const emailsList = typeof emailsRes.json === 'function' ? await emailsRes.json() : emailsRes.body;
      if (Array.isArray(emailsList)) {
        const chosenEmail =
          emailsList.find((e) => e && e.primary === true && e.verified === true && typeof e.email === 'string') ||
          emailsList.find((e) => e && e.verified === true && typeof e.email === 'string');
        if (chosenEmail) {
          email = chosenEmail.email.trim().toLowerCase();
          emailVerified = true;
        }
      }
    }

    if (!subject || !email) {
      throw oidcError('El proveedor SSO no devolvió un correo electrónico válido', 403, 'OIDC_EMAIL_MISSING');
    }
    if (!emailVerified) {
      throw oidcError('El correo electrónico no está verificado en el proveedor SSO', 403, 'OIDC_EMAIL_NOT_VERIFIED');
    }

    // Comprobar allowlist de dominios de correo si está configurada
    if (Array.isArray(provider.allowedDomains) && provider.allowedDomains.length > 0) {
      const domain = email.split('@')[1] || '';
      if (!provider.allowedDomains.includes(domain)) {
        throw oidcError(`El dominio de correo "${domain}" no está autorizado para este proveedor SSO`, 403, 'OIDC_DOMAIN_NOT_ALLOWED');
      }
    }

    const roleResolution = resolveRoleFromClaims(provider, mergedClaims);

    return {
      providerId: provider.id,
      providerType: provider.type,
      subject,
      email,
      emailVerified: true,
      name: name.slice(0, 80),
      teamId: pending.teamId,
      autoProvision: Boolean(provider.autoProvision),
      defaultRole: roleResolution.role,
      resolvedRole: roleResolution.role,
      roleSource: roleResolution.source,
      groups: roleResolution.groups,
      matchedGroups: roleResolution.matchedGroups,
      enforceLocal2fa: Boolean(provider.enforceLocal2fa)
    };
  }
}

const defaultInstance = new OidcService();

module.exports = Object.assign(defaultInstance, {
  OidcService,
  PROVIDER_PRESETS,
  ALLOWED_JWS_ALGS,
  ALLOWED_DEFAULT_ROLES,
  generatePkcePair,
  verifyIdToken,
  sanitizeGroupRoleMap,
  sanitizeGroupsClaim,
  extractGroupsFromClaims,
  resolveRoleFromClaims
});
