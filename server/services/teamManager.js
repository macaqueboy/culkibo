const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');

const { hashBcrypt, verifyBcrypt } = require('./bcryptHash');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Gestión multiusuario, equipos/workspaces, RBAC estricto, ACLs por proyecto,
 * invitaciones de un solo uso y tokens API/MCP con ámbito dinámico.
 *
 * Cero dependencias npm externas, cero ejecución de shell, almacenamiento atómico
 * `0o600` con respaldo `.bak` (`data/teams.json` + `data/.rbac.key`) y carga
 * perezosa: si `data/teams.json` no existe, no escribe nada en disco ni consume
 * memoria extra en instalaciones single-user.
 */

function resolveDefaultDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.join(__dirname, '..', '..', 'data');
}
const DEFAULT_DATA_DIR = resolveDefaultDataDir();
const DATA_FILE_NAME = 'teams.json';
const KEY_FILE_NAME = '.rbac.key';
const DEFAULT_TEAM_ID = 'team_default';

const MAX_SESSIONS_PER_USER = 25;
const DEFAULT_SESSION_TTL_HOURS = 24;
const MAX_SESSION_TTL_HOURS = 24 * 30;
const DEFAULT_INVITE_TTL_HOURS = 48;
const MAX_INVITE_TTL_HOURS = 168;
const MIN_PASSWORD_BYTES = 8;
const MAX_PASSWORD_BYTES = 72; // Evita truncado silencioso de OpenBSD bcrypt > 72 bytes
const DEFAULT_BCRYPT_COST = 10;

// Bloqueo anti fuerza bruta por correo (LRU acotado, nunca clear() masivo)
const EMAIL_FAIL_WINDOW_MS = 60 * 1000;
const EMAIL_FAIL_MAX = 10;
const EMAIL_FAIL_MAP_CAP = 2000;

// Hash bcrypt sintético (coste 10) válido para mitigación timing en emails inexistentes
const DUMMY_BCRYPT_HASH = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/;
const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,47}$/;

/** Jerarquía estricta de rangos: owner(40) > admin(30) > developer(20) > viewer(10). */
const ROLE_RANKS = Object.freeze({
  viewer: 10,
  developer: 20,
  admin: 30,
  owner: 40
});

const VALID_ROLES = Object.freeze(['viewer', 'developer', 'admin', 'owner']);
const INVITABLE_ROLES = Object.freeze(['viewer', 'developer', 'admin']);
const PROJECT_ACL_ROLES = Object.freeze(['none', 'viewer', 'developer', 'admin']);

const VIEWER_PERMS = Object.freeze([
  'projects:read',
  'deployments:read',
  'logs:read',
  'metrics:read',
  'domains:read',
  'databases:read',
  'catalog:read',
  'mcp:read',
  'fleet:read',
  'team:read',
  'uptime:read',
  'environments:read',
  'gitops:read',
  'sync:read'
]);

const DEVELOPER_ONLY_PERMS = Object.freeze([
  'projects:write',
  'deployments:write',
  'sync:write',
  'crons:write',
  'previews:write',
  'runtime:exec',
  'domains:write',
  'databases:write',
  'secrets:read',
  'mcp:write',
  'uptime:write',
  'environments:write',
  'sleep:write',
  'tokens:self'
]);

const ADMIN_ONLY_PERMS = Object.freeze([
  'projects:delete',
  'projects:acl',
  'catalog:write',
  'databases:admin',
  'team:write',
  'audit:read',
  'fleet:write',
  'gitops:write',
  'tokens:read',
  'tokens:write'
]);

const OWNER_ONLY_PERMS = Object.freeze([
  'team:delete',
  'team:transfer',
  'auth:rotate',
  'system:write',
  'system:panel_domain',
  'docker:write',
  'ingress:write',
  'ssl:write',
  'cloudflare:write',
  'backup:instance',
  'fleet:ssh',
  'host:localPath',
  'instance:admin',
  'tokens:admin'
]);

const ALL_PERMISSIONS = Object.freeze([
  ...VIEWER_PERMS,
  ...DEVELOPER_ONLY_PERMS,
  ...ADMIN_ONLY_PERMS,
  ...OWNER_ONLY_PERMS
]);

const ALL_PERMISSIONS_SET = new Set(ALL_PERMISSIONS);

/** @type {Record<string, ReadonlySet<string>>} */
const ROLE_PERMISSIONS = Object.freeze({
  viewer: new Set(VIEWER_PERMS),
  developer: new Set([...VIEWER_PERMS, ...DEVELOPER_ONLY_PERMS]),
  admin: new Set([...VIEWER_PERMS, ...DEVELOPER_ONLY_PERMS, ...ADMIN_ONLY_PERMS]),
  owner: new Set(['*', ...ALL_PERMISSIONS])
});

/**
 * @typedef {{
 *   isSuperAdmin: boolean,
 *   kind: 'master' | 'loopback' | 'ws_ticket' | 'session' | 'api_token',
 *   userId: string | null,
 *   email: string | null,
 *   name?: string | null,
 *   role: 'owner' | 'admin' | 'developer' | 'viewer',
 *   teamId: string,
 *   sessionId?: string | null,
 *   tokenId?: string | null,
 *   tokenName?: string | null,
 *   tokenVersion?: number,
 *   projectIds: string[] | null,
 *   scopes: readonly string[] | null,
 *   requestedScopes?: string[] | null,
 *   clamped?: boolean
 * }} Principal
 */

/**
 * Crea un error con código HTTP asociado.
 * @param {string} message
 * @param {number} [status]
 * @param {string} [code]
 */
function httpError(message, status = 400, code = 'RBAC_ERROR') {
  /** @type {Error & { status?: number, code?: string }} */
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

/** @param {string | null | undefined} role */
function roleRank(role) {
  if (!role || typeof role !== 'string') return 0;
  return Object.prototype.hasOwnProperty.call(ROLE_RANKS, role) ? ROLE_RANKS[role] : 0;
}

/**
 * @param {string | null | undefined} role
 * @param {string} minRole
 */
function hasMinRole(role, minRole) {
  const min = roleRank(minRole);
  if (min <= 0) return false;
  return roleRank(role) >= min;
}

/** @param {string | null | undefined} role */
function getRolePermissions(role) {
  if (!role || !Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)) {
    return new Set();
  }
  return new Set(ROLE_PERMISSIONS[role]);
}

/** @param {any} rawEmail */
function normalizeEmail(rawEmail) {
  if (typeof rawEmail !== 'string') return '';
  return rawEmail.trim().toLowerCase();
}

/** @param {string} email */
function assertValidEmail(email) {
  const norm = normalizeEmail(email);
  if (!norm || norm.length > 254 || !EMAIL_RE.test(norm)) {
    throw httpError('Correo electrónico inválido', 400, 'INVALID_EMAIL');
  }
  return norm;
}

/**
 * Valida la contraseña en UTF-8 (`8 <= bytes <= 72`, sin bytes nulos).
 * Evita la colisión por truncado silencioso de OpenBSD bcrypt a 72 bytes.
 * @param {any} password
 */
function validatePassword(password) {
  if (typeof password !== 'string' || password.includes('\0')) {
    throw httpError('Contraseña inválida', 400, 'INVALID_PASSWORD');
  }
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < MIN_PASSWORD_BYTES) {
    throw httpError(`La contraseña debe tener al menos ${MIN_PASSWORD_BYTES} caracteres`, 400, 'PASSWORD_TOO_SHORT');
  }
  if (bytes > MAX_PASSWORD_BYTES) {
    throw httpError(`La contraseña no puede superar ${MAX_PASSWORD_BYTES} bytes UTF-8`, 400, 'PASSWORD_TOO_LONG');
  }
  return password;
}

/**
 * Normaliza y valida una lista de `projectIds` (`null`/`'*'` = todos, o array acotado).
 * @param {any} rawProjectIds
 * @returns {string[] | null}
 */
function normalizeProjectIds(rawProjectIds) {
  if (rawProjectIds === undefined || rawProjectIds === null || rawProjectIds === '*') {
    return null;
  }
  if (!Array.isArray(rawProjectIds)) {
    throw httpError('projectIds debe ser null, "*" o una lista de IDs de proyecto', 400, 'INVALID_PROJECT_IDS');
  }
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const item of rawProjectIds) {
    if (typeof item !== 'string') {
      throw httpError('Cada projectId debe ser una cadena válida', 400, 'INVALID_PROJECT_IDS');
    }
    const clean = item.trim();
    if (!PROJECT_ID_RE.test(clean)) {
      throw httpError(`projectId inválido: ${clean.slice(0, 40)}`, 400, 'INVALID_PROJECT_IDS');
    }
    if (!seen.has(clean)) {
      seen.add(clean);
      out.push(clean);
    }
  }
  return out;
}

/**
 * Intersecta dos restricciones de `projectIds` (`null` significa sin restricción).
 * @param {readonly string[] | null | undefined} a
 * @param {readonly string[] | null | undefined} b
 * @returns {string[] | null}
 */
function intersectProjectIds(a, b) {
  const aArr = Array.isArray(a) ? a : null;
  const bArr = Array.isArray(b) ? b : null;
  if (aArr === null && bArr === null) return null;
  if (aArr === null) return [.../** @type {readonly string[]} */ (bArr)];
  if (bArr === null) return [...aArr];
  const setB = new Set(bArr);
  return aArr.filter((id) => setB.has(id));
}

/**
 * Comprueba si `requested` es un subconjunto de `allowed` (`null` = todos los proyectos).
 * @param {string[] | null} requested
 * @param {readonly string[] | null | undefined} allowed
 */
function isProjectSubset(requested, allowed) {
  if (!Array.isArray(allowed)) return true; // caller sin restricción
  if (requested === null) return false; // no se puede ampliar a todos los proyectos
  const allowedSet = new Set(allowed);
  return requested.every((id) => allowedSet.has(id));
}

/**
 * Intersecta los scopes solicitados de un token con los permisos actuales del rol.
 * @param {readonly string[]} tokenScopes
 * @param {string} role
 * @returns {string[]}
 */
function intersectScopesWithRole(tokenScopes, role) {
  const rolePerms = ROLE_PERMISSIONS[role];
  if (!rolePerms || !Array.isArray(tokenScopes)) return [];
  if (role === 'owner') {
    if (tokenScopes.includes('*')) return ['*'];
    return Array.from(new Set(tokenScopes.filter((s) => ALL_PERMISSIONS_SET.has(s))));
  }
  if (tokenScopes.includes('*')) {
    return Array.from(rolePerms).filter((s) => s !== '*');
  }
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const s of tokenScopes) {
    if (typeof s === 'string' && rolePerms.has(s) && !seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}

/**
 * Extrae el objeto `principal` aunque el llamador pase `{ method, principal }`.
 * @param {any} principalOrAuth
 * @returns {Principal | null}
 */
function unwrapPrincipal(principalOrAuth) {
  if (!principalOrAuth || typeof principalOrAuth !== 'object') return null;
  if (principalOrAuth.principal && typeof principalOrAuth.principal === 'object') {
    return principalOrAuth.principal;
  }
  return principalOrAuth;
}

/**
 * Comparación constante de cadenas hex/UTF-8.
 * @param {string} a
 * @param {string} b
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  try {
    return crypto.timingSafeEqual(ba, bb);
  } catch (e) {
    return false;
  }
}

/** @param {string} name */
function slugifyTeamName(name) {
  const base = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return base || `team-${crypto.randomBytes(3).toString('hex')}`;
}

/**
 * Crea el estado vacío inicial (sin escribir en disco hasta que haya un usuario).
 */
function createEmptyState() {
  const now = new Date().toISOString();
  return {
    version: 1,
    settings: {
      enforceOnLoopback: false,
      sessionTtlHours: DEFAULT_SESSION_TTL_HOURS,
      maxInviteTtlHours: MAX_INVITE_TTL_HOURS
    },
    /** @type {any[]} */
    users: [],
    /** @type {any[]} */
    teams: [
      {
        id: DEFAULT_TEAM_ID,
        slug: 'default',
        name: 'Default Workspace',
        isDefault: true,
        createdBy: null,
        createdAt: now,
        updatedAt: now,
        /** @type {any[]} */
        members: []
      }
    ],
    /** @type {Record<string, { teamId: string, overrides: Record<string, string> }>} */
    projectAcls: {},
    /** @type {any[]} */
    invites: [],
    /** @type {any[]} */
    apiTokens: []
  };
}

class TeamManager extends EventEmitter {
  /**
   * @param {{
   *   dataDir?: string,
   *   dataFile?: string,
   *   keyFile?: string,
   *   secret?: string | null,
   *   bcryptCost?: number
   * }} [options]
   */
  constructor(options = {}) {
    super();
    this.dataDir = options.dataDir ? path.resolve(options.dataDir) : resolveDefaultDataDir();
    this.dataFile = options.dataFile ? path.resolve(options.dataFile) : path.join(this.dataDir, DATA_FILE_NAME);
    this.keyFile = options.keyFile ? path.resolve(options.keyFile) : path.join(this.dataDir, KEY_FILE_NAME);
    this._secretOverride = options.secret || null;
    this._bcryptCost = Math.min(14, Math.max(4, Number(options.bcryptCost) || DEFAULT_BCRYPT_COST));

    /** @type {ReturnType<typeof createEmptyState> | null} */
    this._state = null;
    /** @type {Buffer | null} */
    this._signingKey = null;
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this._emailFailMap = new Map();
    /** @type {number} */
    this._lastTokenTouchFlush = 0;
  }

  /** Carga perezosa desde disco solo si existe `data/teams.json` o se requiere escritura. */
  _ensureLoaded(forWrite = false) {
    if (this._state) return this._state;
    const loaded = loadJsonWithBackupSync(this.dataFile, {
      validate: (parsed) => Boolean(
        parsed &&
        typeof parsed === 'object' &&
        Array.isArray(parsed.users) &&
        Array.isArray(parsed.teams)
      )
    });
    if (loaded.corrupt) {
      throw httpError(
        `Archivo RBAC corrupto en ${this.dataFile} (cuarentena: ${loaded.quarantinePath || 'desconocida'}). Restaura una copia válida antes de continuar.`,
        500,
        'RBAC_STORE_CORRUPT'
      );
    }
    if (loaded.ok && loaded.data) {
      const s = loaded.data;
      if (!s.settings || typeof s.settings !== 'object') {
        s.settings = {
          enforceOnLoopback: false,
          sessionTtlHours: DEFAULT_SESSION_TTL_HOURS,
          maxInviteTtlHours: MAX_INVITE_TTL_HOURS
        };
      }
      if (!s.projectAcls || typeof s.projectAcls !== 'object') s.projectAcls = {};
      if (!Array.isArray(s.invites)) s.invites = [];
      if (!Array.isArray(s.apiTokens)) s.apiTokens = [];
      this._state = s;
      if (loaded.recoveredFromBak) {
        try {
          atomicWriteJsonSync(this.dataFile, this._state, { mode: 0o600, pretty: true, backup: false });
        } catch (e) {}
      }
      return this._state;
    }
    if (!forWrite) {
      return null;
    }
    this._state = createEmptyState();
    return this._state;
  }

  /**
   * Obtiene o inicializa la clave HMAC maestra (`data/.rbac.key`, 32 bytes, `0o600`).
   * Nunca regenera silenciosamente si ya existen usuarios o la clave está corrupta.
   * @returns {Buffer}
   */
  _ensureSigningKey() {
    if (this._signingKey) return this._signingKey;

    const envSecret = this._secretOverride || process.env.CULKIBO_TEAM_SECRET;
    if (envSecret && String(envSecret).trim()) {
      this._signingKey = crypto.scryptSync(String(envSecret).trim(), 'culkibo-rbac-v1-signing-key', 32);
      return this._signingKey;
    }

    if (fs.existsSync(this.keyFile)) {
      const raw = fs.readFileSync(this.keyFile, 'utf8').trim();
      const buf = Buffer.from(raw, 'hex');
      if (buf.length !== 32 || buf.toString('hex') !== raw.toLowerCase()) {
        throw httpError(
          `Clave de firma RBAC corrupta en ${this.keyFile} (se esperan 32 bytes hex). No se regenerará automáticamente.`,
          500,
          'RBAC_KEY_CORRUPT'
        );
      }
      this._signingKey = buf;
      return this._signingKey;
    }

    // Guardia anti-pérdida de clave: si ya hay usuarios en teams.json, jamás crear otra clave
    if (this._state && this._state.users.length > 0 && fs.existsSync(this.dataFile)) {
      throw httpError(
        `Falta la clave de firma ${this.keyFile} pero ${this.dataFile} contiene cuentas/tokens activos. Restaura ${KEY_FILE_NAME} desde tu respaldo.`,
        500,
        'RBAC_KEY_MISSING'
      );
    }

    fs.mkdirSync(path.dirname(this.keyFile), { recursive: true, mode: 0o700 });
    const fresh = crypto.randomBytes(32);
    try {
      fs.writeFileSync(this.keyFile, fresh.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      try { fs.chmodSync(this.keyFile, 0o600); } catch (e) {}
      this._signingKey = fresh;
      return this._signingKey;
    } catch (err) {
      if (err && /** @type {any} */ (err).code === 'EEXIST') {
        const racedRaw = fs.readFileSync(this.keyFile, 'utf8').trim();
        const raced = Buffer.from(racedRaw, 'hex');
        if (raced.length === 32) {
          this._signingKey = raced;
          return this._signingKey;
        }
      }
      throw err;
    }
  }

  /** Guarda el estado de forma atómica (`0o600` + respaldo `.bak`). */
  _save() {
    if (!this._state) return;
    atomicWriteJsonSync(this.dataFile, this._state, { mode: 0o600, pretty: true, backup: true });
  }

  /** @param {string} domain @param {string} value */
  _hmacHex(domain, value) {
    const key = this._ensureSigningKey();
    return crypto.createHmac('sha256', key).update(`${domain}:${value}`).digest('hex');
  }

  /**
   * Emite evento `principal_revoked` para cortar WS/SSE inmediatamente.
   * @param {{ userId?: string | null, sessionId?: string | null, tokenId?: string | null, teamId?: string | null, reason?: string }} evt
   */
  _emitRevoked(evt) {
    const payload = {
      userId: evt.userId || null,
      sessionId: evt.sessionId || null,
      tokenId: evt.tokenId || null,
      teamId: evt.teamId || null,
      reason: evt.reason || 'revoked',
      at: new Date().toISOString()
    };
    this.emit('principal_revoked', payload);
  }

  /**
   * Suscripción a eventos de revocación de principal (WS/SSE close 4001).
   * @param {(evt: { userId: string | null, sessionId: string | null, tokenId: string | null, teamId: string | null, reason: string, at: string }) => void} listener
   */
  onPrincipalRevoked(listener) {
    if (typeof listener !== 'function') return () => {};
    this.on('principal_revoked', listener);
    return () => this.off('principal_revoked', listener);
  }

  /** Indica si existe al menos un usuario configurado (cero E/S innecesaria en arranque). */
  isMultiUserEnabled() {
    if (this._state) return this._state.users.length > 0;
    if (!fs.existsSync(this.dataFile)) return false;
    const state = this._ensureLoaded(false);
    return Boolean(state && state.users.length > 0);
  }

  /** Indica si se fuerza autenticación incluso en loopback. */
  isEnforceOnLoopback() {
    if (!this.isMultiUserEnabled()) return false;
    const state = this._ensureLoaded(false);
    return Boolean(state && state.settings && state.settings.enforceOnLoopback);
  }

  /** Resumen sin secretos para `/api/auth/session` y `authStatus()`. */
  getStatusSummary() {
    if (!this._state && !fs.existsSync(this.dataFile)) {
      return { multiUserEnabled: false, usersCount: 0, teamsCount: 0, keyFile: KEY_FILE_NAME };
    }
    const state = this._ensureLoaded(false);
    if (!state) {
      return { multiUserEnabled: false, usersCount: 0, teamsCount: 0, keyFile: KEY_FILE_NAME };
    }
    return {
      multiUserEnabled: state.users.length > 0,
      usersCount: state.users.length,
      teamsCount: state.teams.length,
      enforceOnLoopback: Boolean(state.settings && state.settings.enforceOnLoopback),
      keyFile: KEY_FILE_NAME
    };
  }

  // ---------------------------------------------------------------------------
  // Anti fuerza bruta por correo (LRU acotado a 2000 correos)
  // ---------------------------------------------------------------------------

  /** @param {string} email */
  _checkEmailLockout(email) {
    if (!email || this._emailFailMap.size === 0) return { blocked: false, retryAfterSec: 0 };
    const now = Date.now();
    const entry = this._emailFailMap.get(email);
    if (entry && entry.resetAt > now && entry.count >= EMAIL_FAIL_MAX) {
      return { blocked: true, retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) };
    }
    return { blocked: false, retryAfterSec: 0 };
  }

  /** @param {string} email */
  _recordEmailFailure(email) {
    if (!email) return;
    const now = Date.now();
    let entry = this._emailFailMap.get(email);
    if (!entry || entry.resetAt <= now) {
      if (this._emailFailMap.size >= EMAIL_FAIL_MAP_CAP) {
        for (const [k, v] of this._emailFailMap.entries()) {
          if (v.resetAt <= now) this._emailFailMap.delete(k);
          if (this._emailFailMap.size < EMAIL_FAIL_MAP_CAP) break;
        }
        if (this._emailFailMap.size >= EMAIL_FAIL_MAP_CAP) {
          const oldest = this._emailFailMap.keys().next().value;
          if (oldest) this._emailFailMap.delete(oldest);
        }
      }
      entry = { count: 1, resetAt: now + EMAIL_FAIL_WINDOW_MS };
    } else {
      entry.count++;
      this._emailFailMap.delete(email);
    }
    this._emailFailMap.set(email, entry);
  }

  /** @param {string} email */
  _clearEmailFailure(email) {
    if (email) this._emailFailMap.delete(email);
  }

  // ---------------------------------------------------------------------------
  // Sanitizadores (nunca exponer passwordHash, tokenKey ni hashes HMAC)
  // ---------------------------------------------------------------------------

  /** @param {any} user */
  sanitizeUser(user) {
    if (!user) return null;
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      mustRotatePassword: Boolean(user.mustRotatePassword),
      activeSessionsCount: Array.isArray(user.sessions) ? user.sessions.length : 0,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt || null
    };
  }

  /** @param {any} team */
  sanitizeTeam(team) {
    if (!team) return null;
    return {
      id: team.id,
      slug: team.slug,
      name: team.name,
      isDefault: Boolean(team.isDefault),
      createdBy: team.createdBy || null,
      createdAt: team.createdAt,
      updatedAt: team.updatedAt || team.createdAt,
      membersCount: Array.isArray(team.members) ? team.members.length : 0
    };
  }

  /** @param {any} invite */
  sanitizeInvite(invite) {
    if (!invite) return null;
    const now = Date.now();
    const expired = Date.parse(invite.expiresAt) <= now;
    const status = invite.revokedAt ? 'revoked' : invite.usedAt ? 'used' : expired ? 'expired' : 'pending';
    return {
      id: invite.id,
      teamId: invite.teamId,
      email: invite.email,
      role: invite.role,
      projectIds: Array.isArray(invite.projectIds) ? [...invite.projectIds] : null,
      tokenPreview: `${invite.tokenPrefix}_********`,
      status,
      createdBy: invite.createdBy,
      createdAt: invite.createdAt,
      expiresAt: invite.expiresAt,
      usedAt: invite.usedAt || null,
      usedBy: invite.usedBy || null,
      revokedAt: invite.revokedAt || null
    };
  }

  /** @param {any} tok */
  sanitizeApiToken(tok) {
    if (!tok) return null;
    const now = Date.now();
    const expired = Boolean(tok.expiresAt && Date.parse(tok.expiresAt) <= now);
    const status = tok.revokedAt ? 'revoked' : expired ? 'expired' : 'active';
    const liveRole = this.getMemberRole(tok.userId, tok.teamId);
    const effectiveScopes = liveRole ? intersectScopesWithRole(tok.scopes, liveRole) : [];
    return {
      id: tok.id,
      name: tok.name,
      userId: tok.userId,
      teamId: tok.teamId,
      tokenPreview: `${tok.tokenPrefix}_********`,
      scopes: [...tok.scopes],
      effectiveScopes,
      projectIds: Array.isArray(tok.projectIds) ? [...tok.projectIds] : null,
      status,
      createdAt: tok.createdAt,
      expiresAt: tok.expiresAt || null,
      lastUsedAt: tok.lastUsedAt || null,
      lastUsedIp: tok.lastUsedIp || null,
      revokedAt: tok.revokedAt || null
    };
  }

  // ---------------------------------------------------------------------------
  // Búsquedas internas
  // ---------------------------------------------------------------------------

  /** @param {string} userId */
  _findUserById(userId) {
    const state = this._ensureLoaded(false);
    if (!state || !userId) return null;
    return state.users.find((u) => u.id === userId) || null;
  }

  /** @param {string} email */
  _findUserByEmail(email) {
    const state = this._ensureLoaded(false);
    const norm = normalizeEmail(email);
    if (!state || !norm) return null;
    return state.users.find((u) => u.email === norm) || null;
  }

  /** @param {string} teamId */
  _findTeam(teamId) {
    const state = this._ensureLoaded(false);
    if (!state || !teamId) return null;
    return state.teams.find((t) => t.id === teamId) || null;
  }

  /**
   * @param {string | null | undefined} userId
   * @param {string | null | undefined} teamId
   */
  _findMember(userId, teamId) {
    if (!userId || !teamId) return null;
    const team = this._findTeam(teamId);
    if (!team) return null;
    return team.members.find((m) => m.userId === userId) || null;
  }

  /**
   * Devuelve el rol vivo del usuario en el equipo (o null si deshabilitado/no miembro).
   * @param {string | null | undefined} userId
   * @param {string | null | undefined} [teamId]
   * @returns {'owner' | 'admin' | 'developer' | 'viewer' | null}
   */
  getMemberRole(userId, teamId = DEFAULT_TEAM_ID) {
    if (!userId) return null;
    const user = this._findUserById(userId);
    if (!user || user.status !== 'active') return null;
    const member = this._findMember(userId, teamId || DEFAULT_TEAM_ID);
    return member ? member.role : null;
  }

  /**
   * Invalida sesiones existentes del usuario subiendo `tokenVersion` + `tokensValidAfter`.
   * @param {any} user
   */
  _bumpTokenVersion(user) {
    const now = Date.now();
    user.tokenVersion = (Number(user.tokenVersion) || 1) + 1;
    user.tokensValidAfter = Math.max(now, (Number(user.tokensValidAfter) || 0) + 1);
    user.updatedAt = new Date(now).toISOString();
  }

  /**
   * Rota el `tokenKey` (32 bytes) al cambiar contraseña, deshabilitar o cerrar todas las sesiones.
   * @param {any} user
   */
  _rotateUserTokenKey(user) {
    user.tokenKey = crypto.randomBytes(32).toString('hex');
    user.sessions = [];
    this._bumpTokenVersion(user);
  }

  // ---------------------------------------------------------------------------
  // Bootstrap, Login, Password y Sesiones Triple-Capa (`cks_...`)
  // ---------------------------------------------------------------------------

  /**
   * Bootstrap inicial estrictamente de un solo uso (`users.length === 0`).
   * Crea el primer `owner` en `team_default` y emite su primera sesión `cks_`.
   * @param {{ email: string, password: string, name?: string, teamName?: string, enforceOnLoopback?: boolean, ip?: string, ua?: string }} input
   */
  bootstrapOwner(input) {
    const state = this._ensureLoaded(true);
    if (!state) throw httpError('No se pudo inicializar el almacenamiento RBAC', 500, 'RBAC_INIT_ERROR');
    if (state.users.length > 0) {
      throw httpError('El sistema multiusuario ya está inicializado (bootstrap bloqueado)', 403, 'ALREADY_BOOTSTRAPPED');
    }

    const email = assertValidEmail(input && input.email);
    const password = validatePassword(input && input.password);
    const displayName = String((input && input.name) || email.split('@')[0] || 'Owner').trim().slice(0, 80);

    // Garantiza creación atómica de `data/.rbac.key` antes de persistir usuarios
    this._ensureSigningKey();

    const now = new Date().toISOString();
    const userId = `usr_${crypto.randomBytes(8).toString('hex')}`;
    const user = {
      id: userId,
      email,
      name: displayName,
      passwordHash: hashBcrypt(password, this._bcryptCost),
      status: 'active',
      tokenKey: crypto.randomBytes(32).toString('hex'),
      tokenVersion: 1,
      tokensValidAfter: 0,
      mustRotatePassword: false,
      sessions: [],
      createdAt: now,
      updatedAt: now,
      lastLoginAt: now
    };

    let defaultTeam = state.teams.find((t) => t.id === DEFAULT_TEAM_ID);
    if (!defaultTeam) {
      defaultTeam = {
        id: DEFAULT_TEAM_ID,
        slug: 'default',
        name: String((input && input.teamName) || 'Default Workspace').trim().slice(0, 80) || 'Default Workspace',
        isDefault: true,
        createdBy: userId,
        createdAt: now,
        updatedAt: now,
        members: []
      };
      state.teams.push(defaultTeam);
    } else {
      if (input && input.teamName && String(input.teamName).trim()) {
        defaultTeam.name = String(input.teamName).trim().slice(0, 80);
      }
      defaultTeam.createdBy = userId;
      defaultTeam.updatedAt = now;
    }

    defaultTeam.members.push({
      userId,
      role: 'owner',
      projectIds: null,
      addedAt: now,
      addedBy: userId
    });

    if (input && typeof input.enforceOnLoopback === 'boolean') {
      state.settings.enforceOnLoopback = input.enforceOnLoopback;
    }

    state.users.push(user);
    const issued = this._issueSessionForUser(user, defaultTeam.id, { ip: input && input.ip, ua: input && input.ua });
    this._save();

    return {
      user: this.sanitizeUser(user),
      team: this.sanitizeTeam(defaultTeam),
      role: 'owner',
      sessionToken: issued.token,
      sessionId: issued.sessionId,
      expiresAt: issued.expiresAt
    };
  }

  /**
   * Firma y registra una sesión `cks_<b64url(payload)>.<b64url(sig)>` acotada a 25 por usuario.
   * @param {any} user
   * @param {string} teamId
   * @param {{ ip?: string, ua?: string, ttlHours?: number }} [meta]
   */
  _issueSessionForUser(user, teamId, meta = {}) {
    const state = this._ensureLoaded(true);
    const serverKey = this._ensureSigningKey();
    const nowMs = Date.now();
    const configTtl = (state && state.settings && Number(state.settings.sessionTtlHours)) || DEFAULT_SESSION_TTL_HOURS;
    const ttlHours = Math.min(MAX_SESSION_TTL_HOURS, Math.max(1, Number(meta.ttlHours) || configTtl));
    const expMs = nowMs + ttlHours * 3600 * 1000;
    const sid = `sid_${crypto.randomBytes(12).toString('hex')}`;

    if (!Array.isArray(user.sessions)) user.sessions = [];
    // Limpiar sesiones expiradas antes de comprobar el límite
    user.sessions = user.sessions.filter((s) => Date.parse(s.expiresAt) > nowMs);
    while (user.sessions.length >= MAX_SESSIONS_PER_USER) {
      const evicted = user.sessions.shift();
      if (evicted && evicted.sid) {
        this._emitRevoked({ userId: user.id, sessionId: evicted.sid, teamId: evicted.teamId, reason: 'session_evicted' });
      }
    }

    const createdAtIso = new Date(nowMs).toISOString();
    const expiresAtIso = new Date(expMs).toISOString();
    user.sessions.push({
      sid,
      teamId,
      createdAt: createdAtIso,
      expiresAt: expiresAtIso,
      lastUsedAt: createdAtIso,
      ip: String(meta.ip || '').slice(0, 64),
      ua: String(meta.ua || '').slice(0, 200)
    });

    const payload = {
      v: 1,
      sid,
      uid: user.id,
      tid: teamId,
      iat: nowMs,
      exp: expMs,
      tv: Number(user.tokenVersion) || 1
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const derivedKey = crypto.createHmac('sha256', serverKey).update(`session:v1:${user.tokenKey}`).digest();
    const sig = crypto.createHmac('sha256', derivedKey).update(encodedPayload).digest('base64url');

    return {
      token: `cks_${encodedPayload}.${sig}`,
      sessionId: sid,
      expiresAt: expiresAtIso
    };
  }

  /**
   * Inicia sesión con correo + contraseña (protección timing constante + lockout por email).
   * @param {{ email: string, password: string, teamId?: string, ip?: string, ua?: string }} input
   */
  login(input) {
    const normEmail = normalizeEmail(input && input.email);
    const rawPassword = typeof (input && input.password) === 'string' ? input.password : '';

    const lock = this._checkEmailLockout(normEmail);
    if (lock.blocked) {
      const err = httpError('Demasiados intentos fallidos para esta cuenta. Espera un minuto.', 429, 'EMAIL_LOCKED');
      /** @type {any} */ (err).retryAfterSec = lock.retryAfterSec;
      throw err;
    }

    const state = this._ensureLoaded(false);
    const user = state && normEmail ? state.users.find((u) => u.email === normEmail) : null;
    const pwdBytes = Buffer.byteLength(rawPassword, 'utf8');

    // Verificación en tiempo constante aunque el correo no exista o exceda 72 bytes
    if (!user || user.status !== 'active' || pwdBytes < 1 || pwdBytes > MAX_PASSWORD_BYTES || rawPassword.includes('\0')) {
      verifyBcrypt(rawPassword.slice(0, MAX_PASSWORD_BYTES) || 'dummy-check', DUMMY_BCRYPT_HASH);
      this._recordEmailFailure(normEmail);
      throw httpError('Credenciales inválidas', 401, 'INVALID_CREDENTIALS');
    }

    const matched = verifyBcrypt(rawPassword, user.passwordHash);
    if (!matched) {
      this._recordEmailFailure(normEmail);
      throw httpError('Credenciales inválidas', 401, 'INVALID_CREDENTIALS');
    }

    this._clearEmailFailure(normEmail);

    // Determinar equipo activo
    const memberships = (state ? state.teams : [])
      .map((t) => ({ team: t, member: t.members.find((m) => m.userId === user.id) }))
      .filter((x) => Boolean(x.member));
    if (memberships.length === 0) {
      throw httpError('Tu cuenta no pertenece a ningún equipo activo', 403, 'NO_TEAM_MEMBERSHIP');
    }

    let chosen = memberships[0];
    if (input && input.teamId) {
      const found = memberships.find((x) => x.team.id === input.teamId);
      if (!found) {
        throw httpError('No tienes acceso al equipo solicitado', 403, 'TEAM_ACCESS_DENIED');
      }
      chosen = found;
    } else {
      const def = memberships.find((x) => x.team.id === DEFAULT_TEAM_ID);
      if (def) chosen = def;
    }

    user.lastLoginAt = new Date().toISOString();
    const issued = this._issueSessionForUser(user, chosen.team.id, { ip: input && input.ip, ua: input && input.ua });
    this._save();

    return {
      user: this.sanitizeUser(user),
      team: this.sanitizeTeam(chosen.team),
      role: chosen.member.role,
      sessionToken: issued.token,
      sessionId: issued.sessionId,
      expiresAt: issued.expiresAt
    };
  }

  /**
   * Cambia el equipo activo de una sesión autenticada (solo si el usuario es miembro del equipo destino).
   * @param {any} actorOrAuth
   * @param {string} targetTeamId
   * @param {{ ip?: string, ua?: string }} [meta]
   */
  switchTeam(actorOrAuth, targetTeamId, meta = {}) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor || actor.kind !== 'session' || !actor.userId) {
      throw httpError('Se requiere una sesión de usuario activa para cambiar de equipo', 401, 'SESSION_REQUIRED');
    }
    if (!this.isPrincipalStillValid(actor)) {
      throw httpError('Sesión revocada o caducada', 401, 'PRINCIPAL_REVOKED');
    }
    const state = this._ensureLoaded(false);
    const user = state ? state.users.find((u) => u.id === actor.userId && u.status === 'active') : null;
    const team = state ? state.teams.find((t) => t.id === targetTeamId) : null;
    const member = team && user ? team.members.find((m) => m.userId === user.id) : null;
    if (!user || !team || !member) {
      throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');
    }
    const issued = this._issueSessionForUser(user, team.id, meta);
    this._save();
    return {
      user: this.sanitizeUser(user),
      team: this.sanitizeTeam(team),
      role: member.role,
      sessionToken: issued.token,
      sessionId: issued.sessionId,
      expiresAt: issued.expiresAt
    };
  }

  /**
   * Verifica un token de sesión `cks_<payload>.<sig>` en las 3 capas de revocación:
   *  1) Firma HMAC derivada de `(serverSigningKey, user.tokenKey)` (PocketBase pattern)
   *  2) `payload.tv === user.tokenVersion` y `payload.iat >= user.tokensValidAfter` (Portainer pattern)
   *  3) Presencia activa de `payload.sid` en `user.sessions[]` (revocación individual)
   * @param {string} rawToken
   * @returns {{ ok: boolean, principal?: Principal, reason?: string }}
   */
  verifySessionToken(rawToken) {
    if (typeof rawToken !== 'string' || !rawToken.startsWith('cks_') || rawToken.length > 2048) {
      return { ok: false, reason: 'MALFORMED_SESSION_TOKEN' };
    }
    const state = this._ensureLoaded(false);
    if (!state || state.users.length === 0) {
      return { ok: false, reason: 'MULTIUSER_DISABLED' };
    }

    const body = rawToken.slice(4);
    const dotIdx = body.indexOf('.');
    if (dotIdx <= 0 || body.indexOf('.', dotIdx + 1) !== -1) {
      return { ok: false, reason: 'MALFORMED_SESSION_TOKEN' };
    }
    const encodedPayload = body.slice(0, dotIdx);
    const providedSig = body.slice(dotIdx + 1);
    if (!encodedPayload || !providedSig) {
      return { ok: false, reason: 'MALFORMED_SESSION_TOKEN' };
    }

    /** @type {any} */
    let payload;
    try {
      payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    } catch (e) {
      return { ok: false, reason: 'INVALID_SESSION_PAYLOAD' };
    }

    if (
      !payload ||
      payload.v !== 1 ||
      typeof payload.sid !== 'string' ||
      typeof payload.uid !== 'string' ||
      typeof payload.tid !== 'string' ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number' ||
      typeof payload.tv !== 'number'
    ) {
      return { ok: false, reason: 'INVALID_SESSION_CLAIMS' };
    }

    const now = Date.now();
    if (now >= payload.exp) {
      return { ok: false, reason: 'SESSION_EXPIRED' };
    }

    const user = state.users.find((u) => u.id === payload.uid);
    if (!user || user.status !== 'active') {
      return { ok: false, reason: 'USER_INACTIVE' };
    }

    // Capa 1: Firma con clave derivada de serverSigningKey + user.tokenKey
    let serverKey;
    try {
      serverKey = this._ensureSigningKey();
    } catch (e) {
      return { ok: false, reason: 'SIGNING_KEY_ERROR' };
    }
    const derivedKey = crypto.createHmac('sha256', serverKey).update(`session:v1:${user.tokenKey}`).digest();
    const expectedSig = crypto.createHmac('sha256', derivedKey).update(encodedPayload).digest('base64url');
    if (!safeEqual(providedSig, expectedSig)) {
      return { ok: false, reason: 'INVALID_SIGNATURE' };
    }

    // Capa 2: Versión de token y ventana temporal (role/ACL changes)
    if (payload.tv !== (Number(user.tokenVersion) || 1)) {
      return { ok: false, reason: 'TOKEN_VERSION_REVOKED' };
    }
    if (payload.iat < (Number(user.tokensValidAfter) || 0)) {
      return { ok: false, reason: 'TOKEN_ISSUED_BEFORE_CUTOFF' };
    }

    // Capa 3: Sesión presente y vigente en `user.sessions[]`
    const sess = Array.isArray(user.sessions) ? user.sessions.find((s) => s.sid === payload.sid) : null;
    if (!sess || Date.parse(sess.expiresAt) <= now) {
      return { ok: false, reason: 'SESSION_REVOKED' };
    }

    const team = state.teams.find((t) => t.id === payload.tid);
    const member = team ? team.members.find((m) => m.userId === user.id) : null;
    if (!team || !member) {
      return { ok: false, reason: 'TEAM_MEMBERSHIP_REVOKED' };
    }

    /** @type {Principal} */
    const principal = {
      isSuperAdmin: false,
      kind: 'session',
      userId: user.id,
      email: user.email,
      name: user.name,
      role: member.role,
      teamId: team.id,
      sessionId: payload.sid,
      tokenId: null,
      tokenVersion: Number(user.tokenVersion) || 1,
      projectIds: Array.isArray(member.projectIds) ? [...member.projectIds] : null,
      scopes: null
    };
    return { ok: true, principal };
  }

  /**
   * Cierra una única sesión (`sid`) y emite `principal_revoked`.
   * @param {string} userId
   * @param {string} sessionId
   */
  logoutSession(userId, sessionId) {
    const state = this._ensureLoaded(false);
    if (!state) return { revoked: false };
    const user = state.users.find((u) => u.id === userId);
    if (!user || !Array.isArray(user.sessions)) return { revoked: false };
    const before = user.sessions.length;
    user.sessions = user.sessions.filter((s) => s.sid !== sessionId);
    if (user.sessions.length !== before) {
      this._save();
      this._emitRevoked({ userId, sessionId, reason: 'logout' });
      return { revoked: true };
    }
    return { revoked: false };
  }

  /**
   * Cierra TODAS las sesiones de un usuario rotando `tokenKey` (invalidación instantánea).
   * @param {string} userId
   */
  logoutAll(userId) {
    const state = this._ensureLoaded(false);
    if (!state) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');
    const user = state.users.find((u) => u.id === userId);
    if (!user) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');
    this._rotateUserTokenKey(user);
    this._save();
    this._emitRevoked({ userId, reason: 'logout_all' });
    return { revokedAll: true, userId };
  }

  /**
   * Cambia la contraseña del usuario, rota `tokenKey` (revoca TODAS las sesiones previas)
   * y emite opcionalmente una sesión fresca para el dispositivo actual.
   * @param {string} userId
   * @param {{ currentPassword: string, newPassword: string, issueNewSession?: boolean, teamId?: string, ip?: string, ua?: string }} input
   */
  changePassword(userId, input) {
    const state = this._ensureLoaded(false);
    if (!state) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');
    const user = state.users.find((u) => u.id === userId);
    if (!user || user.status !== 'active') throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');

    const currentPassword = typeof (input && input.currentPassword) === 'string' ? input.currentPassword : '';
    if (!currentPassword || Buffer.byteLength(currentPassword, 'utf8') > MAX_PASSWORD_BYTES || !verifyBcrypt(currentPassword, user.passwordHash)) {
      throw httpError('La contraseña actual no es correcta', 401, 'INVALID_CURRENT_PASSWORD');
    }

    const newPassword = validatePassword(input && input.newPassword);
    user.passwordHash = hashBcrypt(newPassword, this._bcryptCost);
    user.mustRotatePassword = false;
    this._rotateUserTokenKey(user);

    /** @type {{ token: string, sessionId: string, expiresAt: string } | null} */
    let newSession = null;
    if (input && input.issueNewSession) {
      const targetTeamId = input.teamId || DEFAULT_TEAM_ID;
      const member = this._findMember(user.id, targetTeamId);
      if (member) {
        newSession = this._issueSessionForUser(user, targetTeamId, { ip: input.ip, ua: input.ua });
      }
    }

    this._save();
    this._emitRevoked({ userId: user.id, reason: 'password_changed' });

    return {
      changed: true,
      userId: user.id,
      ...(newSession ? { sessionToken: newSession.token, sessionId: newSession.sessionId, expiresAt: newSession.expiresAt } : {})
    };
  }

  /**
   * Deshabilita una cuenta de usuario, rota `tokenKey` y revoca todos sus tokens API.
   * @param {any} actorOrAuth
   * @param {string} targetUserId
   * @param {string} [teamId]
   */
  disableUser(actorOrAuth, targetUserId, teamId = DEFAULT_TEAM_ID) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const state = this._ensureLoaded(false);
    if (!state) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');

    const target = state.users.find((u) => u.id === targetUserId);
    if (!target) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');

    if (!actor.isSuperAdmin) {
      if (actor.userId === targetUserId) {
        throw httpError('No puedes deshabilitar tu propia cuenta', 403, 'SELF_ACTION_FORBIDDEN');
      }
      const actorRole = this.getMemberRole(actor.userId, teamId);
      if (actorRole !== 'owner') {
        throw httpError('Solo un owner puede deshabilitar cuentas', 403, 'OWNER_REQUIRED');
      }
      const targetTeam = state.teams.find((t) => t.id === teamId);
      if (!targetTeam || !targetTeam.members.some((m) => m.userId === targetUserId)) {
        throw httpError('El usuario no pertenece a este equipo', 404, 'MEMBER_NOT_FOUND');
      }
      // Evita deshabilitación global cross-team: salvo owner del workspace por defecto,
      // el actor debe ser owner en TODOS los equipos donde participa el usuario destino.
      const isGlobalOwner = this.getMemberRole(actor.userId, DEFAULT_TEAM_ID) === 'owner';
      if (!isGlobalOwner) {
        const targetTeams = state.teams.filter((t) => t.members.some((m) => m.userId === targetUserId));
        const hasForeignTeam = targetTeams.some((t) => this.getMemberRole(actor.userId, t.id) !== 'owner');
        if (hasForeignTeam) {
          throw httpError(
            'No puedes deshabilitar globalmente una cuenta que pertenece a equipos donde no eres owner; usa removeMember()',
            403,
            'CROSS_TEAM_USER_DISABLE_FORBIDDEN'
          );
        }
      }
    }

    // Guardia de último owner en cualquier equipo al que pertenezca
    for (const team of state.teams) {
      const m = team.members.find((x) => x.userId === targetUserId);
      if (m && m.role === 'owner') {
        const activeOwners = team.members.filter((x) => {
          if (x.role !== 'owner' || x.userId === targetUserId) return false;
          const u = state.users.find((usr) => usr.id === x.userId);
          return Boolean(u && u.status === 'active');
        });
        if (activeOwners.length === 0) {
          throw httpError(`No se puede deshabilitar al último owner activo del equipo "${team.name}"`, 409, 'LAST_OWNER_PROTECTED');
        }
      }
    }

    const nowIso = new Date().toISOString();
    target.status = 'disabled';
    this._rotateUserTokenKey(target);
    for (const tok of state.apiTokens) {
      if (tok.userId === targetUserId && !tok.revokedAt) {
        tok.revokedAt = nowIso;
        tok.revokedReason = 'user_disabled';
      }
    }
    this._save();
    this._emitRevoked({ userId: targetUserId, reason: 'user_disabled' });
    return { disabled: true, user: this.sanitizeUser(target) };
  }

  // ---------------------------------------------------------------------------
  // Equipos y Miembros (techo de rol estricto + protección último owner)
  // ---------------------------------------------------------------------------

  /**
   * Lista los equipos visibles para el llamador (anti-IDOR: jamás filtra equipos ajenos).
   * @param {any} actorOrAuth
   */
  listTeams(actorOrAuth) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const state = this._ensureLoaded(false);
    if (!state) return [];
    if (actor.isSuperAdmin) {
      return state.teams.map((t) => this.sanitizeTeam(t));
    }
    return state.teams
      .filter((t) => t.members.some((m) => m.userId === actor.userId))
      .map((t) => {
        const m = t.members.find((x) => x.userId === actor.userId);
        return {
          ...this.sanitizeTeam(t),
          myRole: m ? m.role : null
        };
      });
  }

  /**
   * Crea un nuevo equipo/workspace (solo `owner` o superadmin).
   * @param {any} actorOrAuth
   * @param {{ name: string, slug?: string, ownerUserId?: string }} input
   */
  createTeam(actorOrAuth, input) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    if (!actor.isSuperAdmin) {
      const check = this.authorizeAction(actor, 'team:transfer'); // owner-level
      if (!check.allowed) {
        throw httpError('Solo un owner puede crear nuevos workspaces', 403, 'OWNER_REQUIRED');
      }
    }
    const state = this._ensureLoaded(true);
    if (!state) throw httpError('Almacenamiento RBAC no disponible', 500, 'RBAC_INIT_ERROR');

    const name = String((input && input.name) || '').trim().slice(0, 80);
    if (!name) throw httpError('El nombre del equipo es obligatorio', 400, 'INVALID_TEAM_NAME');

    const slug = input && input.slug ? String(input.slug).trim().toLowerCase() : slugifyTeamName(name);
    if (!SLUG_RE.test(slug)) {
      throw httpError('Slug de equipo inválido (solo minúsculas, números y guiones)', 400, 'INVALID_TEAM_SLUG');
    }
    if (state.teams.some((t) => t.slug === slug)) {
      throw httpError(`Ya existe un equipo con el slug "${slug}"`, 409, 'TEAM_SLUG_TAKEN');
    }

    const ownerId = (input && input.ownerUserId) || actor.userId;
    if (ownerId && !state.users.some((u) => u.id === ownerId && u.status === 'active')) {
      throw httpError('Usuario owner no encontrado o deshabilitado', 404, 'USER_NOT_FOUND');
    }

    const now = new Date().toISOString();
    const team = {
      id: `team_${crypto.randomBytes(6).toString('hex')}`,
      slug,
      name,
      isDefault: false,
      createdBy: actor.userId || null,
      createdAt: now,
      updatedAt: now,
      members: ownerId
        ? [{ userId: ownerId, role: 'owner', projectIds: null, addedAt: now, addedBy: actor.userId || null }]
        : []
    };
    state.teams.push(team);
    this._save();
    return this.sanitizeTeam(team);
  }

  /**
   * Lista los miembros de un equipo (estrictamente acotado al equipo del llamador).
   * @param {any} actorOrAuth
   * @param {string} [teamId]
   */
  listMembers(actorOrAuth, teamId = DEFAULT_TEAM_ID) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    const authz = this.authorizeAction(actor, 'team:read', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Permiso denegado', authz.status, authz.reason);
    }

    const state = this._ensureLoaded(false);
    const team = state ? state.teams.find((t) => t.id === resolvedTeamId) : null;
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    return team.members.map((m) => {
      const user = state ? state.users.find((u) => u.id === m.userId) : null;
      return {
        userId: m.userId,
        email: user ? user.email : null,
        name: user ? user.name : null,
        status: user ? user.status : 'unknown',
        role: m.role,
        projectIds: Array.isArray(m.projectIds) ? [...m.projectIds] : null,
        addedAt: m.addedAt,
        addedBy: m.addedBy || null
      };
    });
  }

  /**
   * Cambia el rol de un miembro con techo estricto de rol y revocación inmediata.
   * - `admin` SOLO puede gestionar `developer`/`viewer` (nunca `admin` ni `owner`).
   * - Bloquea auto-escalada y degradación del último `owner`.
   * @param {any} actorOrAuth
   * @param {string} teamId
   * @param {string} targetUserId
   * @param {string} newRole
   */
  updateMemberRole(actorOrAuth, teamId, targetUserId, newRole) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    if (!VALID_ROLES.includes(/** @type {any} */ (newRole))) {
      throw httpError(`Rol inválido: ${newRole}`, 400, 'INVALID_ROLE');
    }

    const authz = this.authorizeAction(actor, 'team:write', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para gestionar miembros', authz.status, authz.reason);
    }

    const state = this._ensureLoaded(false);
    const team = state ? state.teams.find((t) => t.id === resolvedTeamId) : null;
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    const targetMember = team.members.find((m) => m.userId === targetUserId);
    if (!targetMember) throw httpError('Miembro no encontrado en el equipo', 404, 'MEMBER_NOT_FOUND');
    const targetUser = state ? state.users.find((u) => u.id === targetUserId) : null;
    if (!targetUser) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');

    if (!actor.isSuperAdmin) {
      // Bloquear auto-modificación / auto-escalada
      if (actor.userId === targetUserId) {
        throw httpError('No puedes cambiar tu propio rol', 403, 'SELF_ESCALATION_BLOCKED');
      }
      const actorRank = roleRank(authz.effectiveRole);
      const currentTargetRank = roleRank(targetMember.role);
      const nextTargetRank = roleRank(newRole);

      // Techo de rol: solo puedes tocar miembros con rango ESTRICTAMENTE inferior y asignar rango ESTRICTAMENTE inferior
      if (currentTargetRank >= actorRank) {
        throw httpError('No puedes modificar a un miembro con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
      if (nextTargetRank >= actorRank) {
        throw httpError(
          newRole === 'owner'
            ? 'La transferencia de ownership requiere transferOwnership()'
            : 'No puedes asignar un rol igual o superior al tuyo',
          403,
          'ROLE_CEILING_EXCEEDED'
        );
      }
    }

    // Guardia de último owner
    if (targetMember.role === 'owner' && newRole !== 'owner') {
      const ownerCount = team.members.filter((m) => m.role === 'owner').length;
      if (ownerCount <= 1) {
        throw httpError('No se puede degradar al último owner del equipo', 409, 'LAST_OWNER_PROTECTED');
      }
    }

    const previousRole = targetMember.role;
    targetMember.role = newRole;
    team.updatedAt = new Date().toISOString();

    // Revocación instantánea de sesiones (capa 2: tokenVersion + tokensValidAfter)
    this._bumpTokenVersion(targetUser);
    this._save();
    this._emitRevoked({ userId: targetUserId, teamId: resolvedTeamId, reason: 'role_changed' });

    return {
      teamId: resolvedTeamId,
      userId: targetUserId,
      previousRole,
      role: newRole,
      sessionsRevoked: true
    };
  }

  /**
   * Actualiza los proyectos permitidos (`projectIds: null | string[]`) de un miembro.
   * @param {any} actorOrAuth
   * @param {string} teamId
   * @param {string} targetUserId
   * @param {string[] | null} rawProjectIds
   */
  updateMemberProjects(actorOrAuth, teamId, targetUserId, rawProjectIds) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    const projectIds = normalizeProjectIds(rawProjectIds);

    const authz = this.authorizeAction(actor, 'team:write', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para modificar ACL de miembros', authz.status, authz.reason);
    }

    const state = this._ensureLoaded(false);
    const team = state ? state.teams.find((t) => t.id === resolvedTeamId) : null;
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    const targetMember = team.members.find((m) => m.userId === targetUserId);
    if (!targetMember) throw httpError('Miembro no encontrado en el equipo', 404, 'MEMBER_NOT_FOUND');
    const targetUser = state ? state.users.find((u) => u.id === targetUserId) : null;
    if (!targetUser) throw httpError('Usuario no encontrado', 404, 'USER_NOT_FOUND');

    if (!actor.isSuperAdmin) {
      if (actor.userId === targetUserId) {
        throw httpError('No puedes ampliar tus propios proyectos permitidos', 403, 'SELF_ESCALATION_BLOCKED');
      }
      if (roleRank(targetMember.role) >= roleRank(authz.effectiveRole)) {
        throw httpError('No puedes modificar el ámbito de un miembro con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
      if (!isProjectSubset(projectIds, actor.projectIds)) {
        throw httpError('No puedes conceder acceso a proyectos fuera de tu propio ámbito', 403, 'PROJECT_SCOPE_EXCEEDED');
      }
    }

    targetMember.projectIds = projectIds;
    team.updatedAt = new Date().toISOString();
    this._bumpTokenVersion(targetUser);
    this._save();
    this._emitRevoked({ userId: targetUserId, teamId: resolvedTeamId, reason: 'acl_changed' });

    return {
      teamId: resolvedTeamId,
      userId: targetUserId,
      projectIds: projectIds ? [...projectIds] : null
    };
  }

  /**
   * Elimina a un miembro de un equipo (respetando techo de rol y último owner).
   * @param {any} actorOrAuth
   * @param {string} teamId
   * @param {string} targetUserId
   */
  removeMember(actorOrAuth, teamId, targetUserId) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;

    const authz = this.authorizeAction(actor, 'team:write', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para eliminar miembros', authz.status, authz.reason);
    }

    const state = this._ensureLoaded(false);
    const team = state ? state.teams.find((t) => t.id === resolvedTeamId) : null;
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    const idx = team.members.findIndex((m) => m.userId === targetUserId);
    if (idx === -1) throw httpError('Miembro no encontrado en el equipo', 404, 'MEMBER_NOT_FOUND');
    const targetMember = team.members[idx];

    if (!actor.isSuperAdmin && actor.userId !== targetUserId) {
      if (roleRank(targetMember.role) >= roleRank(authz.effectiveRole)) {
        throw httpError('No puedes eliminar a un miembro con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
    }

    if (targetMember.role === 'owner') {
      const ownerCount = team.members.filter((m) => m.role === 'owner').length;
      if (ownerCount <= 1) {
        throw httpError('No se puede eliminar al último owner del equipo', 409, 'LAST_OWNER_PROTECTED');
      }
    }

    team.members.splice(idx, 1);
    team.updatedAt = new Date().toISOString();

    // Limpiar ACLs de proyecto en este equipo para el usuario eliminado
    if (state && state.projectAcls) {
      for (const acl of Object.values(state.projectAcls)) {
        if (acl && acl.teamId === resolvedTeamId && acl.overrides && Object.prototype.hasOwnProperty.call(acl.overrides, targetUserId)) {
          delete acl.overrides[targetUserId];
        }
      }
    }

    const targetUser = state ? state.users.find((u) => u.id === targetUserId) : null;
    if (targetUser) {
      if (Array.isArray(targetUser.sessions)) {
        targetUser.sessions = targetUser.sessions.filter((s) => s.teamId !== resolvedTeamId);
      }
      this._bumpTokenVersion(targetUser);
    }

    // Revocar tokens API de ese usuario ligados a este equipo
    const nowIso = new Date().toISOString();
    if (state) {
      for (const tok of state.apiTokens) {
        if (tok.userId === targetUserId && tok.teamId === resolvedTeamId && !tok.revokedAt) {
          tok.revokedAt = nowIso;
          tok.revokedReason = 'member_removed';
        }
      }
    }

    this._save();
    this._emitRevoked({ userId: targetUserId, teamId: resolvedTeamId, reason: 'member_removed' });

    return { removed: true, teamId: resolvedTeamId, userId: targetUserId };
  }

  /**
   * Transferencia explícita de ownership (solo `owner` actual o superadmin; nunca por invitación).
   * @param {any} actorOrAuth
   * @param {string} teamId
   * @param {string} targetUserId
   * @param {{ demoteSelf?: boolean }} [opts]
   */
  transferOwnership(actorOrAuth, teamId, targetUserId, opts = {}) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;

    if (!actor.isSuperAdmin) {
      const authz = this.authorizeAction(actor, 'team:transfer', { teamId: resolvedTeamId });
      if (!authz.allowed || authz.effectiveRole !== 'owner') {
        throw httpError('Solo el owner del equipo puede transferir la propiedad', 403, 'OWNER_REQUIRED');
      }
    }

    const state = this._ensureLoaded(false);
    const team = state ? state.teams.find((t) => t.id === resolvedTeamId) : null;
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    const targetMember = team.members.find((m) => m.userId === targetUserId);
    const targetUser = state ? state.users.find((u) => u.id === targetUserId) : null;
    if (!targetMember || !targetUser || targetUser.status !== 'active') {
      throw httpError('El destinatario debe ser un miembro activo del equipo', 404, 'MEMBER_NOT_FOUND');
    }

    targetMember.role = 'owner';
    targetMember.projectIds = null;
    this._bumpTokenVersion(targetUser);

    if (opts.demoteSelf !== false && actor.userId && actor.userId !== targetUserId) {
      const selfMember = team.members.find((m) => m.userId === actor.userId);
      const selfUser = state ? state.users.find((u) => u.id === actor.userId) : null;
      if (selfMember && selfMember.role === 'owner') {
        selfMember.role = 'admin';
        if (selfUser) this._bumpTokenVersion(selfUser);
      }
    }

    team.updatedAt = new Date().toISOString();
    this._save();
    this._emitRevoked({ userId: targetUserId, teamId: resolvedTeamId, reason: 'ownership_transferred' });
    if (actor.userId && actor.userId !== targetUserId) {
      this._emitRevoked({ userId: actor.userId, teamId: resolvedTeamId, reason: 'ownership_transferred' });
    }

    return { transferred: true, teamId: resolvedTeamId, newOwnerId: targetUserId };
  }

  // ---------------------------------------------------------------------------
  // Invitaciones CSPRNG (`cki_<id8>_<secret32>`) de un solo uso y techo de rol
  // ---------------------------------------------------------------------------

  /**
   * Crea una invitación segura. Devuelve el token en claro UNA SOLA VEZ.
   * En disco solo se guarda `tokenPrefix` + HMAC-SHA256 con clave del servidor.
   * @param {any} actorOrAuth
   * @param {{ teamId?: string, email: string, role: string, projectIds?: string[] | null, ttlHours?: number }} input
   */
  createInvite(actorOrAuth, input) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const teamId = (input && input.teamId) || actor.teamId || DEFAULT_TEAM_ID;

    const authz = this.authorizeAction(actor, 'team:write', { teamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para invitar miembros', authz.status, authz.reason);
    }

    const email = assertValidEmail(input && input.email);
    const role = String((input && input.role) || 'viewer').trim().toLowerCase();

    // Nunca se invita como `owner` (Dokploy GHSA-fm9p-wmpw-gxjh / Coolify CVE-2025-22611)
    if (role === 'owner') {
      throw httpError('No se puede invitar con rol owner; usa transferOwnership()', 403, 'OWNER_INVITE_FORBIDDEN');
    }
    if (!INVITABLE_ROLES.includes(/** @type {any} */ (role))) {
      throw httpError(`Rol de invitación inválido: ${role}`, 400, 'INVALID_ROLE');
    }

    // Bloquear auto-invitación y techo de rol estricto
    if (!actor.isSuperAdmin) {
      if (actor.email && normalizeEmail(actor.email) === email) {
        throw httpError('No puedes invitarte a ti mismo', 403, 'SELF_INVITE_FORBIDDEN');
      }
      const actorRank = roleRank(authz.effectiveRole);
      if (roleRank(role) >= actorRank) {
        throw httpError('No puedes invitar a un rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
    }

    const projectIds = normalizeProjectIds(input && input.projectIds);
    if (!actor.isSuperAdmin && !isProjectSubset(projectIds, actor.projectIds)) {
      throw httpError('No puedes invitar con acceso a proyectos fuera de tu ámbito', 403, 'PROJECT_SCOPE_EXCEEDED');
    }

    const state = this._ensureLoaded(true);
    if (!state) throw httpError('Almacenamiento RBAC no disponible', 500, 'RBAC_INIT_ERROR');
    const team = state.teams.find((t) => t.id === teamId);
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    // Si el correo ya pertenece al equipo, evitar escalada silenciosa por invitación
    const existingUser = state.users.find((u) => u.email === email);
    if (existingUser && team.members.some((m) => m.userId === existingUser.id)) {
      throw httpError('Ese correo ya es miembro de este equipo', 409, 'ALREADY_MEMBER');
    }

    const maxTtl = (state.settings && Number(state.settings.maxInviteTtlHours)) || MAX_INVITE_TTL_HOURS;
    const requestedTtl = input && input.ttlHours !== undefined ? Number(input.ttlHours) : DEFAULT_INVITE_TTL_HOURS;
    if (!Number.isFinite(requestedTtl) || requestedTtl <= 0 || requestedTtl > maxTtl) {
      throw httpError(`El TTL de invitación debe estar entre 1 y ${maxTtl} horas`, 400, 'INVALID_INVITE_TTL');
    }

    const id8 = crypto.randomBytes(4).toString('hex');
    const secret32 = crypto.randomBytes(24).toString('base64url');
    const rawToken = `cki_${id8}_${secret32}`;
    const tokenPrefix = `cki_${id8}`;
    const tokenHash = this._hmacHex('invite', rawToken);

    const nowMs = Date.now();
    const invite = {
      id: `inv_${crypto.randomBytes(6).toString('hex')}`,
      teamId,
      email,
      role,
      projectIds,
      tokenPrefix,
      tokenHash,
      createdBy: actor.userId || 'superadmin',
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + requestedTtl * 3600 * 1000).toISOString(),
      usedAt: null,
      usedBy: null,
      revokedAt: null
    };

    state.invites.push(invite);
    this._save();

    return {
      invite: this.sanitizeInvite(invite),
      inviteToken: rawToken
    };
  }

  /**
   * Lista invitaciones de un equipo (restringido a `owner`/`admin`; tokens enmascarados).
   * @param {any} actorOrAuth
   * @param {string} [teamId]
   */
  listInvites(actorOrAuth, teamId = DEFAULT_TEAM_ID) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    const authz = this.authorizeAction(actor, 'team:write', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Solo owners/admins pueden listar invitaciones', authz.status, authz.reason);
    }
    const state = this._ensureLoaded(false);
    if (!state) return [];
    return state.invites
      .filter((inv) => inv.teamId === resolvedTeamId)
      .map((inv) => this.sanitizeInvite(inv));
  }

  /**
   * Revoca una invitación pendiente.
   * @param {any} actorOrAuth
   * @param {string} teamId
   * @param {string} inviteId
   */
  revokeInvite(actorOrAuth, teamId, inviteId) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    const authz = this.authorizeAction(actor, 'team:write', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para revocar invitaciones', authz.status, authz.reason);
    }
    const state = this._ensureLoaded(false);
    const inv = state ? state.invites.find((i) => i.id === inviteId && i.teamId === resolvedTeamId) : null;
    if (!inv) throw httpError('Invitación no encontrada', 404, 'INVITE_NOT_FOUND');
    if (!inv.revokedAt) {
      inv.revokedAt = new Date().toISOString();
      this._save();
    }
    return { revoked: true, invite: this.sanitizeInvite(inv) };
  }

  /**
   * Acepta una invitación (estrictamente POST, un solo uso, vinculada al email y NUNCA resetea contraseñas).
   * @param {{ token: string, email: string, password?: string, name?: string, ip?: string, ua?: string }} input
   */
  acceptInvite(input) {
    const rawToken = typeof (input && input.token) === 'string' ? input.token.trim() : '';
    const email = assertValidEmail(input && input.email);
    if (!rawToken.startsWith('cki_')) {
      throw httpError('Token de invitación inválido', 401, 'INVALID_INVITE');
    }
    const parts = rawToken.split('_');
    if (parts.length < 3 || parts[1].length !== 8) {
      throw httpError('Token de invitación inválido', 401, 'INVALID_INVITE');
    }
    const prefix = `cki_${parts[1]}`;

    const state = this._ensureLoaded(false);
    if (!state) throw httpError('Invitación inválida o caducada', 401, 'INVALID_INVITE');

    const candidateHash = this._hmacHex('invite', rawToken);
    const invite = state.invites.find((i) => i.tokenPrefix === prefix && safeEqual(i.tokenHash, candidateHash));
    if (!invite) {
      throw httpError('Invitación inválida', 401, 'INVALID_INVITE');
    }
    if (invite.revokedAt) {
      throw httpError('Esta invitación ha sido revocada', 410, 'INVITE_REVOKED');
    }
    if (invite.usedAt) {
      throw httpError('Esta invitación ya fue utilizada', 410, 'INVITE_ALREADY_USED');
    }
    if (Date.now() > Date.parse(invite.expiresAt)) {
      throw httpError('Esta invitación ha caducado', 410, 'INVITE_EXPIRED');
    }
    if (invite.email !== email) {
      throw httpError('El correo electrónico no coincide con la invitación', 403, 'INVITE_EMAIL_MISMATCH');
    }

    const team = state.teams.find((t) => t.id === invite.teamId);
    if (!team) throw httpError('El equipo de la invitación ya no existe', 404, 'TEAM_NOT_FOUND');

    const nowIso = new Date().toISOString();
    let user = state.users.find((u) => u.email === email);
    let createdNewUser = false;

    if (user) {
      // Coolify CVE-2026-34171: una invitación NUNCA resetea contraseñas de usuarios existentes
      if (user.status !== 'active') {
        throw httpError('Esta cuenta está deshabilitada', 403, 'USER_DISABLED');
      }
      if (team.members.some((m) => m.userId === user.id)) {
        throw httpError('Ya eres miembro de este equipo', 409, 'ALREADY_MEMBER');
      }
      // Para cuentas existentes, exige verificar su contraseña actual (nunca sobrescribirla ni emitir sesión sin autenticar)
      const providedPwd = typeof (input && input.password) === 'string' ? input.password : '';
      if (!providedPwd || Buffer.byteLength(providedPwd, 'utf8') > MAX_PASSWORD_BYTES || !verifyBcrypt(providedPwd, user.passwordHash)) {
        throw httpError('Esta cuenta ya existe: introduce tu contraseña actual para unirte al equipo (las invitaciones nunca resetean contraseñas)', 401, 'EXISTING_USER_PASSWORD_REQUIRED');
      }
    } else {
      const password = validatePassword(input && input.password);
      const displayName = String((input && input.name) || email.split('@')[0] || 'Usuario').trim().slice(0, 80);
      user = {
        id: `usr_${crypto.randomBytes(8).toString('hex')}`,
        email,
        name: displayName,
        passwordHash: hashBcrypt(password, this._bcryptCost),
        status: 'active',
        tokenKey: crypto.randomBytes(32).toString('hex'),
        tokenVersion: 1,
        tokensValidAfter: 0,
        mustRotatePassword: false,
        sessions: [],
        createdAt: nowIso,
        updatedAt: nowIso,
        lastLoginAt: nowIso
      };
      state.users.push(user);
      createdNewUser = true;
    }

    // Consumo atómico single-use ANTES de emitir la sesión
    invite.usedAt = nowIso;
    invite.usedBy = user.id;

    team.members.push({
      userId: user.id,
      role: invite.role,
      projectIds: Array.isArray(invite.projectIds) ? [...invite.projectIds] : null,
      addedAt: nowIso,
      addedBy: invite.createdBy
    });
    team.updatedAt = nowIso;
    this._save();

    const issued = this._issueSessionForUser(user, team.id, { ip: input && input.ip, ua: input && input.ua });
    this._save();

    return {
      user: this.sanitizeUser(user),
      team: this.sanitizeTeam(team),
      role: invite.role,
      createdNewUser,
      sessionToken: issued.token,
      sessionId: issued.sessionId,
      expiresAt: issued.expiresAt
    };
  }

  // ---------------------------------------------------------------------------
  // ACLs por Proyecto (`projectAcls`)
  // ---------------------------------------------------------------------------

  /**
   * Establece o actualiza un override ACL en un proyecto para un usuario.
   * @param {any} actorOrAuth
   * @param {string} projectId
   * @param {{ teamId?: string, userId: string, role: 'none' | 'viewer' | 'developer' | 'admin' }} input
   */
  setProjectAcl(actorOrAuth, projectId, input) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    if (!PROJECT_ID_RE.test(String(projectId || ''))) {
      throw httpError('projectId inválido', 400, 'INVALID_PROJECT_ID');
    }
    const teamId = (input && input.teamId) || actor.teamId || DEFAULT_TEAM_ID;
    const targetUserId = String((input && input.userId) || '').trim();
    const aclRole = String((input && input.role) || '').trim().toLowerCase();

    if (!PROJECT_ACL_ROLES.includes(/** @type {any} */ (aclRole))) {
      throw httpError(`Rol ACL de proyecto inválido: ${aclRole}`, 400, 'INVALID_ACL_ROLE');
    }

    const authz = this.authorizeAction(actor, 'projects:acl', { teamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para modificar ACL del proyecto', authz.status, authz.reason);
    }

    const state = this._ensureLoaded(true);
    if (!state) throw httpError('Almacenamiento RBAC no disponible', 500, 'RBAC_INIT_ERROR');
    const team = state.teams.find((t) => t.id === teamId);
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    const targetMember = team.members.find((m) => m.userId === targetUserId);
    const targetUser = state.users.find((u) => u.id === targetUserId);
    if (!targetMember || !targetUser) {
      throw httpError('Usuario no es miembro del equipo', 404, 'MEMBER_NOT_FOUND');
    }

    if (!actor.isSuperAdmin) {
      if (actor.userId === targetUserId) {
        throw httpError('No puedes modificar tu propia ACL de proyecto', 403, 'SELF_ESCALATION_BLOCKED');
      }
      const actorRank = roleRank(authz.effectiveRole);
      if (roleRank(targetMember.role) >= actorRank) {
        throw httpError('No puedes sobrescribir permisos de un miembro con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
      if (aclRole !== 'none' && roleRank(aclRole) >= actorRank) {
        throw httpError('No puedes asignar un rol ACL igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
    }

    if (!state.projectAcls[projectId]) {
      state.projectAcls[projectId] = { teamId, overrides: {} };
    } else if (state.projectAcls[projectId].teamId !== teamId) {
      throw httpError('El proyecto pertenece a otro equipo', 404, 'PROJECT_NOT_FOUND');
    }
    state.projectAcls[projectId].overrides[targetUserId] = aclRole;

    this._bumpTokenVersion(targetUser);
    this._save();
    this._emitRevoked({ userId: targetUserId, teamId, reason: 'acl_changed' });

    return {
      projectId,
      teamId,
      overrides: { ...state.projectAcls[projectId].overrides }
    };
  }

  /**
   * Elimina el override ACL de un usuario en un proyecto.
   * @param {any} actorOrAuth
   * @param {string} projectId
   * @param {string} targetUserId
   * @param {string} [teamId]
   */
  removeProjectAcl(actorOrAuth, projectId, targetUserId, teamId) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const resolvedTeamId = teamId || actor.teamId || DEFAULT_TEAM_ID;
    const authz = this.authorizeAction(actor, 'projects:acl', { teamId: resolvedTeamId });
    if (!authz.allowed) {
      throw httpError(authz.status === 404 ? 'Equipo no encontrado' : 'Sin permisos para modificar ACL del proyecto', authz.status, authz.reason);
    }
    const state = this._ensureLoaded(false);
    if (!state || !state.projectAcls[projectId]) {
      return { projectId, removed: false };
    }
    if (state.projectAcls[projectId].teamId !== resolvedTeamId) {
      throw httpError('Proyecto no encontrado', 404, 'PROJECT_NOT_FOUND');
    }

    const team = state.teams.find((t) => t.id === resolvedTeamId);
    const targetMember = team ? team.members.find((m) => m.userId === targetUserId) : null;
    if (!actor.isSuperAdmin) {
      if (actor.userId === targetUserId) {
        throw httpError('No puedes eliminar tu propia ACL de proyecto', 403, 'SELF_ESCALATION_BLOCKED');
      }
      const actorRank = roleRank(authz.effectiveRole);
      if (targetMember && roleRank(targetMember.role) >= actorRank) {
        throw httpError('No puedes modificar la ACL de un miembro con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
    }

    delete state.projectAcls[projectId].overrides[targetUserId];
    const targetUser = state.users.find((u) => u.id === targetUserId);
    if (targetUser) this._bumpTokenVersion(targetUser);
    this._save();
    this._emitRevoked({ userId: targetUserId, teamId: resolvedTeamId, reason: 'acl_changed' });
    return { projectId, removed: true, overrides: { ...state.projectAcls[projectId].overrides } };
  }

  // ---------------------------------------------------------------------------
  // Tokens API / MCP con Ámbito Dinámico (`ckp_<id8>_<secret32>`)
  // ---------------------------------------------------------------------------

  /**
   * Crea un token API/MCP con ámbito acotado (`ckp_<id8>_<secret32>`).
   * - Guardado únicamente como HMAC con clave del servidor; secreto devuelto UNA vez.
   * - Tope de servidor: jamás puede conceder permisos superiores al rol actual del creador/dueño.
   * @param {any} actorOrAuth
   * @param {{
   *   name: string,
   *   userId?: string,
   *   teamId?: string,
   *   scopes?: string[],
   *   role?: string,
   *   projectIds?: string[] | null,
   *   expiresInDays?: number | null,
   *   expiresAt?: string | null
   * }} input
   */
  createApiToken(actorOrAuth, input) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');

    const state = this._ensureLoaded(true);
    if (!state) throw httpError('Almacenamiento RBAC no disponible', 500, 'RBAC_INIT_ERROR');

    const name = String((input && input.name) || '').trim().slice(0, 80);
    if (!name) throw httpError('El nombre del token es obligatorio', 400, 'INVALID_TOKEN_NAME');

    const teamId = (input && input.teamId) || actor.teamId || DEFAULT_TEAM_ID;
    const team = state.teams.find((t) => t.id === teamId);
    if (!team) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');

    let targetUserId = input && input.userId ? String(input.userId) : actor.userId;
    if (actor.isSuperAdmin && !targetUserId) {
      const firstOwner = team.members.find((m) => m.role === 'owner') || team.members[0];
      if (!firstOwner) {
        throw httpError('Crea primero un usuario owner (bootstrap) antes de emitir tokens con ámbito', 400, 'NO_USERS_IN_TEAM');
      }
      targetUserId = firstOwner.userId;
    }
    if (!targetUserId) {
      throw httpError('userId obligatorio para emitir un token API', 400, 'USER_ID_REQUIRED');
    }

    const targetMember = team.members.find((m) => m.userId === targetUserId);
    const targetUser = state.users.find((u) => u.id === targetUserId);
    if (!targetMember || !targetUser || targetUser.status !== 'active') {
      throw httpError('Usuario destino no activo en el equipo', 404, 'MEMBER_NOT_FOUND');
    }

    // Validar permisos del actor (Dokploy GHSA-6g88-x4hx-9837)
    let callerEffectiveRole = 'owner';
    /** @type {Set<string>} */
    let callerAllowedPerms = new Set(['*', ...ALL_PERMISSIONS]);
    if (!actor.isSuperAdmin) {
      if (actor.kind === 'api_token' && actor.teamId !== teamId) {
        throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');
      }
      const actorLiveRole = this.getMemberRole(actor.userId, teamId);
      if (!actorLiveRole) throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');
      callerEffectiveRole = actorLiveRole;

      // No se puede crear un token para otro usuario salvo admin/owner con techo de rol
      if (actor.userId !== targetUserId) {
        if (!hasMinRole(actorLiveRole, 'admin')) {
          throw httpError('No puedes crear tokens para otros usuarios', 403, 'FORBIDDEN');
        }
        if (roleRank(targetMember.role) >= roleRank(actorLiveRole)) {
          throw httpError('No puedes crear tokens para un usuario con rol igual o superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
        }
      }

      // Calcular permisos efectivos reales del llamador (si llama desde otro token API, intersectar)
      const baseRolePerms = getRolePermissions(actorLiveRole);
      if (actor.kind === 'api_token') {
        const eff = intersectScopesWithRole(actor.scopes || [], actorLiveRole);
        callerAllowedPerms = new Set(eff);
      } else {
        callerAllowedPerms = baseRolePerms;
      }
    }

    // Determinar scopes solicitados (explícitos o a partir de `role`)
    /** @type {string[]} */
    let requestedScopes = [];
    const inputScopes = input && Array.isArray(input.scopes) ? input.scopes : null;
    if (inputScopes && inputScopes.length > 0) {
      requestedScopes = inputScopes.map((s) => String(s || '').trim()).filter(Boolean);
    } else if (input && input.role) {
      const requestedRole = String(input.role).trim().toLowerCase();
      if (!VALID_ROLES.includes(/** @type {any} */ (requestedRole))) {
        throw httpError(`Rol inválido para token: ${requestedRole}`, 400, 'INVALID_ROLE');
      }
      if (!actor.isSuperAdmin && roleRank(requestedRole) > roleRank(callerEffectiveRole)) {
        throw httpError('No puedes crear un token con un rol superior al tuyo', 403, 'ROLE_CEILING_EXCEEDED');
      }
      requestedScopes = requestedRole === 'owner' ? ['*'] : Array.from(ROLE_PERMISSIONS[requestedRole]);
    } else {
      throw httpError('Debes especificar al menos un scope para el token API', 400, 'SCOPES_REQUIRED');
    }

    // Validar que cada scope existe y está permitido para el creador Y el dueño del token
    const targetRolePerms = ROLE_PERMISSIONS[targetMember.role];
    const callerIsOwner = actor.isSuperAdmin || callerEffectiveRole === 'owner';

    for (const sc of requestedScopes) {
      if (sc === '*') {
        if (!callerIsOwner || targetMember.role !== 'owner') {
          throw httpError('El comodín "*" solo está permitido para tokens de owner', 403, 'SCOPE_EXCEEDS_ROLE');
        }
        continue;
      }
      if (!ALL_PERMISSIONS_SET.has(sc)) {
        throw httpError(`Permiso/scope desconocido: ${sc}`, 400, 'UNKNOWN_SCOPE');
      }
      if (!actor.isSuperAdmin && !callerAllowedPerms.has('*') && !callerAllowedPerms.has(sc)) {
        throw httpError(`No puedes conceder el permiso "${sc}" porque excede tus permisos actuales`, 403, 'SCOPE_EXCEEDS_CALLER');
      }
      if (!targetRolePerms.has('*') && !targetRolePerms.has(sc)) {
        throw httpError(`El permiso "${sc}" excede el rol actual (${targetMember.role}) del usuario destino`, 403, 'SCOPE_EXCEEDS_ROLE');
      }
    }

    const projectIds = normalizeProjectIds(input && input.projectIds);
    if (!actor.isSuperAdmin && !isProjectSubset(projectIds, actor.projectIds)) {
      throw httpError('No puedes crear un token con proyectos fuera de tu ámbito', 403, 'PROJECT_SCOPE_EXCEEDED');
    }
    if (!isProjectSubset(projectIds, targetMember.projectIds)) {
      throw httpError('Los proyectos del token exceden el ámbito del usuario destino', 403, 'PROJECT_SCOPE_EXCEEDED');
    }

    /** @type {string | null} */
    let expiresAtIso = null;
    if (input && input.expiresInDays !== undefined && input.expiresInDays !== null) {
      const days = Number(input.expiresInDays);
      if (!Number.isFinite(days) || days <= 0 || days > 3650) {
        throw httpError('expiresInDays debe ser un número entre 1 y 3650', 400, 'INVALID_EXPIRY');
      }
      expiresAtIso = new Date(Date.now() + days * 86400 * 1000).toISOString();
    } else if (input && input.expiresAt) {
      const ts = Date.parse(String(input.expiresAt));
      if (!Number.isFinite(ts) || ts <= Date.now()) {
        throw httpError('expiresAt debe ser una fecha futura válida', 400, 'INVALID_EXPIRY');
      }
      expiresAtIso = new Date(ts).toISOString();
    }

    const id8 = crypto.randomBytes(4).toString('hex');
    const secret32 = crypto.randomBytes(24).toString('base64url');
    const rawToken = `ckp_${id8}_${secret32}`;
    const tokenPrefix = `ckp_${id8}`;
    const tokenHash = this._hmacHex('apitoken', rawToken);

    const record = {
      id: `tok_${crypto.randomBytes(6).toString('hex')}`,
      name,
      userId: targetUserId,
      teamId,
      tokenPrefix,
      tokenHash,
      scopes: Array.from(new Set(requestedScopes)),
      projectIds,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAtIso,
      lastUsedAt: null,
      lastUsedIp: null,
      revokedAt: null,
      revokedReason: null
    };

    state.apiTokens.push(record);
    this._save();

    return {
      tokenRecord: this.sanitizeApiToken(record),
      token: rawToken
    };
  }

  /**
   * Lista los tokens API visibles para el llamador (nunca expone hashes ni secretos).
   * @param {any} actorOrAuth
   * @param {{ teamId?: string }} [opts]
   */
  listApiTokens(actorOrAuth, opts = {}) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const state = this._ensureLoaded(false);
    if (!state) return [];

    if (actor.isSuperAdmin) {
      const list = opts.teamId ? state.apiTokens.filter((t) => t.teamId === opts.teamId) : state.apiTokens;
      return list.map((t) => this.sanitizeApiToken(t));
    }

    const teamId = opts.teamId || actor.teamId;
    if (teamId !== actor.teamId) {
      throw httpError('Equipo no encontrado', 404, 'TEAM_NOT_FOUND');
    }
    const role = this.getMemberRole(actor.userId, teamId);
    const canSeeAllTeam = hasMinRole(role, 'admin');
    return state.apiTokens
      .filter((t) => t.teamId === teamId && (canSeeAllTeam || t.userId === actor.userId))
      .map((t) => this.sanitizeApiToken(t));
  }

  /**
   * Revoca un token API/MCP y emite `principal_revoked` de inmediato.
   * @param {any} actorOrAuth
   * @param {string} tokenId
   */
  revokeApiToken(actorOrAuth, tokenId) {
    const actor = unwrapPrincipal(actorOrAuth);
    if (!actor) throw httpError('Autenticación requerida', 401, 'UNAUTHENTICATED');
    const state = this._ensureLoaded(false);
    const tok = state ? state.apiTokens.find((t) => t.id === tokenId) : null;
    if (!tok) throw httpError('Token API no encontrado', 404, 'TOKEN_NOT_FOUND');

    if (!actor.isSuperAdmin) {
      if (tok.teamId !== actor.teamId) {
        throw httpError('Token API no encontrado', 404, 'TOKEN_NOT_FOUND');
      }
      if (tok.userId !== actor.userId) {
        const actorRole = this.getMemberRole(actor.userId, tok.teamId);
        const ownerRole = this.getMemberRole(tok.userId, tok.teamId);
        if (!hasMinRole(actorRole, 'admin') || (ownerRole && roleRank(ownerRole) >= roleRank(actorRole))) {
          throw httpError('Sin permisos para revocar este token', 403, 'FORBIDDEN');
        }
      }
    }

    if (!tok.revokedAt) {
      tok.revokedAt = new Date().toISOString();
      tok.revokedReason = 'revoked_by_actor';
      this._save();
      this._emitRevoked({ userId: tok.userId, tokenId: tok.id, teamId: tok.teamId, reason: 'token_revoked' });
    }
    return { revoked: true, tokenRecord: this.sanitizeApiToken(tok) };
  }

  /**
   * Verifica un token API/MCP (`ckp_<id8>_<secret32>`) y calcula dinámicamente:
   *  `effectiveScopes = intersection(token.scopes, currentRolePerms(user, team))`
   *  `effectiveProjectIds = intersection(token.projectIds, member.projectIds)`
   * @param {string} rawToken
   * @param {{ ip?: string }} [meta]
   * @returns {{ ok: boolean, principal?: Principal, reason?: string }}
   */
  verifyApiToken(rawToken, meta = {}) {
    if (typeof rawToken !== 'string' || !rawToken.startsWith('ckp_') || rawToken.length > 512) {
      return { ok: false, reason: 'MALFORMED_API_TOKEN' };
    }
    const parts = rawToken.split('_');
    if (parts.length < 3 || parts[1].length !== 8) {
      return { ok: false, reason: 'MALFORMED_API_TOKEN' };
    }
    const prefix = `ckp_${parts[1]}`;

    const state = this._ensureLoaded(false);
    if (!state || state.apiTokens.length === 0) {
      return { ok: false, reason: 'TOKEN_NOT_FOUND' };
    }

    let candidateHash;
    try {
      candidateHash = this._hmacHex('apitoken', rawToken);
    } catch (e) {
      return { ok: false, reason: 'SIGNING_KEY_ERROR' };
    }

    const tok = state.apiTokens.find((t) => t.tokenPrefix === prefix && safeEqual(t.tokenHash, candidateHash));
    if (!tok) {
      return { ok: false, reason: 'INVALID_API_TOKEN' };
    }
    if (tok.revokedAt) {
      return { ok: false, reason: 'TOKEN_REVOKED' };
    }
    if (tok.expiresAt && Date.now() >= Date.parse(tok.expiresAt)) {
      return { ok: false, reason: 'TOKEN_EXPIRED' };
    }

    const user = state.users.find((u) => u.id === tok.userId);
    if (!user || user.status !== 'active') {
      return { ok: false, reason: 'USER_INACTIVE' };
    }
    const team = state.teams.find((t) => t.id === tok.teamId);
    const member = team ? team.members.find((m) => m.userId === user.id) : null;
    if (!team || !member) {
      return { ok: false, reason: 'TEAM_MEMBERSHIP_REVOKED' };
    }

    // Recorte dinámico en caliente: si el usuario fue degradado, el token pierde permisos al instante
    const effectiveScopes = intersectScopesWithRole(tok.scopes, member.role);
    const effectiveProjectIds = intersectProjectIds(tok.projectIds, member.projectIds);
    const wasClamped = !tok.scopes.includes('*') && effectiveScopes.length < tok.scopes.length;

    const nowMs = Date.now();
    tok.lastUsedAt = new Date(nowMs).toISOString();
    if (meta && meta.ip) tok.lastUsedIp = String(meta.ip).slice(0, 64);
    if (nowMs - this._lastTokenTouchFlush > 30000) {
      this._lastTokenTouchFlush = nowMs;
      try { this._save(); } catch (e) {}
    }

    /** @type {Principal} */
    const principal = {
      isSuperAdmin: false,
      kind: 'api_token',
      userId: user.id,
      email: user.email,
      name: user.name,
      role: member.role,
      teamId: team.id,
      sessionId: null,
      tokenId: tok.id,
      tokenName: tok.name,
      tokenVersion: Number(user.tokenVersion) || 1,
      projectIds: effectiveProjectIds,
      scopes: effectiveScopes,
      requestedScopes: [...tok.scopes],
      clamped: wasClamped
    };
    return { ok: true, principal };
  }

  /**
   * Discrimina y verifica cualquier credencial gestionada (`cks_` o `ckp_`).
   * @param {string} rawToken
   * @param {{ ip?: string }} [meta]
   */
  verifyCredential(rawToken, meta = {}) {
    if (typeof rawToken !== 'string') return { ok: false, reason: 'INVALID_CREDENTIAL' };
    if (rawToken.startsWith('cks_')) {
      const res = this.verifySessionToken(rawToken);
      return res.ok ? { ok: true, method: 'session', principal: res.principal } : res;
    }
    if (rawToken.startsWith('ckp_')) {
      const res = this.verifyApiToken(rawToken, meta);
      return res.ok ? { ok: true, method: 'api_token', principal: res.principal } : res;
    }
    return { ok: false, reason: 'UNKNOWN_PREFIX' };
  }

  /**
   * Comprueba en vivo si un principal (p. ej. asociado a un ticket WS) sigue vigente.
   * @param {any} principalOrAuth
   * @returns {boolean}
   */
  isPrincipalStillValid(principalOrAuth) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) return false;
    if (principal.isSuperAdmin) return true;

    const state = this._ensureLoaded(false);
    if (!state) return false;

    const user = state.users.find((u) => u.id === principal.userId);
    if (!user || user.status !== 'active') return false;

    const team = state.teams.find((t) => t.id === principal.teamId);
    const member = team ? team.members.find((m) => m.userId === user.id) : null;
    if (!team || !member) return false;

    if (principal.kind === 'session') {
      if (principal.tokenVersion !== undefined && principal.tokenVersion !== (Number(user.tokenVersion) || 1)) {
        return false;
      }
      const now = Date.now();
      const sess = Array.isArray(user.sessions) ? user.sessions.find((s) => s.sid === principal.sessionId) : null;
      return Boolean(sess && Date.parse(sess.expiresAt) > now);
    }

    if (principal.kind === 'api_token') {
      const tok = state.apiTokens.find((t) => t.id === principal.tokenId);
      if (!tok || tok.revokedAt) return false;
      if (tok.expiresAt && Date.now() >= Date.parse(tok.expiresAt)) return false;
      return true;
    }

    return false;
  }

  // ---------------------------------------------------------------------------
  // Motor Central de Autorización, Filtrado y Redacción de Secretos
  // ---------------------------------------------------------------------------

  /**
   * Resuelve el rol efectivo del principal sobre un proyecto concreto.
   * @param {any} principalOrAuth
   * @param {{ id: string, teamId?: string } | string} projectOrId
   * @returns {'owner' | 'admin' | 'developer' | 'viewer' | null}
   */
  resolveProjectRole(principalOrAuth, projectOrId) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) return null;
    if (principal.isSuperAdmin) return 'owner';

    const projectId = typeof projectOrId === 'string' ? projectOrId : String((projectOrId && projectOrId.id) || '');
    if (!projectId) return null;

    const state = this._ensureLoaded(false);
    if (!state) return null;

    const user = state.users.find((u) => u.id === principal.userId);
    if (!user || user.status !== 'active') return null;

    const aclEntry = state.projectAcls ? state.projectAcls[projectId] : null;
    const projectTeamId = (typeof projectOrId === 'object' && projectOrId && projectOrId.teamId) ||
      (aclEntry && aclEntry.teamId) ||
      DEFAULT_TEAM_ID;

    // Aislamiento estricto multi-tenant: bloquea IDOR entre equipos
    if (principal.teamId !== projectTeamId) return null;

    const team = state.teams.find((t) => t.id === projectTeamId);
    const member = team ? team.members.find((m) => m.userId === user.id) : null;
    if (!team || !member) return null;

    // Restricción por lista blanca `projectIds` (tanto del token como de la membresía viva)
    let tokenProjectIds = principal.projectIds;
    if (principal.kind === 'api_token' && principal.tokenId) {
      const liveTok = state.apiTokens.find((t) => t.id === principal.tokenId);
      if (!liveTok || liveTok.revokedAt || (liveTok.expiresAt && Date.now() >= Date.parse(liveTok.expiresAt))) {
        return null;
      }
      tokenProjectIds = liveTok.projectIds;
    }
    const effectiveProjectIds = intersectProjectIds(tokenProjectIds, member.projectIds);
    if (Array.isArray(effectiveProjectIds) && !effectiveProjectIds.includes(projectId)) {
      return null;
    }

    // Override ACL explícito por proyecto ('none' gana siempre al rol del equipo)
    if (aclEntry && aclEntry.overrides && Object.prototype.hasOwnProperty.call(aclEntry.overrides, user.id)) {
      const ov = aclEntry.overrides[user.id];
      if (ov === 'none') return null;
      if (VALID_ROLES.includes(/** @type {any} */ (ov))) {
        return /** @type {'owner' | 'admin' | 'developer' | 'viewer'} */ (ov);
      }
    }

    return member.role;
  }

  /**
   * Comprueba si un rol (y scopes opcionales de token API) concede `perm`.
   * @param {Principal} principal
   * @param {string} effectiveRole
   * @param {string} perm
   */
  _roleAndTokenAllowPerm(principal, effectiveRole, perm) {
    const rolePerms = ROLE_PERMISSIONS[effectiveRole];
    if (!rolePerms) return false;
    const roleAllows = rolePerms.has('*') || rolePerms.has(perm);
    if (!roleAllows) return false;

    if (principal.kind === 'api_token') {
      // Intersección dinámica siempre contra los scopes almacenados en vivo si existe el token
      let rawScopes = principal.scopes;
      if (principal.tokenId) {
        const state = this._ensureLoaded(false);
        const liveTok = state ? state.apiTokens.find((t) => t.id === principal.tokenId) : null;
        if (!liveTok || liveTok.revokedAt || (liveTok.expiresAt && Date.now() >= Date.parse(liveTok.expiresAt))) {
          return false;
        }
        rawScopes = liveTok.scopes;
      }
      const effScopes = intersectScopesWithRole(rawScopes || [], effectiveRole);
      return effScopes.includes('*') || effScopes.includes(perm);
    }

    return true;
  }

  /**
   * Autorización centralizada de cualquier acción RBAC.
   * @param {any} principalOrAuth
   * @param {string} perm
   * @param {{ teamId?: string, projectId?: string, project?: any }} [ctx]
   * @returns {{ allowed: boolean, status: number, reason: string, effectiveRole: string | null }}
   */
  authorizeAction(principalOrAuth, perm, ctx = {}) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) {
      return { allowed: false, status: 401, reason: 'UNAUTHENTICATED', effectiveRole: null };
    }
    if (principal.isSuperAdmin) {
      return { allowed: true, status: 200, reason: 'SUPERADMIN', effectiveRole: 'owner' };
    }

    if (!this.isPrincipalStillValid(principal)) {
      return { allowed: false, status: 401, reason: 'PRINCIPAL_REVOKED', effectiveRole: null };
    }

    if (ctx && (ctx.project || ctx.projectId)) {
      const pid = ctx.projectId || (ctx.project && ctx.project.id);
      return this.authorizeProject(principal, pid, perm, ctx.project || null);
    }

    const targetTeamId = (ctx && ctx.teamId) || principal.teamId;
    if (principal.kind === 'api_token' && targetTeamId && principal.teamId && targetTeamId !== principal.teamId) {
      return { allowed: false, status: 404, reason: 'CROSS_TEAM_DENIED', effectiveRole: null };
    }

    const liveRole = this.getMemberRole(principal.userId, targetTeamId);
    if (!liveRole) {
      const crossTeam = Boolean(targetTeamId && principal.teamId && targetTeamId !== principal.teamId);
      return { allowed: false, status: crossTeam ? 404 : 403, reason: crossTeam ? 'CROSS_TEAM_DENIED' : 'NO_MEMBERSHIP', effectiveRole: null };
    }

    if (!this._roleAndTokenAllowPerm(principal, liveRole, perm)) {
      return { allowed: false, status: 403, reason: 'FORBIDDEN', effectiveRole: liveRole };
    }

    return { allowed: true, status: 200, reason: 'OK', effectiveRole: liveRole };
  }

  /**
   * Autorización centralizada sobre un proyecto (404 anti-oráculo si pertenece a otro equipo o es invisible; 403 si es visible pero falta permiso).
   * @param {any} principalOrAuth
   * @param {string} projectId
   * @param {string} [perm]
   * @param {any} [projectObj]
   * @returns {{ allowed: boolean, status: number, reason: string, effectiveRole: string | null }}
   */
  authorizeProject(principalOrAuth, projectId, perm = 'projects:read', projectObj = null) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) {
      return { allowed: false, status: 401, reason: 'UNAUTHENTICATED', effectiveRole: null };
    }
    if (principal.isSuperAdmin) {
      return { allowed: true, status: 200, reason: 'SUPERADMIN', effectiveRole: 'owner' };
    }
    if (!this.isPrincipalStillValid(principal)) {
      return { allowed: false, status: 401, reason: 'PRINCIPAL_REVOKED', effectiveRole: null };
    }

    const ref = projectObj && typeof projectObj === 'object'
      ? { id: projectId || projectObj.id, teamId: projectObj.teamId }
      : { id: projectId };
    const effectiveRole = this.resolveProjectRole(principal, ref);
    if (!effectiveRole) {
      // 404 evita enumerar IDs de proyectos de otros equipos o fuera de tu ACL
      return { allowed: false, status: 404, reason: 'PROJECT_NOT_FOUND', effectiveRole: null };
    }

    if (!this._roleAndTokenAllowPerm(principal, effectiveRole, perm)) {
      return { allowed: false, status: 403, reason: 'FORBIDDEN', effectiveRole };
    }

    return { allowed: true, status: 200, reason: 'OK', effectiveRole };
  }

  /**
   * Verificación dual para operaciones entre dos recursos (p. ej. cloneTo/moveTo, enlazar BD).
   * Cierra Coolify CVE-2026-34037 (autorizar origen pero olvidar destino).
   * @param {any} principalOrAuth
   * @param {any} sourceProject
   * @param {any} targetProject
   * @param {string} [sourcePerm]
   * @param {string} [targetPerm]
   */
  authorizeDualProjectAction(principalOrAuth, sourceProject, targetProject, sourcePerm = 'projects:read', targetPerm = 'projects:write') {
    const src = this.authorizeProject(principalOrAuth, sourceProject && sourceProject.id, sourcePerm, sourceProject);
    if (!src.allowed) return src;
    const dst = this.authorizeProject(principalOrAuth, targetProject && targetProject.id, targetPerm, targetProject);
    if (!dst.allowed) return dst;
    return { allowed: true, status: 200, reason: 'OK', effectiveRole: dst.effectiveRole };
  }

  /**
   * Atajo booleano para MCP (`mcpServer.js` / `mcpStreamableHttp.js`).
   * @param {any} principalOrAuth
   * @param {string} perm
   * @param {{ teamId?: string, projectId?: string, project?: any }} [ctx]
   */
  canAccess(principalOrAuth, perm, ctx = {}) {
    return this.authorizeAction(principalOrAuth, perm, ctx).allowed;
  }

  /**
   * Filtra una lista de proyectos al conjunto visible para `principal` y redacta secretos
   * automáticamente para `viewer` o tokens sin `secrets:read`.
   * @param {any} principalOrAuth
   * @param {any[]} projectsList
   * @param {{ redact?: boolean }} [opts]
   */
  filterProjects(principalOrAuth, projectsList, opts = {}) {
    if (!Array.isArray(projectsList)) return [];
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) return [];
    if (principal.isSuperAdmin) return projectsList;

    const shouldRedact = opts.redact !== false;
    /** @type {any[]} */
    const out = [];
    for (const proj of projectsList) {
      if (!proj || !proj.id) continue;
      const check = this.authorizeProject(principal, proj.id, 'projects:read', proj);
      if (!check.allowed) continue;
      out.push(shouldRedact ? this.redactProjectForPrincipal(principal, proj) : proj);
    }
    return out;
  }

  /**
   * Oculta `envVars`, `buildArgs`, `webhookSecret`, `deployHookToken` y secretos
   * cuando el principal no tiene `secrets:read` sobre el proyecto (p. ej. `viewer`).
   * Nunca muta el objeto original en memoria.
   * @param {any} principalOrAuth
   * @param {any} proj
   */
  redactProjectForPrincipal(principalOrAuth, proj) {
    if (!proj || typeof proj !== 'object') return proj;
    const principal = unwrapPrincipal(principalOrAuth);
    if (principal && principal.isSuperAdmin) return proj;

    const canSeeSecrets = Boolean(
      principal && this.authorizeProject(principal, proj.id, 'secrets:read', proj).allowed
    );
    if (canSeeSecrets) return proj;

    const copy = { ...proj };
    if (copy.envVars && typeof copy.envVars === 'object' && !Array.isArray(copy.envVars)) {
      /** @type {Record<string, string>} */
      const maskedEnv = {};
      for (const key of Object.keys(copy.envVars)) {
        maskedEnv[key] = '[REDACTED]';
      }
      copy.envVars = maskedEnv;
    }
    if (copy.buildArgs && typeof copy.buildArgs === 'object' && !Array.isArray(copy.buildArgs)) {
      /** @type {Record<string, string>} */
      const maskedArgs = {};
      for (const key of Object.keys(copy.buildArgs)) {
        maskedArgs[key] = '[REDACTED]';
      }
      copy.buildArgs = maskedArgs;
    }
    if (copy.webhookSecret) copy.webhookSecret = '[REDACTED]';
    if (copy.deployHookToken) copy.deployHookToken = '[REDACTED]';
    if (copy.secrets && typeof copy.secrets === 'object') {
      /** @type {Record<string, string>} */
      const maskedSec = {};
      for (const key of Object.keys(copy.secrets)) {
        maskedSec[key] = '[REDACTED]';
      }
      copy.secrets = maskedSec;
    }
    copy._secretsRedacted = true;
    return copy;
  }

  /**
   * Evalúa si el principal cumple un rol mínimo (`owner(40) > admin(30) > developer(20) > viewer(10)`).
   * Para tokens API/MCP (`ckp_`), además verifica que los `effectiveScopes` vivos del token
   * cubran por completo los permisos de `minRole` (evita que un token `projects:read` de un owner pase `requireRole('admin'|'owner')`).
   * @param {any} principalOrAuth
   * @param {'viewer' | 'developer' | 'admin' | 'owner'} minRole
   * @param {string} [teamId]
   * @returns {{ allowed: boolean, status: number, reason: string, effectiveRole: string | null }}
   */
  doesPrincipalSatisfyRole(principalOrAuth, minRole, teamId) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) {
      return { allowed: false, status: 401, reason: 'UNAUTHENTICATED', effectiveRole: null };
    }
    const needed = roleRank(minRole);
    if (needed <= 0) {
      return { allowed: false, status: 403, reason: 'UNKNOWN_ROLE', effectiveRole: null };
    }
    if (principal.isSuperAdmin) {
      return { allowed: true, status: 200, reason: 'SUPERADMIN', effectiveRole: 'owner' };
    }
    if (!this.isPrincipalStillValid(principal)) {
      return { allowed: false, status: 401, reason: 'PRINCIPAL_REVOKED', effectiveRole: null };
    }

    const targetTeamId = teamId || principal.teamId;
    if (principal.kind === 'api_token' && targetTeamId && principal.teamId && targetTeamId !== principal.teamId) {
      return { allowed: false, status: 404, reason: 'CROSS_TEAM_DENIED', effectiveRole: null };
    }

    const liveRole = this.getMemberRole(principal.userId, targetTeamId);
    if (!liveRole) {
      const crossTeam = Boolean(targetTeamId && principal.teamId && targetTeamId !== principal.teamId);
      return {
        allowed: false,
        status: crossTeam ? 404 : 403,
        reason: crossTeam ? 'CROSS_TEAM_DENIED' : 'INSUFFICIENT_ROLE',
        effectiveRole: null
      };
    }

    if (roleRank(liveRole) < needed) {
      return { allowed: false, status: 403, reason: 'INSUFFICIENT_ROLE', effectiveRole: liveRole };
    }

    if (principal.kind === 'api_token') {
      const state = this._ensureLoaded(false);
      const liveTok = state && principal.tokenId ? state.apiTokens.find((t) => t.id === principal.tokenId) : null;
      if (!liveTok || liveTok.revokedAt || (liveTok.expiresAt && Date.now() >= Date.parse(liveTok.expiresAt))) {
        return { allowed: false, status: 401, reason: 'TOKEN_REVOKED', effectiveRole: null };
      }
      const effScopes = intersectScopesWithRole(liveTok.scopes, liveRole);
      if (effScopes.includes('*')) {
        return { allowed: true, status: 200, reason: 'OK', effectiveRole: liveRole };
      }
      if (minRole === 'owner') {
        return { allowed: false, status: 403, reason: 'TOKEN_SCOPES_INSUFFICIENT_FOR_ROLE', effectiveRole: liveRole };
      }
      const requiredPerms = ROLE_PERMISSIONS[minRole];
      const effSet = new Set(effScopes);
      for (const perm of requiredPerms) {
        if (perm !== '*' && !effSet.has(perm)) {
          return { allowed: false, status: 403, reason: 'TOKEN_SCOPES_INSUFFICIENT_FOR_ROLE', effectiveRole: liveRole };
        }
      }
    }

    return { allowed: true, status: 200, reason: 'OK', effectiveRole: liveRole };
  }

  /**
   * Política por defecto (default-deny) para rutas HTTP `/api/*` cuando el llamador no es superadmin.
   * Bloquea:
   *  - Rutas de host/instancia para `developer` y `viewer` (Portainer CVE-2026-44848)
   *  - Mutaciones `/vault`, `/servers`, `/gitops`, `/catalog`, `/deploy/freeze-windows` y rutas no mapeadas (fail-closed)
   *  - Acciones de sesión (`logout`/`logout-all`/`password`) para tokens API (`ckp_`)
   *  - Rutas de credenciales/secretos/exec y toda mutación para `viewer`
   * @param {any} principalOrAuth
   * @param {string} method
   * @param {string} pathname
   */
  authorizeHttpRoute(principalOrAuth, method, pathname) {
    const principal = unwrapPrincipal(principalOrAuth);
    if (!principal) {
      return { allowed: false, status: 401, reason: 'UNAUTHENTICATED', effectiveRole: null };
    }
    if (principal.isSuperAdmin) {
      return { allowed: true, status: 200, reason: 'SUPERADMIN', effectiveRole: 'owner' };
    }

    const m = String(method || 'GET').toUpperCase();
    const p = String(pathname || '/');
    const isRead = m === 'GET' || m === 'HEAD' || m === 'OPTIONS';

    // Consulta propia y emisión de ticket WS permitidas para sesión o token válido
    if (p === '/api/auth/me' || p === '/api/auth/session' || p === '/api/auth/ws-ticket') {
      if (!this.isPrincipalStillValid(principal)) {
        return { allowed: false, status: 401, reason: 'PRINCIPAL_REVOKED', effectiveRole: null };
      }
      return { allowed: true, status: 200, reason: 'SELF_AUTH_ROUTE', effectiveRole: principal.role };
    }

    // Gestión de contraseña / sesiones: estrictamente `session` (nunca un token API `ckp_`)
    if (p === '/api/auth/logout' || p === '/api/auth/logout-all' || p === '/api/auth/password') {
      if (!this.isPrincipalStillValid(principal)) {
        return { allowed: false, status: 401, reason: 'PRINCIPAL_REVOKED', effectiveRole: null };
      }
      if (principal.kind !== 'session') {
        return { allowed: false, status: 403, reason: 'SESSION_REQUIRED', effectiveRole: principal.role };
      }
      return { allowed: true, status: 200, reason: 'SELF_AUTH_ROUTE', effectiveRole: principal.role };
    }

    // Rutas críticas de host/instancia -> estrictamente `owner` (bloqueadas para developer, viewer y admin)
    if (
      p === '/api/auth/rotate' ||
      p.startsWith('/api/docker') ||
      p.startsWith('/api/ssl') ||
      p.startsWith('/api/cloudflare') ||
      p.startsWith('/api/backup/instance') ||
      p === '/api/system/panel-domain' ||
      p.startsWith('/api/fleet/keys') ||
      (!isRead && p.startsWith('/api/system')) ||
      (!isRead && p.startsWith('/api/ingress')) ||
      (!isRead && (p.startsWith('/api/deploy/freeze-windows') || p.includes('/freeze-windows')))
    ) {
      const permMap = p === '/api/auth/rotate'
        ? 'auth:rotate'
        : p.startsWith('/api/docker')
          ? 'docker:write'
          : p.startsWith('/api/ssl')
            ? 'ssl:write'
            : p.startsWith('/api/cloudflare')
              ? 'cloudflare:write'
              : p.startsWith('/api/backup/instance')
                ? 'backup:instance'
                : p.startsWith('/api/ingress')
                  ? 'ingress:write'
                  : p.startsWith('/api/fleet/keys')
                    ? 'fleet:ssh'
                    : 'system:write';
      return this.authorizeAction(principal, permMap);
    }

    // Vault cifrado: lectura -> `secrets:read`; mutación -> `environments:write` (nunca solo `secrets:read`!)
    if (/\/vault(?:\/|$)/.test(p)) {
      return this.authorizeAction(principal, isRead ? 'secrets:read' : 'environments:write');
    }

    // Rutas de secretos / credenciales / exec -> bloqueadas para `viewer` y tokens solo-lectura en mutaciones
    if (/\/credentials(?:\/|$)/.test(p) || /\/secrets(?:\/|$)/.test(p)) {
      return this.authorizeAction(principal, isRead ? 'secrets:read' : 'projects:write');
    }
    if (/\/runtime\/exec(?:\/|$)/.test(p)) {
      return this.authorizeAction(principal, 'runtime:exec');
    }

    // Auditoría -> `audit:read` (admin/owner)
    if (p.startsWith('/api/audit')) {
      return this.authorizeAction(principal, 'audit:read');
    }

    // Multi-Server Fleet (SSH nodes) -> lectura `fleet:read`, escritura `fleet:write` (admin/owner)
    if (p.startsWith('/api/servers') || p.startsWith('/api/fleet')) {
      return this.authorizeAction(principal, isRead ? 'fleet:read' : 'fleet:write');
    }

    // GitOps declarativo -> lectura `gitops:read`, plan/apply `gitops:write` (admin/owner)
    if (p.startsWith('/api/gitops')) {
      return this.authorizeAction(principal, isRead ? 'gitops:read' : 'gitops:write');
    }

    // Catálogo 1-clic -> lectura `catalog:read`, instalar/borrar `catalog:write` (admin/owner)
    if (p.startsWith('/api/catalog')) {
      return this.authorizeAction(principal, isRead ? 'catalog:read' : 'catalog:write');
    }

    // Gestión de equipos / invitaciones -> `team:read` / `team:write` (admin/owner)
    if (p.startsWith('/api/teams')) {
      return this.authorizeAction(principal, isRead ? 'team:read' : 'team:write');
    }

    // Tokens API -> `tokens:self` o `tokens:read`/`tokens:write` (bloquea viewer)
    if (p.startsWith('/api/auth/tokens')) {
      const selfCheck = this.authorizeAction(principal, 'tokens:self');
      if (selfCheck.allowed) return selfCheck;
      return this.authorizeAction(principal, isRead ? 'tokens:read' : 'tokens:write');
    }

    // ACL por proyecto -> `projects:acl` (admin/owner)
    if (/^\/api\/projects\/[^/]+\/acl(?:\/|$)/.test(p)) {
      return this.authorizeAction(principal, 'projects:acl');
    }

    // Eliminación de proyectos -> `projects:delete` (admin/owner)
    if (m === 'DELETE' && /^\/api\/projects\/[^/]+$/.test(p)) {
      return this.authorizeAction(principal, 'projects:delete');
    }

    // Bases de datos gestionadas -> lectura `databases:read`, delete `databases:admin`, mutación `databases:write`
    if (p.startsWith('/api/databases')) {
      return this.authorizeAction(principal, isRead ? 'databases:read' : (m === 'DELETE' ? 'databases:admin' : 'databases:write'));
    }

    // Uptime & páginas de estado -> `uptime:read` / `uptime:write`
    if (p.startsWith('/api/uptime') || p.startsWith('/api/status-pages')) {
      return this.authorizeAction(principal, isRead ? 'uptime:read' : 'uptime:write');
    }

    // Entornos / promoción -> `environments:read` / `environments:write`
    if (p.startsWith('/api/environments')) {
      return this.authorizeAction(principal, isRead ? 'environments:read' : 'environments:write');
    }

    // MCP -> `mcp:read` / `mcp:write`
    if (p.startsWith('/api/mcp')) {
      return this.authorizeAction(principal, isRead ? 'mcp:read' : 'mcp:write');
    }

    // Rutas de aplicación permitidas para developer+ en escritura
    if (
      p.startsWith('/api/projects') ||
      p.startsWith('/api/deploy') ||
      p.startsWith('/api/sync') ||
      p.startsWith('/api/domains') ||
      p.startsWith('/api/crons') ||
      p.startsWith('/api/previews') ||
      p.startsWith('/api/sleep')
    ) {
      if (isRead) return this.authorizeAction(principal, 'projects:read');
      if (p.startsWith('/api/deploy')) return this.authorizeAction(principal, 'deployments:write');
      if (p.startsWith('/api/sync')) return this.authorizeAction(principal, 'sync:write');
      if (p.startsWith('/api/domains')) return this.authorizeAction(principal, 'domains:write');
      if (p.startsWith('/api/crons')) return this.authorizeAction(principal, 'crons:write');
      if (p.startsWith('/api/previews')) return this.authorizeAction(principal, 'previews:write');
      if (p.startsWith('/api/sleep')) return this.authorizeAction(principal, 'sleep:write');
      return this.authorizeAction(principal, 'projects:write');
    }

    // Default-deny estricto (fail-closed): toda mutación no listada requiere `instance:admin` (solo owner)
    if (!isRead) {
      return this.authorizeAction(principal, 'instance:admin');
    }

    // Lecturas generales: `projects:read`
    return this.authorizeAction(principal, 'projects:read');
  }
}

const defaultInstance = new TeamManager();

module.exports = Object.assign(defaultInstance, {
  TeamManager,
  DEFAULT_TEAM_ID,
  KEY_FILE_NAME,
  DATA_FILE_NAME,
  ROLE_RANKS,
  VALID_ROLES,
  INVITABLE_ROLES,
  PROJECT_ACL_ROLES,
  ROLE_PERMISSIONS,
  ALL_PERMISSIONS,
  MAX_SESSIONS_PER_USER,
  MAX_INVITE_TTL_HOURS,
  MIN_PASSWORD_BYTES,
  MAX_PASSWORD_BYTES,
  roleRank,
  hasMinRole,
  getRolePermissions,
  normalizeEmail,
  validatePassword,
  normalizeProjectIds,
  intersectProjectIds,
  intersectScopesWithRole,
  unwrapPrincipal
});
