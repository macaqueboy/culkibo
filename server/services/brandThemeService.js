const path = require('path');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Open-Core White-Label Brand & Custom Login Theme Engine (`coolify#1744` & Dokploy Enterprise alternative).
 *
 * Persiste atómicamente (`0o600`) la configuración de marca en `CULKIBO_DATA_DIR/data/brand-theme.json`
 * con validación estricta anti-XSS / anti-CSS-injection en todos los campos.
 * Cero dependencias npm externas, cero ejecución de shell.
 */

const BRAND_FILE_NAME = 'brand-theme.json';
const ACCENT_HEX_RE = /^#[0-9a-fA-F]{6}$/;
const MAX_BRAND_NAME_LEN = 60;
const MAX_TAGLINE_LEN = 140;
const MAX_URL_LEN = 1024;
const MAX_LOGO_LEN = 16384;

const DEFAULT_BRAND = Object.freeze({
  brandName: 'Culkibo',
  tagline: 'Ultra-lightweight self-hosted PaaS',
  accentHex: '#6366f1',
  logoUrl: '',
  supportUrl: '',
  hidePoweredBy: false,
  updatedAt: null
});

/** @type {any} */
let _auditLogger = null;
function getAuditLogger() {
  if (!_auditLogger) {
    try { _auditLogger = require('./auditLogger'); } catch (e) {}
  }
  return _auditLogger;
}

function resolveDefaultBrandFile() {
  const baseDir = process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
  return path.join(baseDir, BRAND_FILE_NAME);
}

/**
 * Crea un error HTTP estructurado.
 * @param {string} message
 * @param {number} [status]
 * @param {string} [code]
 */
function brandError(message, status = 400, code = 'INVALID_BRAND_CONFIG') {
  /** @type {Error & { status?: number, code?: string }} */
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

const DANGEROUS_SVG_PATTERNS = [
  /<\s*script\b/i,
  /<\/\s*script\b/i,
  /\bon[a-z]+\s*=/i,
  /<\s*foreignobject\b/i,
  /<\s*iframe\b/i,
  /<\s*object\b/i,
  /<\s*embed\b/i,
  /<\s*applet\b/i,
  /<\s*meta\b/i,
  /<\s*link\b/i,
  /<\s*style\b/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
  /xlink\s*:\s*href\s*=\s*["']?\s*(?:javascript|vbscript|data\s*:\s*text\/html)/i,
  /\bhref\s*=\s*["']?\s*(?:javascript|vbscript|data\s*:\s*text\/html)/i,
  /expression\s*\(/i,
  /@import\b/i
];

/**
 * Decodifica múltiples pasadas de `%XX` / entidades HTML simples para impedir evasiones XSS.
 * @param {string} raw
 * @returns {string}
 */
function decodeForSecurityScan(raw) {
  let text = String(raw || '');
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(text);
      if (next === text) break;
      text = next;
    } catch (e) {
      break;
    }
  }
  return text
    .replace(/&#x([0-9a-fA-F]+);?/g, (_, hex) => {
      const cp = parseInt(hex, 16);
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    })
    .replace(/&#([0-9]+);?/g, (_, dec) => {
      const cp = parseInt(dec, 10);
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    });
}

/**
 * Valida y sanitiza `logoUrl`: acepta `""`, URL `https://` válida o `data:image/svg+xml,...` seguro.
 * Rechaza estrictamente `javascript:`, `vbscript:`, `data:text/html`, `<script`, `on*=`, `<foreignObject`, `<iframe` y `xlink:href=javascript:`.
 *
 * @param {any} rawLogo
 * @returns {string}
 */
function sanitizeBrandLogo(rawLogo) {
  if (rawLogo === undefined || rawLogo === null) return '';
  if (typeof rawLogo !== 'string') {
    throw brandError('logoUrl debe ser una cadena de texto', 400, 'INVALID_LOGO_URL');
  }
  const trimmed = rawLogo.trim();
  if (!trimmed) return '';
  if (trimmed.length > MAX_LOGO_LEN) {
    throw brandError(`logoUrl supera el límite máximo de ${MAX_LOGO_LEN} caracteres`, 400, 'INVALID_LOGO_URL');
  }
  if (/[\0\r\n]/.test(trimmed)) {
    throw brandError('logoUrl contiene caracteres de control no permitidos', 400, 'INVALID_LOGO_URL');
  }

  const lower = trimmed.toLowerCase();
  if (
    lower.startsWith('javascript:') ||
    lower.startsWith('vbscript:') ||
    lower.startsWith('data:text/html') ||
    lower.startsWith('http://') ||
    lower.startsWith('file:')
  ) {
    throw brandError('Esquema de logoUrl bloqueado por seguridad (usa https:// o data:image/svg+xml seguro)', 400, 'INVALID_LOGO_URL');
  }

  // Caso 1: Inline SVG data URI
  if (lower.startsWith('data:image/svg+xml')) {
    const commaIdx = trimmed.indexOf(',');
    if (commaIdx === -1) {
      throw brandError('data:image/svg+xml malformado (falta separador ",")', 400, 'INVALID_LOGO_URL');
    }
    const header = trimmed.slice(0, commaIdx).toLowerCase();
    const payloadRaw = trimmed.slice(commaIdx + 1);
    if (!payloadRaw) {
      throw brandError('data:image/svg+xml vacío', 400, 'INVALID_LOGO_URL');
    }

    let decodedPayload = '';
    if (header.includes(';base64')) {
      try {
        decodedPayload = Buffer.from(payloadRaw, 'base64').toString('utf8');
      } catch (e) {
        throw brandError('SVG base64 inválido', 400, 'INVALID_LOGO_URL');
      }
    } else {
      decodedPayload = decodeForSecurityScan(payloadRaw);
    }

    const scanTargets = [trimmed, payloadRaw, decodedPayload, decodeForSecurityScan(decodedPayload)];
    for (const sample of scanTargets) {
      for (const re of DANGEROUS_SVG_PATTERNS) {
        if (re.test(sample)) {
          throw brandError('El SVG inline contiene elementos o atributos XSS bloqueados (script/event-handler/foreignObject/iframe/javascript:)', 400, 'UNSAFE_SVG_LOGO');
        }
      }
    }

    if (!/<\s*svg\b/i.test(decodedPayload)) {
      throw brandError('data:image/svg+xml debe contener un elemento raíz <svg>', 400, 'INVALID_LOGO_URL');
    }
    return trimmed;
  }

  // Caso 2: URL HTTPS estricta
  if (lower.startsWith('https://')) {
    if (trimmed.length > MAX_URL_LEN || /[\s<>"'`]/.test(trimmed)) {
      throw brandError('logoUrl HTTPS contiene caracteres no permitidos o excede el límite', 400, 'INVALID_LOGO_URL');
    }
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch (e) {
      throw brandError('logoUrl HTTPS malformada', 400, 'INVALID_LOGO_URL');
    }
    if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) {
      throw brandError('logoUrl debe ser una URL https:// válida sin credenciales incrustadas', 400, 'INVALID_LOGO_URL');
    }
    return parsed.toString();
  }

  throw brandError('logoUrl debe estar vacío, ser una URL https:// o un data:image/svg+xml seguro', 400, 'INVALID_LOGO_URL');
}

/**
 * Valida y normaliza un parche parcial de marca blanca (rechaza XSS y CSS injection).
 *
 * @param {any} patch
 * @returns {{
 *   brandName?: string,
 *   tagline?: string,
 *   accentHex?: string,
 *   logoUrl?: string,
 *   supportUrl?: string,
 *   hidePoweredBy?: boolean
 * }}
 */
function validateBrandPatch(patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    throw brandError('El cuerpo de configuración de marca debe ser un objeto JSON', 400, 'INVALID_BRAND_PATCH');
  }

  /** @type {any} */
  const clean = {};

  if (patch.brandName !== undefined) {
    if (typeof patch.brandName !== 'string') {
      throw brandError('brandName debe ser una cadena de texto', 400, 'INVALID_BRAND_NAME');
    }
    const name = patch.brandName.trim();
    if (name.length < 1 || name.length > MAX_BRAND_NAME_LEN) {
      throw brandError(`brandName debe tener entre 1 y ${MAX_BRAND_NAME_LEN} caracteres`, 400, 'INVALID_BRAND_NAME');
    }
    if (/[<>"'\0\r\n]/.test(name)) {
      throw brandError('brandName no puede contener <, >, ", \' ni caracteres de control', 400, 'INVALID_BRAND_NAME');
    }
    clean.brandName = name;
  }

  if (patch.tagline !== undefined) {
    if (typeof patch.tagline !== 'string') {
      throw brandError('tagline debe ser una cadena de texto', 400, 'INVALID_BRAND_TAGLINE');
    }
    const tag = patch.tagline.trim();
    if (tag.length > MAX_TAGLINE_LEN) {
      throw brandError(`tagline no puede superar ${MAX_TAGLINE_LEN} caracteres`, 400, 'INVALID_BRAND_TAGLINE');
    }
    if (/[<>\0\r\n]/.test(tag)) {
      throw brandError('tagline no puede contener <, > ni caracteres de control', 400, 'INVALID_BRAND_TAGLINE');
    }
    clean.tagline = tag;
  }

  if (patch.accentHex !== undefined) {
    if (typeof patch.accentHex !== 'string') {
      throw brandError('accentHex debe ser un color hexadecimal #RRGGBB', 400, 'INVALID_ACCENT_HEX');
    }
    const hex = patch.accentHex.trim();
    if (!ACCENT_HEX_RE.test(hex)) {
      throw brandError('accentHex debe cumplir estrictamente el formato #RRGGBB (6 dígitos hexadecimales)', 400, 'INVALID_ACCENT_HEX');
    }
    clean.accentHex = hex.toLowerCase();
  }

  if (patch.supportUrl !== undefined) {
    if (patch.supportUrl === null || patch.supportUrl === '') {
      clean.supportUrl = '';
    } else {
      if (typeof patch.supportUrl !== 'string') {
        throw brandError('supportUrl debe ser una cadena de texto', 400, 'INVALID_SUPPORT_URL');
      }
      const sUrl = patch.supportUrl.trim();
      if (!sUrl) {
        clean.supportUrl = '';
      } else {
        if (sUrl.length > MAX_URL_LEN || /[\0\r\n\s<>"']/.test(sUrl)) {
          throw brandError('supportUrl contiene caracteres no permitidos', 400, 'INVALID_SUPPORT_URL');
        }
        let parsed;
        try {
          parsed = new URL(sUrl);
        } catch (e) {
          throw brandError('supportUrl debe ser una URL https:// válida', 400, 'INVALID_SUPPORT_URL');
        }
        if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) {
          throw brandError('supportUrl solo permite URLs https:// válidas (se bloquean http://, javascript: y data:)', 400, 'INVALID_SUPPORT_URL');
        }
        clean.supportUrl = parsed.toString();
      }
    }
  }

  if (patch.logoUrl !== undefined) {
    clean.logoUrl = sanitizeBrandLogo(patch.logoUrl);
  }

  if (patch.hidePoweredBy !== undefined) {
    if (typeof patch.hidePoweredBy !== 'boolean') {
      throw brandError('hidePoweredBy debe ser booleano', 400, 'INVALID_BRAND_PATCH');
    }
    clean.hidePoweredBy = patch.hidePoweredBy;
  }

  return clean;
}

class BrandThemeService {
  /**
   * @param {{ dataDir?: string | null, filePath?: string | null }} [opts]
   */
  constructor(opts = {}) {
    this._explicitFile = opts.filePath
      ? path.resolve(opts.filePath)
      : (opts.dataDir ? path.join(path.resolve(opts.dataDir), BRAND_FILE_NAME) : null);
    /** @type {string | null} */
    this._loadedPath = null;
    /** @type {{ brandName: string, tagline: string, accentHex: string, logoUrl: string, supportUrl: string, hidePoweredBy: boolean, updatedAt: string | null }} */
    this._brand = { ...DEFAULT_BRAND };
  }

  _resolveFile() {
    return this._explicitFile || resolveDefaultBrandFile();
  }

  _ensureLoaded() {
    const target = this._resolveFile();
    if (this._loadedPath === target) return;
    this._loadedPath = target;
    this._brand = { ...DEFAULT_BRAND };

    const loaded = loadJsonWithBackupSync(target, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed))
    });
    if (loaded.ok && loaded.data) {
      try {
        const sanitized = validateBrandPatch({
          brandName: loaded.data.brandName,
          tagline: loaded.data.tagline,
          accentHex: loaded.data.accentHex,
          logoUrl: loaded.data.logoUrl,
          supportUrl: loaded.data.supportUrl,
          hidePoweredBy: typeof loaded.data.hidePoweredBy === 'boolean' ? loaded.data.hidePoweredBy : false
        });
        this._brand = {
          ...DEFAULT_BRAND,
          ...sanitized,
          updatedAt: typeof loaded.data.updatedAt === 'string' ? loaded.data.updatedAt : null
        };
      } catch (e) {
        // Si el JSON en disco fue manipulado con valores inválidos, caer de forma segura al tema por defecto
        this._brand = { ...DEFAULT_BRAND };
      }
    }
  }

  _save() {
    const target = this._resolveFile();
    atomicWriteJsonSync(target, this._brand, { mode: 0o600, pretty: true, backup: true });
  }

  getBrand() {
    this._ensureLoaded();
    return { ...this._brand };
  }

  /**
   * Actualiza y persiste la configuración de marca blanca tras validación estricta anti-XSS.
   * @param {any} patch
   * @param {{ actor?: any }} [opts]
   */
  updateBrand(patch, { actor = null } = {}) {
    this._ensureLoaded();
    const validated = validateBrandPatch(patch);
    const next = {
      ...this._brand,
      ...validated,
      updatedAt: new Date().toISOString()
    };
    this._brand = next;
    this._save();
    try {
      const al = getAuditLogger();
      if (al && typeof al.record === 'function') {
        al.record({
          source: 'brand_theme',
          action: 'brand.update',
          actor: actor || undefined,
          fields: Object.keys(validated)
        });
      }
    } catch (e) {}
    return { ...this._brand };
  }

  /**
   * Restaura la configuración de marca blanca a `DEFAULT_BRAND`.
   * @param {{ actor?: any }} [opts]
   */
  resetBrand({ actor = null } = {}) {
    this._ensureLoaded();
    this._brand = { ...DEFAULT_BRAND };
    this._save();
    try {
      const al = getAuditLogger();
      if (al && typeof al.record === 'function') {
        al.record({
          source: 'brand_theme',
          action: 'brand.reset',
          actor: actor || undefined
        });
      }
    } catch (e) {}
    return { ...this._brand };
  }
}

const instance = Object.assign(new BrandThemeService(), {
  BrandThemeService,
  DEFAULT_BRAND,
  validateBrandPatch,
  sanitizeBrandLogo
});

module.exports = instance;
