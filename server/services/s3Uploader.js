const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const { Readable } = require('stream');
const { isMetadataIp, assertSafeUrl } = require('./ssrfGuard');

/**
 * Cliente S3 mínimo: SigV4 firmado a mano sobre `node:crypto` y el `fetch`
 * nativo de Node. Sin dependencias.
 *
 * WHY NOT the AWS SDK: `@aws-sdk/client-s3` pulls ~90 transitive packages and
 * ~25 MB into node_modules for what is, in the end, four HTTP requests
 * (CreateMultipartUpload, UploadPart, CompleteMultipartUpload, GetObject).
 * Culkibo currently ships seven runtime dependencies in total; a self-hosted
 * orchestrator that people audit before trusting it with their data should not
 * quadruple its supply-chain surface to copy a file to a bucket.
 *
 * WHY NOT `aws4fetch` or `aws4` (both ~5 KB, both fine libraries): the signing
 * itself is ~70 lines and is covered here by the AWS-published known-answer
 * test vector (see tests/database.test.js). Once the signer is pinned by a KAT,
 * owning it is cheaper than tracking someone else's release cadence — and it
 * lets us do the two things S3-compatible providers actually need and the
 * generic helpers do not standardise: forced path-style addressing and an
 * arbitrary endpoint host.
 *
 * Verified against the AWS Signature Version 4 specification, September 2026:
 *   - The signing key is HMAC-chained date -> region -> service -> aws4_request.
 *   - S3 (unlike most services) REQUIRES the `x-amz-content-sha256` header and
 *     requires it to be part of the signed headers.
 *   - Cloudflare R2 requires region `auto` and path-style addressing.
 *   - The minimum part size for a multipart upload is 5 MiB for every part
 *     except the last one; the maximum number of parts is 10 000.
 */

const ALGORITHM = 'AWS4-HMAC-SHA256';
const EMPTY_SHA256 = crypto.createHash('sha256').update('').digest('hex');

/** 5 MiB: hard floor imposed by S3 on every part but the last. */
const MIN_PART_SIZE = 5 * 1024 * 1024;
/** 8 MiB default: comfortably above the floor and small enough to retry cheaply. */
const DEFAULT_PART_SIZE = 8 * 1024 * 1024;
const MAX_PARTS = 10000;

// ---------------------------------------------------------------------------
// Primitivas de firma (exportadas para poder fijarlas con vectores conocidos)
// ---------------------------------------------------------------------------

/**
 * Codificación RFC 3986 tal y como la exige SigV4.
 *
 * `encodeURIComponent` deja sin codificar `!'()*`, que SigV4 sí exige
 * codificar. Un solo carácter de diferencia produce una firma válida en
 * apariencia y un 403 en producción, normalmente sólo con las claves que
 * llevan paréntesis. De ahí el post-proceso.
 */
function rfc3986(str) {
  return encodeURIComponent(String(str)).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sha256Base64(data) {
  return crypto.createHash('sha256').update(data).digest('base64');
}

/**
 * Sanitiza un mapa de metadatos de usuario a cabeceras `x-amz-meta-*` seguras
 * para SigV4 (sin CRLF ni claves inválidas).
 * @param {Record<string, any> | null | undefined} metadata
 * @returns {Record<string, string>}
 */
function sanitizeMetadataHeaders(metadata) {
  /** @type {Record<string, string>} */
  const headers = {};
  if (!metadata || typeof metadata !== 'object') return headers;
  for (const [rawKey, rawVal] of Object.entries(metadata)) {
    if (rawVal === undefined || rawVal === null) continue;
    const cleanKey = String(rawKey).trim().toLowerCase().replace(/^x-amz-meta-/, '');
    if (!/^[a-z0-9_-]{1,64}$/.test(cleanKey)) {
      throw new Error(`Clave de metadato S3 inválida: ${rawKey}`);
    }
    const cleanVal = String(rawVal).replace(/[\r\n\0]+/g, ' ').trim().slice(0, 1024);
    if (!cleanVal) continue;
    headers[`x-amz-meta-${cleanKey}`] = cleanVal;
  }
  return headers;
}

const VALID_STORAGE_CLASSES = new Set([
  'STANDARD_IA', 'ONEZONE_IA', 'INTELLIGENT_TIERING', 'GLACIER_IR', 'GLACIER', 'DEEP_ARCHIVE'
]);

/**
 * Construye el documento XML S3 `LifecycleConfiguration` con validación estricta
 * de reglas (expiración, aborto de multiparts huérfanos, versiones no actuales y transiciones).
 * @param {Array<{
 *   id: string,
 *   prefix?: string,
 *   status?: 'Enabled' | 'Disabled',
 *   expirationDays?: number,
 *   abortIncompleteMultipartUploadDays?: number,
 *   noncurrentVersionExpirationDays?: number,
 *   transitions?: Array<{ days: number, storageClass: string }>
 * }>} rules
 * @returns {string}
 */
function buildLifecycleXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0 || rules.length > 100) {
    throw new Error('Lifecycle S3 requiere entre 1 y 100 reglas');
  }
  const seenIds = new Set();
  const xmlRules = rules.map((r, idx) => {
    if (!r || typeof r !== 'object') throw new Error(`Regla lifecycle #${idx + 1} inválida`);
    const id = String(r.id || '').trim();
    if (!id || id.length > 255 || /[\r\n\0]/.test(id)) {
      throw new Error(`ID de regla lifecycle inválido en #${idx + 1}`);
    }
    if (seenIds.has(id)) throw new Error(`ID de regla lifecycle duplicado: ${id}`);
    seenIds.add(id);

    const status = r.status === 'Disabled' ? 'Disabled' : 'Enabled';
    if (r.status !== undefined && r.status !== 'Enabled' && r.status !== 'Disabled') {
      throw new Error(`Estado de regla lifecycle inválido: ${r.status}`);
    }
    const prefix = String(r.prefix ?? '').replace(/[\r\n\0]/g, '');

    /** @type {string[]} */
    const actions = [];
    if (r.expirationDays !== undefined && r.expirationDays !== null) {
      const days = Number(r.expirationDays);
      if (!Number.isInteger(days) || days < 1 || days > 36500) {
        throw new Error(`expirationDays inválido en regla ${id}`);
      }
      actions.push(`<Expiration><Days>${days}</Days></Expiration>`);
    }
    if (r.abortIncompleteMultipartUploadDays !== undefined && r.abortIncompleteMultipartUploadDays !== null) {
      const days = Number(r.abortIncompleteMultipartUploadDays);
      if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new Error(`abortIncompleteMultipartUploadDays inválido en regla ${id}`);
      }
      actions.push(
        `<AbortIncompleteMultipartUpload><DaysAfterInitiation>${days}</DaysAfterInitiation></AbortIncompleteMultipartUpload>`
      );
    }
    if (r.noncurrentVersionExpirationDays !== undefined && r.noncurrentVersionExpirationDays !== null) {
      const days = Number(r.noncurrentVersionExpirationDays);
      if (!Number.isInteger(days) || days < 1 || days > 36500) {
        throw new Error(`noncurrentVersionExpirationDays inválido en regla ${id}`);
      }
      actions.push(
        `<NoncurrentVersionExpiration><NoncurrentDays>${days}</NoncurrentDays></NoncurrentVersionExpiration>`
      );
    }
    if (Array.isArray(r.transitions)) {
      for (const tr of r.transitions) {
        const days = Number(tr && tr.days);
        const sc = String(tr && tr.storageClass || '').trim().toUpperCase();
        if (!Number.isInteger(days) || days < 1 || days > 36500) {
          throw new Error(`Días de transición inválidos en regla ${id}`);
        }
        if (!VALID_STORAGE_CLASSES.has(sc)) {
          throw new Error(`StorageClass S3 no permitido en regla ${id}: ${sc}`);
        }
        actions.push(`<Transition><Days>${days}</Days><StorageClass>${sc}</StorageClass></Transition>`);
      }
    }
    if (actions.length === 0) {
      throw new Error(`La regla lifecycle ${id} debe definir al menos una acción`);
    }

    const filterXml = prefix
      ? `<Filter><Prefix>${xmlEscape(prefix)}</Prefix></Filter>`
      : '<Filter/>';
    return `<Rule><ID>${xmlEscape(id)}</ID>${filterXml}<Status>${status}</Status>${actions.join('')}</Rule>`;
  });

  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    xmlRules.join('') +
    '</LifecycleConfiguration>'
  );
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

/**
 * kSigning = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
 */
function deriveSigningKey(secretAccessKey, dateStamp, region, service) {
  return hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, dateStamp), region), service), 'aws4_request');
}

/** `20130524T000000Z` y `20130524` a partir de una fecha. */
function amzDates(date = new Date()) {
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

/**
 * Cadena canónica de consulta: parámetros ordenados por byte, clave y valor
 * codificados. Un parámetro sin valor se firma igualmente como `clave=`.
 */
function canonicalQueryString(query = {}) {
  return Object.keys(query)
    .sort()
    .map((k) => `${rfc3986(k)}=${rfc3986(query[k] === undefined || query[k] === null ? '' : query[k])}`)
    .join('&');
}

/**
 * Construye petición canónica, cadena a firmar y cabecera Authorization.
 *
 * `canonicalUri` debe llegar YA codificado y se usa tal cual tanto para firmar
 * como para construir la URL: codificar dos veces (una aquí y otra en `URL`)
 * es el fallo clásico con claves que contienen espacios o `+`.
 *
 * @returns {{authorization:string, headers:Object, canonicalRequest:string, stringToSign:string, signature:string, signedHeaders:string}}
 */
function signRequest({
  method,
  canonicalUri,
  query = {},
  headers = {},
  payloadHash,
  accessKeyId,
  secretAccessKey,
  sessionToken,
  region,
  service = 's3',
  date = new Date()
}) {
  const { amzDate, dateStamp } = amzDates(date);

  const allHeaders = {
    ...headers,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash
  };
  if (sessionToken) allHeaders['x-amz-security-token'] = sessionToken;

  // Nombres en minúscula, valores con espacios colapsados, ordenados por nombre.
  const normalized = Object.keys(allHeaders)
    .map((name) => [name.toLowerCase(), String(allHeaders[name]).trim().replace(/\s+/g, ' ')])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const canonicalHeaders = normalized.map(([k, v]) => `${k}:${v}\n`).join('');
  const signedHeaders = normalized.map(([k]) => k).join(';');

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString(query),
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [ALGORITHM, amzDate, scope, sha256Hex(canonicalRequest)].join('\n');

  const signingKey = deriveSigningKey(secretAccessKey, dateStamp, region, service);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

  return {
    canonicalRequest,
    stringToSign,
    signature,
    signedHeaders,
    headers: allHeaders,
    authorization:
      `${ALGORITHM} Credential=${accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`
  };
}

// ---------------------------------------------------------------------------
// Utilidades de XML
// ---------------------------------------------------------------------------

/**
 * Extractor de un único campo. No es un parser de XML y no pretende serlo: las
 * tres respuestas que leemos (UploadId, Code, Message) son campos planos de un
 * documento que genera el propio proveedor. Meter un parser completo para esto
 * sería otra dependencia por nada.
 */
function xmlField(xml, tag) {
  const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(String(xml || ''));
  return m ? m[1].trim() : null;
}

/**
 * Escapado para CONTENIDO de elemento, no para atributos: la comilla doble se
 * deja tal cual a propósito. Los ETag de S3 vienen entrecomillados y el ejemplo
 * de AWS los imprime con sus comillas literales dentro de `<ETag>`; convertirlas
 * en `&quot;` depende de que el parser del proveedor las deshaga, y es
 * exactamente el detalle que hace que Complete devuelva InvalidPart.
 */
function xmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ---------------------------------------------------------------------------
// Cliente
// ---------------------------------------------------------------------------

class S3Client {
  /**
   * @param {{
   *   endpoint?: string,
   *   region?: string,
   *   bucket?: string,
   *   accessKeyId?: string,
   *   secretAccessKey?: string,
   *   sessionToken?: string | null,
   *   forcePathStyle?: boolean,
   *   partSizeBytes?: number,
   *   timeoutMs?: number,
   *   maxRetries?: number
   * }} [config]
   */
  constructor(config = {}) {
    const missing = ['endpoint', 'bucket', 'accessKeyId', 'secretAccessKey'].filter((k) => !config[k]);
    if (missing.length) {
      throw new Error(`Configuración S3 incompleta: faltan ${missing.join(', ')}`);
    }

    const endpoint = String(config.endpoint);
    const bucket = String(config.bucket);
    let url;
    try {
      url = new URL(endpoint);
    } catch (e) {
      throw new Error(`Endpoint S3 inválido: ${endpoint}`);
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new Error('El endpoint S3 debe ser http o https');
    }
    const hostLower = url.hostname.toLowerCase();
    if (isMetadataIp(hostLower) || hostLower === 'metadata.google.internal' || hostLower === 'metadata.goog') {
      throw new Error(`Endpoint S3 bloqueado por protección SSRF (metadatos cloud): ${url.hostname}`);
    }

    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) {
      throw new Error(`Nombre de bucket inválido: ${bucket}`);
    }

    this.origin = url.origin;
    this.host = url.host;
    this.bucket = bucket;
    this.region = config.region || 'auto';
    this.accessKeyId = config.accessKeyId;
    this.secretAccessKey = config.secretAccessKey;
    this.sessionToken = config.sessionToken || null;

    // Path-style por defecto. R2, MinIO y Backblaze lo aceptan siempre; el
    // virtual-host sólo es obligatorio en AWS S3 y allí hace falta que el
    // certificado del bucket resuelva, lo que rompe con buckets con puntos.
    this.forcePathStyle =
      config.forcePathStyle !== undefined ? Boolean(config.forcePathStyle) : !/(^|\.)amazonaws\.com$/.test(url.hostname);

    this.partSizeBytes = Math.max(MIN_PART_SIZE, config.partSizeBytes || DEFAULT_PART_SIZE);
    this.timeoutMs = config.timeoutMs || 120000;
    this.maxRetries = config.maxRetries !== undefined ? config.maxRetries : 3;
  }

  /**
   * Descripción sin secretos. Es lo único que puede salir por la API o un log.
   */
  describe() {
    return {
      endpoint: this.origin,
      bucket: this.bucket,
      region: this.region,
      pathStyle: this.forcePathStyle,
      accessKeyId: redactKey(this.accessKeyId),
      secretAccessKey: '********'
    };
  }

  /**
   * Devuelve la ruta canónica (ya codificada) y la URL absoluta de una clave.
   * Permite `allowEmptyKey: true` únicamente para operaciones a nivel de bucket (ListObjectsV2).
   */
  resolve(key, { allowEmptyKey = false } = {}) {
    const segments = String(key ?? '').split('/').filter((s) => s.length > 0);
    if (!segments.length && !allowEmptyKey) throw new Error('Clave de objeto vacía');

    if (this.forcePathStyle) {
      const canonicalUri = segments.length > 0
        ? '/' + [this.bucket, ...segments].map(rfc3986).join('/')
        : '/' + rfc3986(this.bucket);
      return { canonicalUri, url: this.origin + canonicalUri, host: this.host };
    }
    const canonicalUri = segments.length > 0 ? '/' + segments.map(rfc3986).join('/') : '/';
    const alreadyPrefixed = this.host.toLowerCase().startsWith(`${this.bucket.toLowerCase()}.`);
    const host = alreadyPrefixed ? this.host : `${this.bucket}.${this.host}`;
    return { canonicalUri, url: `${new URL(this.origin).protocol}//${host}${canonicalUri}`, host };
  }

  /**
   * Petición HTTP(S) fijada a la IP validada por `assertSafeUrl` (cierra TOCTOU
   * de DNS rebinding hacia metadatos cloud) devolviendo un adaptador compatible
   * con Fetch streaming (`res.status`, `res.headers.get`, `res.text`, `res.body`).
   */
  _pinnedRequest(fullUrl, { method, headers, body, timeoutMs, pinnedIp }) {
    const parsed = new URL(fullUrl);
    const isHttps = parsed.protocol === 'https:';
    const mod = isHttps ? https : http;
    const family = net.isIP(pinnedIp) === 6 ? 6 : 4;
    const targetHostname = parsed.hostname.replace(/^\[|\]$/g, '');

    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (err, val) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(val);
      };

      const reqOpts = {
        protocol: parsed.protocol,
        hostname: targetHostname,
        port: parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80),
        path: `${parsed.pathname || '/'}${parsed.search || ''}`,
        method,
        headers,
        timeout: timeoutMs > 0 ? timeoutMs : undefined,
        ...(isHttps ? { servername: net.isIP(targetHostname) ? undefined : targetHostname } : {}),
        lookup: (_host, _opts, cb) => {
          if (typeof _opts === 'function') return _opts(null, pinnedIp, family);
          if (_opts && _opts.all) return cb(null, [{ address: pinnedIp, family }]);
          return cb(null, pinnedIp, family);
        }
      };

      const req = mod.request(reqOpts, (res) => {
        const rawHeaders = res.headers || {};
        const headerAdapter = {
          get(name) {
            const val = rawHeaders[String(name || '').toLowerCase()];
            if (Array.isArray(val)) return val.join(', ');
            return val === undefined ? null : String(val);
          },
          entries() {
            return Object.entries(rawHeaders).map(([k, v]) => [
              k.toLowerCase(),
              Array.isArray(v) ? v.join(', ') : (v === undefined ? '' : String(v))
            ]);
          }
        };
        /** @type {any} */
        let webBody = null;
        try {
          webBody = Readable.toWeb(res);
        } catch (e) {
          webBody = null;
        }
        const readAllText = async () => {
          if (!webBody) {
            const chunks = [];
            for await (const ch of res) chunks.push(Buffer.isBuffer(ch) ? ch : Buffer.from(ch));
            return Buffer.concat(chunks).toString('utf8');
          }
          const reader = webBody.getReader();
          const chunks = [];
          for (;;) {
            const { done: d, value } = await reader.read();
            if (d) break;
            chunks.push(Buffer.from(value));
          }
          return Buffer.concat(chunks).toString('utf8');
        };
        done(null, {
          status: res.statusCode || 0,
          headers: headerAdapter,
          body: webBody,
          text: readAllText
        });
      });

      req.on('timeout', () => req.destroy(new Error(`Tiempo de espera agotado en S3 (${timeoutMs} ms)`)));
      req.on('error', (err) => done(err, null));
      if (body !== undefined && body !== null && method !== 'GET' && method !== 'HEAD') {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * Petición firmada.
   * @param {string} method
   * @param {string} key
   * @param {{ query?: Record<string, any>, headers?: Record<string, any>, body?: any, expectStatus?: number[], timeoutMs?: number, allowEmptyKey?: boolean }} [opts]
   */
  async request(method, key, { query = {}, headers = {}, body = undefined, expectStatus = [200, 204], timeoutMs = undefined, allowEmptyKey = false } = {}) {
    const { canonicalUri, url, host } = this.resolve(key, { allowEmptyKey });
    const parsedUrl = new URL(url);
    const targetPort = Number(parsedUrl.port) || (parsedUrl.protocol === 'https:' ? 443 : 80);
    const daemonPort = Number(process.env.PORT || 3030);
    const payload = body === undefined || body === null ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(body);
    const payloadHash = payload ? sha256Hex(payload) : EMPTY_SHA256;

    const baseHeaders = { host, ...headers };
    if (payload) baseHeaders['content-length'] = String(payload.length);

    const qs = canonicalQueryString(query);
    const fullUrl = qs ? `${url}?${qs}` : url;
    const effectiveTimeout = timeoutMs !== undefined ? timeoutMs : this.timeoutMs;

    /** @type {any} */
    let lastError = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      // Re-validar DNS y fijar IP en CADA intento (cierra DNS rebinding hacia metadatos cloud y plano de control local)
      const safeInfo = await assertSafeUrl(url, { allowPrivate: true, allowLoopback: true });
      const pinnedIp = (safeInfo.addresses || []).find((a) => net.isIP(a) === 4) || (safeInfo.addresses || [])[0];
      if (pinnedIp && (pinnedIp === '127.0.0.1' || pinnedIp === '::1' || pinnedIp.startsWith('127.'))) {
        if (targetPort === 2019 || targetPort === daemonPort) {
          throw new Error(`Puerto de plano de control local (${targetPort}) bloqueado como destino S3`);
        }
      }

      // Re-firmar en cada intento para que el timestamp SigV4 nunca caduque en reintentos largos.
      const signed = signRequest({
        method,
        canonicalUri,
        query,
        headers: baseHeaders,
        payloadHash,
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
        sessionToken: this.sessionToken,
        region: this.region,
        service: 's3'
      });
      const wire = { ...signed.headers, Authorization: signed.authorization };

      try {
        const res = await this._pinnedRequest(fullUrl, {
          method,
          headers: wire,
          body: payload,
          timeoutMs: effectiveTimeout,
          pinnedIp
        });

        if (expectStatus.includes(res.status)) {
          return res;
        }

        const text = await res.text().catch(() => '');
        // 5xx y 429 son transitorios; 4xx significa que insistir no arregla nada.
        const retriable = res.status >= 500 || res.status === 429;
        const err = new Error(
          `S3 ${method} ${maskKey(key)} respondió ${res.status}` +
            (xmlField(text, 'Code') ? `: ${xmlField(text, 'Code')} ${xmlField(text, 'Message') || ''}` : '')
        );
        /** @type {any} */ (err).status = res.status;
        if (!retriable) throw err;
        lastError = err;
      } catch (err) {
        if (err.status && err.status < 500 && err.status !== 429) throw err;
        lastError = err;
      }

      if (attempt < this.maxRetries) {
        await new Promise((r) => setTimeout(r, Math.min(8000, 300 * Math.pow(2, attempt))));
      }
    }
    throw lastError || new Error(`S3 ${method} falló sin respuesta`);
  }

  /**
   * @param {string} key
   * @param {Buffer | string} body
   * @param {string} [contentType]
   * @param {{ metadata?: Record<string, any> | null, checksumSha256?: boolean }} [opts]
   */
  async putObject(key, body, contentType = 'application/octet-stream', { metadata = null, checksumSha256 = true } = {}) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    const contentMd5 = crypto.createHash('md5').update(buf).digest('base64');
    const sha256B64 = sha256Base64(buf);
    /** @type {Record<string, string>} */
    const headers = {
      'content-type': contentType,
      'content-md5': contentMd5,
      ...(checksumSha256 ? { 'x-amz-checksum-sha256': sha256B64 } : {}),
      ...sanitizeMetadataHeaders(metadata)
    };
    const res = await this.request('PUT', key, {
      headers,
      body: buf,
      expectStatus: [200]
    });
    const etag = res.headers.get('etag');
    try { await res.body?.cancel?.(); } catch (e) {}
    return { key, etag, size: buf.length, checksumSha256: sha256B64 };
  }

  async deleteObject(key) {
    const res = await this.request('DELETE', key, { expectStatus: [200, 204, 404] });
    try { await res.body?.cancel?.(); } catch (e) {}
    return { key, deleted: true };
  }

  async headObject(key) {
    const res = await this.request('HEAD', key, { expectStatus: [200, 404] });
    try { await res.body?.cancel?.(); } catch (e) {}
    if (res.status === 404) return null;
    /** @type {Record<string, string>} */
    const metadata = {};
    if (res.headers && typeof res.headers.entries === 'function') {
      for (const [hKey, hVal] of res.headers.entries()) {
        if (hKey.startsWith('x-amz-meta-')) {
          metadata[hKey.slice('x-amz-meta-'.length)] = hVal;
        }
      }
    }
    return {
      key,
      sizeBytes: Number(res.headers.get('content-length') || 0),
      etag: res.headers.get('etag'),
      lastModified: res.headers.get('last-modified'),
      checksumSha256: res.headers.get('x-amz-checksum-sha256') || null,
      metadata
    };
  }

  /**
   * Aplica una política de ciclo de vida S3 (`PUT /?lifecycle`) con Content-MD5 y SHA-256.
   * @param {Parameters<typeof buildLifecycleXml>[0]} rules
   */
  async putBucketLifecycle(rules) {
    const xml = buildLifecycleXml(rules);
    const buf = Buffer.from(xml, 'utf8');
    const contentMd5 = crypto.createHash('md5').update(buf).digest('base64');
    const sha256B64 = sha256Base64(buf);
    const res = await this.request('PUT', '', {
      query: { lifecycle: '' },
      headers: {
        'content-type': 'application/xml',
        'content-md5': contentMd5,
        'x-amz-checksum-sha256': sha256B64
      },
      body: buf,
      expectStatus: [200, 204],
      allowEmptyKey: true
    });
    try { await res.body?.cancel?.(); } catch (e) {}
    return { applied: true, rulesCount: rules.length, xml };
  }

  // -------------------------------------------------------------------------
  // Multipart
  // -------------------------------------------------------------------------

  /**
   * @param {string} key
   * @param {string} [contentType]
   * @param {{ metadata?: Record<string, any> | null, checksumSha256?: boolean }} [opts]
   */
  async createMultipartUpload(key, contentType = 'application/octet-stream', { metadata = null, checksumSha256 = true } = {}) {
    /** @type {Record<string, string>} */
    const headers = {
      'content-type': contentType,
      ...(checksumSha256 ? { 'x-amz-checksum-algorithm': 'SHA256' } : {}),
      ...sanitizeMetadataHeaders(metadata)
    };
    const res = await this.request('POST', key, {
      query: { uploads: '' },
      headers,
      body: Buffer.alloc(0),
      expectStatus: [200]
    });
    const xml = await res.text();
    const uploadId = xmlField(xml, 'UploadId');
    if (!uploadId) throw new Error('S3 no devolvió UploadId en CreateMultipartUpload');
    return uploadId;
  }

  /**
   * @param {string} key
   * @param {string} uploadId
   * @param {number} partNumber
   * @param {Buffer} chunk
   * @param {{ checksumSha256?: boolean }} [opts]
   */
  async uploadPart(key, uploadId, partNumber, chunk, { checksumSha256 = true } = {}) {
    // Escalar timeout si partSize creció para volcados >80 GB y enviar Content-MD5 + SHA-256 (Object Lock)
    const scaledTimeout = Math.max(this.timeoutMs, Math.ceil((chunk.length / (1024 * 1024)) * 15000));
    const contentMd5 = crypto.createHash('md5').update(chunk).digest('base64');
    const sha256Raw = crypto.createHash('sha256').update(chunk).digest();
    const sha256B64 = sha256Raw.toString('base64');
    /** @type {Record<string, string>} */
    const headers = {
      'content-md5': contentMd5,
      ...(checksumSha256 ? { 'x-amz-checksum-sha256': sha256B64 } : {})
    };
    const res = await this.request('PUT', key, {
      query: { partNumber: String(partNumber), uploadId },
      headers,
      body: chunk,
      expectStatus: [200],
      timeoutMs: Math.min(30 * 60 * 1000, scaledTimeout)
    });
    const etag = res.headers.get('etag');
    try { await res.body?.cancel?.(); } catch (e) {}
    if (!etag) throw new Error(`La parte ${partNumber} no devolvió ETag`);
    return { partNumber, etag, checksumSha256: sha256B64, checksumSha256Raw: sha256Raw };
  }

  /** Lista objetos remotos del bucket (ListObjectsV2) con paginación y unescape XML seguro. */
  async listObjectsV2(prefix = '', { maxKeys = 100, continuationToken = null } = {}) {
    const safeMax = Math.min(1000, Math.max(1, Number(maxKeys) || 100));
    /** @type {Record<string, string>} */
    const query = { 'list-type': '2', 'max-keys': String(safeMax) };
    if (prefix) query.prefix = String(prefix);
    if (continuationToken) query['continuation-token'] = String(continuationToken);
    const res = await this.request('GET', '', {
      query,
      expectStatus: [200],
      allowEmptyKey: true
    });
    const xml = await res.text();
    const unescapeXml = (s) => String(s || '')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;|&#39;/g, "'")
      .replace(/&amp;/g, '&');
    /** @type {Array<{ key: string, sizeBytes: number, lastModified: string | null, etag: string | null }>} */
    const objects = [];
    const blockRe = /<Contents>([\s\S]*?)<\/Contents>/g;
    let m;
    while ((m = blockRe.exec(xml)) !== null) {
      const blk = m[1];
      const key = xmlField(blk, 'Key');
      if (!key) continue;
      objects.push({
        key: unescapeXml(key),
        sizeBytes: parseInt(xmlField(blk, 'Size') || '0', 10) || 0,
        lastModified: xmlField(blk, 'LastModified') || null,
        etag: unescapeXml(xmlField(blk, 'ETag') || '') || null
      });
    }
    objects.sort((a, b) => Date.parse(b.lastModified || '0') - Date.parse(a.lastModified || '0'));
    const nextToken = xmlField(xml, 'NextContinuationToken') || null;
    return {
      objects,
      truncated: xmlField(xml, 'IsTruncated') === 'true',
      nextContinuationToken: nextToken ? unescapeXml(nextToken) : null
    };
  }

  async completeMultipartUpload(key, uploadId, parts) {
    // Los ETag viajan con sus comillas tal cual los devolvió el proveedor:
    // quitárselas es el error que hace fallar Complete con InvalidPart.
    const body = Buffer.from(
      '<?xml version="1.0" encoding="UTF-8"?>' +
        '<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
        parts
          .slice()
          .sort((a, b) => a.partNumber - b.partNumber)
          .map(
            (p) =>
              `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${xmlEscape(p.etag)}</ETag>` +
              (p.checksumSha256 ? `<ChecksumSHA256>${xmlEscape(p.checksumSha256)}</ChecksumSHA256>` : '') +
              '</Part>'
          )
          .join('') +
        '</CompleteMultipartUpload>',
      'utf8'
    );

    const res = await this.request('POST', key, {
      query: { uploadId },
      headers: { 'content-type': 'application/xml' },
      body,
      expectStatus: [200]
    });

    // S3 puede devolver 200 con un <Error> dentro: es el caso que casi todas
    // las implementaciones caseras dan por bueno y luego el objeto no existe.
    const xml = await res.text();
    if (xmlField(xml, 'Code')) {
      throw new Error(`CompleteMultipartUpload falló: ${xmlField(xml, 'Code')} ${xmlField(xml, 'Message') || ''}`);
    }
    return { key, etag: xmlField(xml, 'ETag'), location: xmlField(xml, 'Location') };
  }

  async abortMultipartUpload(key, uploadId) {
    try {
      const res = await this.request('DELETE', key, { query: { uploadId }, expectStatus: [200, 204, 404] });
      try { await res.body?.cancel?.(); } catch (e) {}
    } catch (e) {
      // Abortar es limpieza: si falla, el ciclo de vida del bucket lo recogerá.
    }
  }

  /**
   * Sube un fichero eligiendo la estrategia por tamaño.
   *
   * Por debajo del tamaño de parte, un único PUT: una sola petición en lugar de
   * tres y sin dejar subidas a medias que hay que abortar. Por encima,
   * multipart en trozos leídos uno a uno para que la memoria no dependa del
   * tamaño del volcado (un dump de 40 GB no cabe en el heap).
   */
  /**
   * @param {string} key
   * @param {string} filePath
   * @param {{ contentType?: string, onProgress?: ((p: any) => void) | null, metadata?: Record<string, any> | null, checksumSha256?: boolean }} [opts]
   */
  async uploadFile(key, filePath, { contentType = 'application/octet-stream', onProgress = null, metadata = null, checksumSha256 = true } = {}) {
    const stat = await fs.promises.stat(filePath);
    const total = stat.size;

    if (total <= this.partSizeBytes) {
      const body = await fs.promises.readFile(filePath);
      const out = await this.putObject(key, body, contentType, { metadata, checksumSha256 });
      if (onProgress) onProgress({ uploaded: total, total, part: 1, parts: 1 });
      return { ...out, sizeBytes: total, multipart: false };
    }

    // Escala el tamaño de parte si el fichero no cabe en 10 000 partes.
    //
    // Se calcula UNA vez y todas las partes salen de ese mismo tamaño (menos la
    // última). No es una simplificación: Cloudflare R2 es más estricto que S3 y
    // exige literalmente que todas las partes salvo la última midan lo mismo.
    // Un troceador que adapte el tamaño sobre la marcha funciona contra AWS y
    // contra MinIO y falla contra R2, que es justo el destino más habitual aquí.
    let partSize = this.partSizeBytes;
    if (Math.ceil(total / partSize) > MAX_PARTS) {
      partSize = Math.ceil(total / MAX_PARTS / MIN_PART_SIZE) * MIN_PART_SIZE;
    }
    const partCount = Math.ceil(total / partSize);

    const uploadId = await this.createMultipartUpload(key, contentType, { metadata, checksumSha256 });
    const parts = [];
    /** @type {Buffer[]} */
    const rawPartHashes = [];
    const handle = await fs.promises.open(filePath, 'r');
    // Reutilizar un solo buffer de parte en todo el bucle (reduce presión de GC en subidas multi-GB)
    const partBuf = Buffer.alloc(partSize);
    try {
      let uploaded = 0;
      for (let i = 0; i < partCount; i++) {
        const length = Math.min(partSize, total - i * partSize);
        let totalRead = 0;
        while (totalRead < length) {
          const { bytesRead } = await handle.read(partBuf, totalRead, length - totalRead, i * partSize + totalRead);
          if (bytesRead <= 0) break;
          totalRead += bytesRead;
        }
        const chunk = totalRead === partBuf.length ? partBuf : partBuf.subarray(0, totalRead);
        const uploadedPart = await this.uploadPart(key, uploadId, i + 1, chunk, { checksumSha256 });
        if (uploadedPart.checksumSha256Raw) rawPartHashes.push(uploadedPart.checksumSha256Raw);
        parts.push({
          partNumber: uploadedPart.partNumber,
          etag: uploadedPart.etag,
          ...(checksumSha256 ? { checksumSha256: uploadedPart.checksumSha256 } : {})
        });
        uploaded += totalRead;
        if (onProgress) onProgress({ uploaded, total, part: i + 1, parts: partCount });
      }
      await handle.close();
      const out = await this.completeMultipartUpload(key, uploadId, parts);
      const compositeSha256 = rawPartHashes.length === partCount
        ? `${sha256Base64(Buffer.concat(rawPartHashes))}-${partCount}`
        : null;
      return { ...out, sizeBytes: total, multipart: true, parts: partCount, checksumSha256: compositeSha256 };
    } catch (err) {
      try { await handle.close(); } catch (e) {}
      await this.abortMultipartUpload(key, uploadId);
      throw err;
    }
  }

  /** Descarga a disco en streaming de forma atómica (.tmp -> rename) verificando Content-Length, SHA-256 y sin deadlocks ENOSPC. */
  async downloadFile(key, destPath, { expectedSha256Hex = null } = {}) {
    const res = await this.request('GET', key, { expectStatus: [200], timeoutMs: 2 * 3600 * 1000 });
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
    if (!res.body) throw new Error('La respuesta S3 no contiene cuerpo descargable');
    const declaredLenRaw = res.headers.get('content-length');
    const declaredLen = declaredLenRaw != null ? parseInt(declaredLenRaw, 10) : null;
    const remoteChecksumB64 = res.headers.get('x-amz-checksum-sha256') || null;
    const tmpPath = `${destPath}.tmp_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const out = fs.createWriteStream(tmpPath, { mode: 0o600 });
    const reader = res.body.getReader();
    const hasher = crypto.createHash('sha256');
    let bytes = 0;
    /** @type {Error | null} */
    let streamErr = null;
    out.on('error', (err) => { streamErr = err; });
    try {
      for (;;) {
        if (streamErr) throw streamErr;
        const { done, value } = await reader.read();
        if (done) break;
        if (streamErr) throw streamErr;
        const chunkBuf = Buffer.from(value);
        bytes += chunkBuf.length;
        hasher.update(chunkBuf);
        if (!out.write(chunkBuf)) {
          await new Promise((resolve, reject) => {
            if (streamErr) return reject(streamErr);
            if (out.destroyed || out.errored) return reject(out.errored || new Error('Stream de destino cerrado'));
            const cleanup = () => {
              out.off('drain', onDrain);
              out.off('error', onErr);
              out.off('close', onClose);
            };
            const onDrain = () => { cleanup(); resolve(undefined); };
            const onErr = (e) => { cleanup(); reject(e); };
            const onClose = () => { cleanup(); reject(streamErr || new Error('Escritura interrumpida antes de drenar')); };
            out.once('drain', onDrain);
            out.once('error', onErr);
            out.once('close', onClose);
          });
        }
      }
      // P0: escuchar finish + error + close en el cierre final (out.end(cb) nunca pasa err y cuelga ante ENOSPC)
      await new Promise((resolve, reject) => {
        if (streamErr) return reject(streamErr);
        let settled = false;
        const cleanup = () => {
          out.off('finish', onFinish);
          out.off('error', onErr);
          out.off('close', onClose);
        };
        const onFinish = () => { if (settled) return; settled = true; cleanup(); resolve(undefined); };
        const onErr = (e) => { if (settled) return; settled = true; cleanup(); reject(e); };
        const onClose = () => {
          if (settled) return;
          settled = true;
          cleanup();
          if (streamErr) reject(streamErr);
          else if (out.writableFinished) resolve(undefined);
          else reject(new Error('El archivo de destino se cerró antes de vaciar el buffer'));
        };
        out.once('finish', onFinish);
        out.once('error', onErr);
        out.once('close', onClose);
        out.end();
      });
      if (streamErr) throw streamErr;
      if (declaredLen !== null && Number.isFinite(declaredLen) && bytes !== declaredLen) {
        throw new Error(`Descarga S3 truncada: recibidos ${bytes} bytes de ${declaredLen} declarados`);
      }
      const digestRaw = hasher.digest();
      const digestHex = digestRaw.toString('hex');
      const digestB64 = digestRaw.toString('base64');
      if (expectedSha256Hex && digestHex !== String(expectedSha256Hex).toLowerCase()) {
        throw new Error(`Checksum SHA-256 de descarga S3 no coincide (corrupción detectada)`);
      }
      if (remoteChecksumB64 && !remoteChecksumB64.includes('-') && digestB64 !== remoteChecksumB64) {
        throw new Error(`Cabecera x-amz-checksum-sha256 de S3 no coincide con el archivo descargado`);
      }
      await fs.promises.rename(tmpPath, destPath);
      return { key, destPath, sizeBytes: bytes, sha256: digestHex, checksumSha256: digestB64 };
    } catch (err) {
      try { await reader.cancel(); } catch (e) {}
      try { out.destroy(); } catch (e) {}
      try { await fs.promises.unlink(tmpPath); } catch (e) {}
      throw err;
    }
  }
}

/** `AKIA…7EXAMPLE` -> `AKIA****MPLE`. Para logs y respuestas de la API. */
function redactKey(value) {
  const s = String(value || '');
  if (s.length <= 8) return '********';
  return `${s.slice(0, 4)}****${s.slice(-4)}`;
}

/** Los nombres de objeto pueden llevar el nombre del proyecto; no los logeamos enteros. */
function maskKey(key) {
  const s = String(key || '');
  return s.length > 60 ? `${s.slice(0, 30)}…${s.slice(-20)}` : s;
}

module.exports = {
  S3Client,
  // Exportadas para las pruebas y para reutilizarlas sin instanciar el cliente.
  signRequest,
  deriveSigningKey,
  canonicalQueryString,
  rfc3986,
  sha256Hex,
  sha256Base64,
  sanitizeMetadataHeaders,
  buildLifecycleXml,
  amzDates,
  redactKey,
  xmlField,
  MIN_PART_SIZE,
  DEFAULT_PART_SIZE,
  MAX_PARTS
};
