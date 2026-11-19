const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
   * Ambas se derivan de la misma cadena para que firma y petición coincidan.
   */
  resolve(key) {
    const segments = String(key).split('/').filter((s) => s.length > 0);
    if (!segments.length) throw new Error('Clave de objeto vacía');

    if (this.forcePathStyle) {
      const canonicalUri = '/' + [this.bucket, ...segments].map(rfc3986).join('/');
      return { canonicalUri, url: this.origin + canonicalUri, host: this.host };
    }
    const canonicalUri = '/' + segments.map(rfc3986).join('/');
    const host = `${this.bucket}.${this.host}`;
    return { canonicalUri, url: `${new URL(this.origin).protocol}//${host}${canonicalUri}`, host };
  }

  /**
   * Petición firmada. `body` debe ser Buffer/Uint8Array o undefined: firmamos
   * el sha256 real del cuerpo en lugar de UNSIGNED-PAYLOAD porque así la
   * integridad va cubierta extremo a extremo aunque el transporte sea http
   * (MinIO en una red interna, por ejemplo).
   */
  /**
   * @param {string} method
   * @param {string} key
   * @param {{ query?: Record<string, any>, headers?: Record<string, any>, body?: any, expectStatus?: number[] }} [opts]
   */
  async request(method, key, { query = {}, headers = {}, body = undefined, expectStatus = [200, 204] } = {}) {
    const { canonicalUri, url, host } = this.resolve(key);
    const payload = body === undefined || body === null ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(body);
    const payloadHash = payload ? sha256Hex(payload) : EMPTY_SHA256;

    const baseHeaders = { host, ...headers };
    if (payload) baseHeaders['content-length'] = String(payload.length);

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

    const qs = canonicalQueryString(query);
    const fullUrl = qs ? `${url}?${qs}` : url;

    // `host` lo pone undici; enviarlo a mano lanza en Node.
    const wire = { ...signed.headers, Authorization: signed.authorization };
    delete wire.host;

    /** @type {any} */
    let lastError = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const res = await fetch(fullUrl, {
          method,
          headers: wire,
          body: payload,
          signal: AbortSignal.timeout(this.timeoutMs)
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

  async putObject(key, body, contentType = 'application/octet-stream') {
    const res = await this.request('PUT', key, {
      headers: { 'content-type': contentType },
      body,
      expectStatus: [200]
    });
    return { key, etag: res.headers.get('etag'), size: Buffer.isBuffer(body) ? body.length : String(body).length };
  }

  async deleteObject(key) {
    await this.request('DELETE', key, { expectStatus: [200, 204, 404] });
    return { key, deleted: true };
  }

  async headObject(key) {
    const res = await this.request('HEAD', key, { expectStatus: [200, 404] });
    if (res.status === 404) return null;
    return {
      key,
      sizeBytes: Number(res.headers.get('content-length') || 0),
      etag: res.headers.get('etag'),
      lastModified: res.headers.get('last-modified')
    };
  }

  // -------------------------------------------------------------------------
  // Multipart
  // -------------------------------------------------------------------------

  async createMultipartUpload(key, contentType = 'application/octet-stream') {
    const res = await this.request('POST', key, {
      query: { uploads: '' },
      headers: { 'content-type': contentType },
      body: Buffer.alloc(0),
      expectStatus: [200]
    });
    const xml = await res.text();
    const uploadId = xmlField(xml, 'UploadId');
    if (!uploadId) throw new Error('S3 no devolvió UploadId en CreateMultipartUpload');
    return uploadId;
  }

  async uploadPart(key, uploadId, partNumber, chunk) {
    const res = await this.request('PUT', key, {
      query: { partNumber: String(partNumber), uploadId },
      body: chunk,
      expectStatus: [200]
    });
    const etag = res.headers.get('etag');
    if (!etag) throw new Error(`La parte ${partNumber} no devolvió ETag`);
    return { partNumber, etag };
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
          .map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${xmlEscape(p.etag)}</ETag></Part>`)
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
      await this.request('DELETE', key, { query: { uploadId }, expectStatus: [200, 204, 404] });
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
   * @param {{ contentType?: string, onProgress?: ((p: any) => void) | null }} [opts]
   */
  async uploadFile(key, filePath, { contentType = 'application/octet-stream', onProgress = null } = {}) {
    const stat = await fs.promises.stat(filePath);
    const total = stat.size;

    if (total <= this.partSizeBytes) {
      const body = await fs.promises.readFile(filePath);
      const out = await this.putObject(key, body, contentType);
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

    const uploadId = await this.createMultipartUpload(key, contentType);
    const parts = [];
    const handle = await fs.promises.open(filePath, 'r');
    try {
      let uploaded = 0;
      for (let i = 0; i < partCount; i++) {
        const length = Math.min(partSize, total - i * partSize);
        const buf = Buffer.allocUnsafe(length);
        await handle.read(buf, 0, length, i * partSize);
        parts.push(await this.uploadPart(key, uploadId, i + 1, buf));
        uploaded += length;
        if (onProgress) onProgress({ uploaded, total, part: i + 1, parts: partCount });
      }
      await handle.close();
      const out = await this.completeMultipartUpload(key, uploadId, parts);
      return { ...out, sizeBytes: total, multipart: true, parts: partCount };
    } catch (err) {
      try { await handle.close(); } catch (e) {}
      // Sin abort, las partes huérfanas se facturan indefinidamente en R2 y S3.
      await this.abortMultipartUpload(key, uploadId);
      throw err;
    }
  }

  /** Descarga a disco en streaming, para restaurar desde remoto. */
  async downloadFile(key, destPath) {
    const res = await this.request('GET', key, { expectStatus: [200] });
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
    const out = fs.createWriteStream(destPath);
    if (!res.body) throw new Error('La respuesta S3 no contiene cuerpo descargable');
    const reader = res.body.getReader();
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (!out.write(Buffer.from(value))) {
        await new Promise((r) => out.once('drain', r));
      }
    }
    await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve(undefined))));
    return { key, destPath, sizeBytes: bytes };
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
  amzDates,
  redactKey,
  xmlField,
  MIN_PART_SIZE,
  DEFAULT_PART_SIZE,
  MAX_PARTS
};
