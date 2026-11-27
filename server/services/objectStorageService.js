'use strict';

/**
 * Culkibo Zero-Dep Post-MinIO S3 Object Storage Orchestrator & Pure-Crypto AWS SigV4 Presigner.
 *
 * Capitalizes on the 2025–2026 MinIO community console removal / archival with:
 *  - Pinned, private-bridge-default (`127.0.0.1`) S3-compatible presets:
 *      * Garage (`dxflrs/garage:v1.0.1`) — Rust CRDT S3, ~40 MB RAM, ideal for WireGuard mesh
 *      * RustFS (`rustfs/rustfs:1.0.0-alpha.45`) — Apache-2.0 MinIO drop-in w/ ILM & Object Lock
 *      * SeaweedFS (`chrislusf/seaweedfs:3.85`) — Apache-2.0 Filer + S3 gateway
 *  - Pure `node:crypto` AWS Signature Version 4 (`AWS4-HMAC-SHA256`) query-string presigned URLs
 *    (`UNSIGNED-PAYLOAD`, RFC 3986 encoding, `60..604800s` TTL bounds, zero AWS SDK deps).
 *  - Declarative S3 Bucket CORS XML (blocking `*` + `allowCredentials: true`) & Lifecycle XML builders.
 */

const crypto = require('crypto');

const MIN_PRESIGN_EXPIRES_SEC = 60;
const MAX_PRESIGN_EXPIRES_SEC = 604800; // 7 days (AWS SigV4 hard maximum)
const ALLOWED_PRESIGN_METHODS = new Set(['GET', 'PUT', 'HEAD', 'DELETE']);
const ALLOWED_CORS_METHODS = new Set(['GET', 'PUT', 'POST', 'DELETE', 'HEAD']);
const BUCKET_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const S3_PRESETS = Object.freeze({
  garage: Object.freeze({
    id: 'garage',
    name: 'Garage (Rust CRDT S3)',
    image: 'dxflrs/garage:v1.0.1',
    license: 'AGPL-3.0',
    ramEstimateMb: 40,
    bindAddress: '127.0.0.1',
    s3Port: 3900,
    rpcPort: 3901,
    adminPort: 3903,
    privateBridgeDefault: true,
    publicExpose: false,
    description: 'Ultra-lightweight Rust S3-compatible CRDT object store (~40 MB RAM), ideal for multi-node WireGuard Fleet Mesh.',
    features: [
      '~40 MB idle RAM footprint',
      'CRDT geo-distributed replication over WireGuard mesh',
      'S3-compatible API + static website hosting',
      'Private bridge default (127.0.0.1 — zero public exposure)'
    ],
    envDefaults: {
      GARAGE_RPC_BIND_ADDR: '0.0.0.0:3901',
      GARAGE_S3_API_REGION: 'us-east-1',
      GARAGE_ALLOW_WORLD_READABLE_SECRETS: 'false'
    }
  }),
  rustfs: Object.freeze({
    id: 'rustfs',
    name: 'RustFS (Apache-2.0 MinIO Drop-In)',
    image: 'rustfs/rustfs:1.0.0-alpha.45',
    license: 'Apache-2.0',
    ramEstimateMb: 64,
    bindAddress: '127.0.0.1',
    s3Port: 9000,
    consolePort: 9001,
    privateBridgeDefault: true,
    publicExpose: false,
    description: 'High-throughput Apache-2.0 Rust drop-in MinIO replacement with built-in web console, ILM Lifecycle, and Object Lock.',
    features: [
      'Apache-2.0 permissive license (post-MinIO drop-in)',
      'S3 ILM Lifecycle & Object Lock WORM support',
      'Built-in management console bound to 127.0.0.1',
      'Private bridge default (127.0.0.1 — zero public exposure)'
    ],
    envDefaults: {
      RUSTFS_ADDRESS: ':9000',
      RUSTFS_CONSOLE_ADDRESS: ':9001',
      RUSTFS_CONSOLE_ENABLE: 'true'
    }
  }),
  seaweedfs: Object.freeze({
    id: 'seaweedfs',
    name: 'SeaweedFS (Distributed Filer + S3)',
    image: 'chrislusf/seaweedfs:3.85',
    license: 'Apache-2.0',
    ramEstimateMb: 96,
    bindAddress: '127.0.0.1',
    s3Port: 8333,
    filerPort: 8888,
    masterPort: 9333,
    privateBridgeDefault: true,
    publicExpose: false,
    description: 'Battle-tested Apache-2.0 distributed object & POSIX filer store with built-in S3 gateway and automatic volume compaction.',
    features: [
      'Dual POSIX Filer + S3 gateway access',
      'O(1) disk seek volume storage & automatic compaction',
      'Scales smoothly from single VPS to petabyte clusters',
      'Private bridge default (127.0.0.1 — zero public exposure)'
    ],
    envDefaults: {
      WEED_S3_PORT: '8333'
    }
  })
});

/**
 * RFC 3986 percent-encoding required by AWS Signature Version 4.
 * @param {string} input
 * @param {boolean} [encodeSlash]
 * @returns {string}
 */
function awsUriEncode(input, encodeSlash = true) {
  const bytes = Buffer.from(String(input || ''), 'utf8');
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    const isUnreserved =
      (ch >= 0x41 && ch <= 0x5a) || // A-Z
      (ch >= 0x61 && ch <= 0x7a) || // a-z
      (ch >= 0x30 && ch <= 0x39) || // 0-9
      ch === 0x2d || // -
      ch === 0x5f || // _
      ch === 0x2e || // .
      ch === 0x7e;   // ~
    if (isUnreserved || (!encodeSlash && ch === 0x2f)) {
      out += String.fromCharCode(ch);
    } else {
      out += '%' + ch.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

/**
 * Escapes XML special characters safely.
 * @param {string} val
 * @returns {string}
 */
function escapeXml(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Validates an S3 bucket name strictly against DNS/S3 naming rules.
 * @param {string} bucket
 * @returns {string}
 */
function validateBucketName(bucket) {
  const clean = String(bucket || '').trim();
  if (!BUCKET_NAME_RE.test(clean) || clean.includes('..') || clean.includes('.-') || clean.includes('-.') || IPV4_RE.test(clean)) {
    const err = /** @type {any} */ (new Error(`Invalid S3 bucket name: "${clean.slice(0, 64)}"`));
    err.code = 'INVALID_BUCKET_NAME';
    err.status = 400;
    throw err;
  }
  return clean;
}

/**
 * Validates an S3 object key strictly against path traversal (`..`), leading `/`, and control chars.
 * @param {string} key
 * @returns {string}
 */
function validateObjectKey(key) {
  const clean = String(key ?? '');
  if (!clean || clean.length > 1024) {
    const err = /** @type {any} */ (new Error('Invalid S3 object key: must be 1..1024 characters'));
    err.code = 'INVALID_OBJECT_KEY';
    err.status = 400;
    throw err;
  }
  if (clean.startsWith('/') || clean.includes('\\') || /[\x00-\x1f\x7f]/.test(clean)) {
    const err = /** @type {any} */ (new Error('Invalid S3 object key: leading slash, backslash, or control character rejected'));
    err.code = 'INVALID_OBJECT_KEY';
    err.status = 400;
    throw err;
  }
  const segments = clean.split('/');
  if (segments.some((seg) => seg === '..' || seg === '.') || clean.includes('..')) {
    const err = /** @type {any} */ (new Error(`Invalid S3 object key (path traversal blocked): "${clean.slice(0, 80)}"`));
    err.code = 'INVALID_OBJECT_KEY';
    err.status = 400;
    throw err;
  }
  return clean;
}

/**
 * Computes HMAC-SHA256 raw digest buffer.
 * @param {Buffer | string} key
 * @param {string} data
 * @returns {Buffer}
 */
function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

/**
 * Formats a `Date` into AWS SigV4 `{ amzDate: 'YYYYMMDDTHHMMSSZ', dateStamp: 'YYYYMMDD' }`.
 * @param {Date} dt
 */
function formatAmzDates(dt) {
  const iso = dt.toISOString(); // YYYY-MM-DDTHH:MM:SS.sssZ
  const dateStamp = iso.slice(0, 10).replace(/-/g, '');
  const timeStamp = iso.slice(11, 19).replace(/:/g, '');
  return {
    dateStamp,
    amzDate: `${dateStamp}T${timeStamp}Z`
  };
}

/**
 * Generates an AWS Signature Version 4 (`AWS4-HMAC-SHA256`) query-string presigned S3 URL
 * using ONLY Node built-in `crypto` (zero AWS SDK dependencies).
 *
 * @param {{
 *   endpoint: string,
 *   region?: string,
 *   bucket: string,
 *   key: string,
 *   method?: string,
 *   accessKeyId: string,
 *   secretAccessKey: string,
 *   expiresIn?: number,
 *   nowDate?: Date | string | number
 * }} opts
 */
function generatePresignedUrl(opts) {
  if (!opts || typeof opts !== 'object') {
    const err = /** @type {any} */ (new Error('generatePresignedUrl requires an options object'));
    err.code = 'INVALID_REQUEST';
    err.status = 400;
    throw err;
  }

  const rawEndpoint = String(opts.endpoint || '').trim();
  let parsedEndpoint;
  try {
    parsedEndpoint = new URL(rawEndpoint);
  } catch (e) {
    const err = /** @type {any} */ (new Error(`Invalid S3 endpoint URL: "${rawEndpoint.slice(0, 80)}"`));
    err.code = 'INVALID_ENDPOINT';
    err.status = 400;
    throw err;
  }
  if (parsedEndpoint.protocol !== 'http:' && parsedEndpoint.protocol !== 'https:') {
    const err = /** @type {any} */ (new Error(`Unsupported S3 endpoint protocol: ${parsedEndpoint.protocol}`));
    err.code = 'INVALID_ENDPOINT';
    err.status = 400;
    throw err;
  }

  const bucket = validateBucketName(opts.bucket);
  const key = validateObjectKey(opts.key);
  const method = String(opts.method || 'GET').trim().toUpperCase();
  if (!ALLOWED_PRESIGN_METHODS.has(method)) {
    const err = /** @type {any} */ (new Error(`Unsupported presign HTTP method "${method}" (allowed: GET, PUT, HEAD, DELETE)`));
    err.code = 'INVALID_METHOD';
    err.status = 400;
    throw err;
  }

  const region = String(opts.region || 'us-east-1').trim();
  if (!/^[a-z0-9-]{2,64}$/.test(region)) {
    const err = /** @type {any} */ (new Error(`Invalid S3 region: "${region.slice(0, 40)}"`));
    err.code = 'INVALID_REGION';
    err.status = 400;
    throw err;
  }

  const accessKeyId = String(opts.accessKeyId || '').trim();
  const secretAccessKey = String(opts.secretAccessKey || '');
  if (!accessKeyId || !secretAccessKey) {
    const err = /** @type {any} */ (new Error('accessKeyId and secretAccessKey are required for SigV4 presigning'));
    err.code = 'MISSING_CREDENTIALS';
    err.status = 400;
    throw err;
  }

  const expiresIn = opts.expiresIn === undefined ? 900 : Number(opts.expiresIn);
  if (!Number.isInteger(expiresIn) || expiresIn < MIN_PRESIGN_EXPIRES_SEC || expiresIn > MAX_PRESIGN_EXPIRES_SEC) {
    const err = /** @type {any} */ (new Error(`expiresIn must be an integer between ${MIN_PRESIGN_EXPIRES_SEC} and ${MAX_PRESIGN_EXPIRES_SEC} seconds (got ${opts.expiresIn})`));
    err.code = 'INVALID_EXPIRES_IN';
    err.status = 400;
    throw err;
  }

  const nowDate = opts.nowDate instanceof Date
    ? opts.nowDate
    : (opts.nowDate !== undefined ? new Date(opts.nowDate) : new Date());
  if (Number.isNaN(nowDate.getTime())) {
    const err = /** @type {any} */ (new Error('Invalid nowDate'));
    err.code = 'INVALID_DATE';
    err.status = 400;
    throw err;
  }

  const { dateStamp, amzDate } = formatAmzDates(nowDate);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const hostHeader = parsedEndpoint.host;
  const basePath = parsedEndpoint.pathname.replace(/\/+$/, '');
  const canonicalUri = `${basePath}/${awsUriEncode(bucket, true)}/${awsUriEncode(key, false)}`;

  /** @type {Array<[string, string]>} */
  const queryPairs = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${accessKeyId}/${credentialScope}`],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expiresIn)],
    ['X-Amz-SignedHeaders', 'host']
  ];

  const canonicalQueryString = queryPairs
    .map(([k, v]) => [awsUriEncode(k, true), awsUriEncode(v, true)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0)))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    `host:${hostHeader}\n`,
    'host',
    'UNSIGNED-PAYLOAD'
  ].join('\n');

  const canonicalRequestHash = crypto.createHash('sha256').update(canonicalRequest, 'utf8').digest('hex');
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    canonicalRequestHash
  ].join('\n');

  const kDate = hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, 's3');
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  const url = `${parsedEndpoint.origin}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
  const expiresAt = new Date(nowDate.getTime() + expiresIn * 1000).toISOString();

  return {
    ok: true,
    url,
    method,
    bucket,
    key,
    region,
    expiresIn,
    expiresAt,
    amzDate,
    algorithm: 'AWS4-HMAC-SHA256',
    signature
  };
}

/**
 * Compiles an S3 `<CORSConfiguration>` XML document.
 * Strictly REJECTS wildcard `'*'` origin combined with `allowCredentials: true`.
 *
 * @param {Array<{
 *   id?: string,
 *   allowedOrigins: string[],
 *   allowedMethods: string[],
 *   allowedHeaders?: string[],
 *   exposeHeaders?: string[],
 *   maxAgeSeconds?: number,
 *   allowCredentials?: boolean
 * }>} rules
 * @returns {string}
 */
function buildBucketCorsXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    const err = /** @type {any} */ (new Error('buildBucketCorsXml requires at least one CORS rule'));
    err.code = 'INVALID_CORS_RULES';
    err.status = 400;
    throw err;
  }

  /** @type {string[]} */
  const ruleBlocks = [];
  for (let i = 0; i < Math.min(rules.length, 50); i++) {
    const rule = rules[i];
    if (!rule || typeof rule !== 'object') {
      throw new Error(`Invalid CORS rule at index ${i}`);
    }
    const origins = Array.isArray(rule.allowedOrigins)
      ? rule.allowedOrigins.map((o) => String(o || '').trim()).filter(Boolean)
      : [];
    if (origins.length === 0) {
      const err = /** @type {any} */ (new Error(`CORS rule #${i} requires at least one allowedOrigin`));
      err.code = 'INVALID_CORS_ORIGIN';
      err.status = 400;
      throw err;
    }
    const hasWildcard = origins.includes('*');
    if (hasWildcard && rule.allowCredentials === true) {
      const err = /** @type {any} */ (new Error('Insecure S3 CORS configuration blocked: wildcard origin "*" cannot be combined with allowCredentials=true'));
      err.code = 'CORS_WILDCARD_CREDENTIALS_BLOCKED';
      err.status = 400;
      throw err;
    }
    for (const o of origins) {
      if (o === '*') continue;
      if (/[\r\n\0]/.test(o) || !/^https?:\/\/[^/\s]+$/i.test(o)) {
        const err = /** @type {any} */ (new Error(`Invalid CORS origin: "${o.slice(0, 80)}"`));
        err.code = 'INVALID_CORS_ORIGIN';
        err.status = 400;
        throw err;
      }
    }

    const methods = Array.isArray(rule.allowedMethods)
      ? rule.allowedMethods.map((m) => String(m || '').trim().toUpperCase()).filter(Boolean)
      : [];
    if (methods.length === 0 || methods.some((m) => !ALLOWED_CORS_METHODS.has(m))) {
      const err = /** @type {any} */ (new Error(`Invalid CORS allowedMethods at rule #${i} (allowed: GET, PUT, POST, DELETE, HEAD)`));
      err.code = 'INVALID_CORS_METHOD';
      err.status = 400;
      throw err;
    }

    /** @type {string[]} */
    const lines = ['  <CORSRule>'];
    if (rule.id && String(rule.id).trim()) {
      lines.push(`    <ID>${escapeXml(String(rule.id).trim().slice(0, 128))}</ID>`);
    }
    for (const o of origins) lines.push(`    <AllowedOrigin>${escapeXml(o)}</AllowedOrigin>`);
    for (const m of methods) lines.push(`    <AllowedMethod>${escapeXml(m)}</AllowedMethod>`);
    if (Array.isArray(rule.allowedHeaders)) {
      for (const h of rule.allowedHeaders.slice(0, 32)) {
        const clean = String(h || '').trim();
        if (clean && !/[\r\n\0]/.test(clean)) lines.push(`    <AllowedHeader>${escapeXml(clean)}</AllowedHeader>`);
      }
    }
    if (Array.isArray(rule.exposeHeaders)) {
      for (const h of rule.exposeHeaders.slice(0, 32)) {
        const clean = String(h || '').trim();
        if (clean && !/[\r\n\0]/.test(clean)) lines.push(`    <ExposeHeader>${escapeXml(clean)}</ExposeHeader>`);
      }
    }
    if (rule.maxAgeSeconds !== undefined && rule.maxAgeSeconds !== null) {
      const age = Math.max(0, Math.min(86400, Math.round(Number(rule.maxAgeSeconds) || 0)));
      lines.push(`    <MaxAgeSeconds>${age}</MaxAgeSeconds>`);
    }
    lines.push('  </CORSRule>');
    ruleBlocks.push(lines.join('\n'));
  }

  return `<?xml version="1.0" encoding="UTF-8"?>\n<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n${ruleBlocks.join('\n')}\n</CORSConfiguration>\n`;
}

/**
 * Compiles an S3 `<LifecycleConfiguration>` XML document (expiration + abort incomplete multipart).
 *
 * @param {Array<{
 *   id: string,
 *   prefix?: string,
 *   enabled?: boolean,
 *   expirationDays?: number | null,
 *   abortMultipartDays?: number | null,
 *   noncurrentVersionExpirationDays?: number | null
 * }>} rules
 * @returns {string}
 */
function buildLifecycleXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    const err = /** @type {any} */ (new Error('buildLifecycleXml requires at least one lifecycle rule'));
    err.code = 'INVALID_LIFECYCLE_RULES';
    err.status = 400;
    throw err;
  }

  /** @type {string[]} */
  const ruleBlocks = [];
  for (let i = 0; i < Math.min(rules.length, 100); i++) {
    const rule = rules[i];
    if (!rule || typeof rule !== 'object') throw new Error(`Invalid lifecycle rule at index ${i}`);
    const id = String(rule.id || '').trim();
    if (!id || id.length > 255 || /[\r\n\0]/.test(id)) {
      const err = /** @type {any} */ (new Error(`Invalid lifecycle rule id at index ${i}`));
      err.code = 'INVALID_LIFECYCLE_ID';
      err.status = 400;
      throw err;
    }
    const prefix = String(rule.prefix ?? '').trim();
    if (prefix.includes('..') || /[\r\n\0]/.test(prefix)) {
      const err = /** @type {any} */ (new Error(`Invalid lifecycle prefix: "${prefix.slice(0, 60)}"`));
      err.code = 'INVALID_LIFECYCLE_PREFIX';
      err.status = 400;
      throw err;
    }
    const status = rule.enabled === false ? 'Disabled' : 'Enabled';

    /** @type {string[]} */
    const lines = [
      '  <Rule>',
      `    <ID>${escapeXml(id)}</ID>`,
      `    <Filter><Prefix>${escapeXml(prefix)}</Prefix></Filter>`,
      `    <Status>${status}</Status>`
    ];

    let hasAction = false;
    if (rule.expirationDays !== undefined && rule.expirationDays !== null) {
      const days = Math.round(Number(rule.expirationDays));
      if (!Number.isFinite(days) || days < 1 || days > 36500) {
        const err = /** @type {any} */ (new Error(`Invalid expirationDays (${rule.expirationDays}); expected 1..36500`));
        err.code = 'INVALID_LIFECYCLE_DAYS';
        err.status = 400;
        throw err;
      }
      lines.push(`    <Expiration><Days>${days}</Days></Expiration>`);
      hasAction = true;
    }
    if (rule.abortMultipartDays !== undefined && rule.abortMultipartDays !== null) {
      const days = Math.round(Number(rule.abortMultipartDays));
      if (!Number.isFinite(days) || days < 1 || days > 3650) {
        const err = /** @type {any} */ (new Error(`Invalid abortMultipartDays (${rule.abortMultipartDays}); expected 1..3650`));
        err.code = 'INVALID_LIFECYCLE_DAYS';
        err.status = 400;
        throw err;
      }
      lines.push(`    <AbortIncompleteMultipartUpload><DaysAfterInitiation>${days}</DaysAfterInitiation></AbortIncompleteMultipartUpload>`);
      hasAction = true;
    }
    if (rule.noncurrentVersionExpirationDays !== undefined && rule.noncurrentVersionExpirationDays !== null) {
      const days = Math.round(Number(rule.noncurrentVersionExpirationDays));
      if (!Number.isFinite(days) || days < 1 || days > 36500) {
        const err = /** @type {any} */ (new Error(`Invalid noncurrentVersionExpirationDays (${rule.noncurrentVersionExpirationDays})`));
        err.code = 'INVALID_LIFECYCLE_DAYS';
        err.status = 400;
        throw err;
      }
      lines.push(`    <NoncurrentVersionExpiration><NoncurrentDays>${days}</NoncurrentDays></NoncurrentVersionExpiration>`);
      hasAction = true;
    }

    if (!hasAction) {
      const err = /** @type {any} */ (new Error(`Lifecycle rule "${id}" must define expirationDays, abortMultipartDays, or noncurrentVersionExpirationDays`));
      err.code = 'INVALID_LIFECYCLE_ACTION';
      err.status = 400;
      throw err;
    }

    lines.push('  </Rule>');
    ruleBlocks.push(lines.join('\n'));
  }

  return `<?xml version="1.0" encoding="UTF-8"?>\n<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n${ruleBlocks.join('\n')}\n</LifecycleConfiguration>\n`;
}

class ObjectStorageService {
  /** Lists all pinned post-MinIO S3-compatible storage engine presets. */
  listPresets() {
    return Object.values(S3_PRESETS);
  }

  /**
   * Returns a single S3 preset by ID (`garage` | `rustfs` | `seaweedfs`) or `null`.
   * @param {string} id
   */
  getPreset(id) {
    const key = String(id || '').trim().toLowerCase();
    if (key === 'garage' || key === 'rustfs' || key === 'seaweedfs') {
      return S3_PRESETS[key];
    }
    return null;
  }

  /** @param {Parameters<typeof generatePresignedUrl>[0]} opts */
  generatePresignedUrl(opts) {
    return generatePresignedUrl(opts);
  }

  /** @param {Parameters<typeof buildBucketCorsXml>[0]} rules */
  buildBucketCorsXml(rules) {
    return buildBucketCorsXml(rules);
  }

  /** @param {Parameters<typeof buildLifecycleXml>[0]} rules */
  buildLifecycleXml(rules) {
    return buildLifecycleXml(rules);
  }
}

const defaultObjectStorageService = new ObjectStorageService();

const exported = Object.assign(defaultObjectStorageService, {
  ObjectStorageService,
  S3_PRESETS,
  generatePresignedUrl,
  buildBucketCorsXml,
  buildLifecycleXml,
  validateBucketName,
  validateObjectKey,
  MAX_PRESIGN_EXPIRES_SEC,
  MIN_PRESIGN_EXPIRES_SEC
});

module.exports = exported;
