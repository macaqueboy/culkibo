const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

/**
 * Culkibo DirectPush — Unregistry-inspired zero-registry SSH OCI Distribution v2
 * loopback server for layer-delta image deployment directly to any VPS over SSH.
 *
 * How it works:
 * - Binds strictly on loopback (`127.0.0.1` / `::1`) — never exposed to the public internet.
 * - Implements the OCI Distribution Specification v2 endpoints (`GET /v2/`,
 *   `HEAD/GET /v2/:name/blobs/:digest`, `POST/PATCH/PUT/DELETE /v2/:name/blobs/uploads/...`,
 *   `HEAD/GET/PUT /v2/:name/manifests/:ref`, `GET /v2/_catalog`, `GET /v2/:name/tags/list`).
 * - Delta transfer: Docker/BuildKit checks `HEAD /v2/:name/blobs/:digest` first; any layer
 *   already present on the target is skipped (zero wire bytes transferred!).
 * - Strict SHA-256 verification on every uploaded blob: any mismatch is immediately
 *   rejected with HTTP `400` (`DIGEST_INVALID`) and deleted before commit.
 * - Zero new runtime npm deps, zero shell construction (`shell: false` argv plans only),
 *   zero background timers on import.
 */

const REPO_NAME_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const REFERENCE_RE = /^(?:[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}|sha256:[a-f0-9]{64})$/;
const UPLOAD_ID_RE = /^[a-f0-9-]{8,64}$/;
const DOCKER_IMAGE_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]{0,200}$/;
const SERVER_ID_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const SSH_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const HOST_SAFE_RE = /^[a-zA-Z0-9._:\[\]-]{1,253}$/;
const FORBIDDEN_SHELL_RE = /[\0\r\n\s;|&`$<>()'"\\]/;

const DEFAULT_MAX_BLOB_BYTES = 512 * 1024 * 1024; // 512 MiB
const DEFAULT_MAX_MANIFEST_BYTES = 4 * 1024 * 1024; // 4 MiB
const DEFAULT_MAX_ACTIVE_UPLOADS = 64;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

/**
 * Constant-time string comparison via SHA-256 digests (no length leak).
 * @param {string} a
 * @param {string} b
 */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a || ''), 'utf8').digest();
  const hb = crypto.createHash('sha256').update(String(b || ''), 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}

/**
 * Computes `sha256:<hex>` digest for a Buffer.
 * @param {Buffer} buf
 */
function sha256Digest(buf) {
  return `sha256:${crypto.createHash('sha256').update(buf).digest('hex')}`;
}

/**
 * Emits a standard OCI Distribution v2 JSON error response.
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {string} code
 * @param {string} message
 * @param {any} [detail]
 */
function sendOciError(res, status, code, message, detail = undefined) {
  const body = Buffer.from(
    JSON.stringify({
      errors: [{ code, message, ...(detail !== undefined ? { detail } : {}) }]
    }),
    'utf8'
  );
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Docker-Distribution-Api-Version': 'registry/2.0',
    'Content-Length': body.length
  });
  res.end(body);
}

class DirectPushRegistry {
  /**
   * @param {{
   *   storageDir?: string | null,
   *   authToken?: string | null,
   *   maxBlobBytes?: number,
   *   maxManifestBytes?: number,
   *   maxActiveUploads?: number
   * }} [options]
   */
  constructor(options = {}) {
    this.storageDir = options.storageDir ? path.resolve(options.storageDir) : null;
    this.authToken = options.authToken ? String(options.authToken) : null;
    this.maxBlobBytes = Math.max(1024, Number(options.maxBlobBytes) || DEFAULT_MAX_BLOB_BYTES);
    this.maxManifestBytes = Math.max(1024, Number(options.maxManifestBytes) || DEFAULT_MAX_MANIFEST_BYTES);
    this.maxActiveUploads = Math.max(1, Number(options.maxActiveUploads) || DEFAULT_MAX_ACTIVE_UPLOADS);

    /** @type {http.Server | null} */
    this.server = null;
    this.host = '127.0.0.1';
    this.port = 0;
    this.running = false;

    /** @type {Map<string, { size: number, filePath: string | null, buf: Buffer | null }>} */
    this.blobs = new Map();
    /** @type {Map<string, Map<string, { digest: string, mediaType: string, body: Buffer }>>} */
    this.manifests = new Map();
    /** @type {Map<string, { id: string, repo: string, tempPath: string | null, chunks: Buffer[], size: number, hasher: crypto.Hash, createdAt: number }>} */
    this.uploads = new Map();

    this.stats = {
      blobsUploaded: 0,
      bytesUploaded: 0,
      blobsSkipped: 0,
      bytesSaved: 0,
      manifestsPushed: 0,
      digestRejections: 0
    };
  }

  _ensureStorageDirs() {
    if (!this.storageDir) return;
    fs.mkdirSync(path.join(this.storageDir, 'blobs'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(this.storageDir, 'uploads'), { recursive: true, mode: 0o700 });
  }

  /**
   * Seeds an existing layer blob into the registry (e.g., layers already present on target VPS).
   * @param {Buffer | string} content
   * @returns {{ digest: string, size: number }}
   */
  seedBlob(content) {
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const digest = sha256Digest(buf);
    if (!this.blobs.has(digest)) {
      if (this.storageDir) {
        this._ensureStorageDirs();
        const hex = digest.slice(7);
        const filePath = path.join(this.storageDir, 'blobs', hex);
        fs.writeFileSync(filePath, buf, { mode: 0o600 });
        this.blobs.set(digest, { size: buf.length, filePath, buf: null });
      } else {
        this.blobs.set(digest, { size: buf.length, filePath: null, buf });
      }
    }
    return { digest, size: buf.length };
  }

  /** @param {string} digest */
  hasBlob(digest) {
    return DIGEST_RE.test(String(digest || '')) && this.blobs.has(digest);
  }

  /** @param {string} digest @returns {Buffer | null} */
  readBlob(digest) {
    const entry = this.blobs.get(digest);
    if (!entry) return null;
    if (entry.buf) return entry.buf;
    if (entry.filePath && fs.existsSync(entry.filePath)) {
      return fs.readFileSync(entry.filePath);
    }
    return null;
  }

  /** @param {string} repo @param {string} ref */
  getManifest(repo, ref) {
    const repoMap = this.manifests.get(repo);
    return repoMap ? (repoMap.get(ref) || null) : null;
  }

  /** Returns live delta transfer & verification statistics. */
  getStats() {
    let totalStoredBytes = 0;
    for (const b of this.blobs.values()) totalStoredBytes += b.size;
    const logicalTransferBytes = this.stats.bytesUploaded + this.stats.bytesSaved;
    const savedRatioPct = logicalTransferBytes > 0
      ? Number(((this.stats.bytesSaved / logicalTransferBytes) * 100).toFixed(1))
      : 0;
    return {
      running: this.running,
      host: this.host,
      port: this.port,
      url: this.running ? `http://${this.host}:${this.port}` : null,
      blobsStored: this.blobs.size,
      totalStoredBytes,
      blobsUploaded: this.stats.blobsUploaded,
      bytesUploaded: this.stats.bytesUploaded,
      blobsSkipped: this.stats.blobsSkipped,
      bytesSaved: this.stats.bytesSaved,
      savedRatioPct,
      manifestsPushed: this.stats.manifestsPushed,
      digestRejections: this.stats.digestRejections,
      activeUploads: this.uploads.size
    };
  }

  /** @param {any} upload */
  _cleanupUpload(upload) {
    if (!upload) return;
    this.uploads.delete(upload.id);
    upload.chunks = [];
    if (upload.tempPath) {
      try { if (fs.existsSync(upload.tempPath)) fs.unlinkSync(upload.tempPath); } catch (e) {}
    }
  }

  /**
   * Streams incoming HTTP request body into an active upload session while updating SHA-256.
   * @param {http.IncomingMessage} req
   * @param {any} upload
   */
  _appendRequestToUpload(req, upload) {
    return new Promise((resolve, reject) => {
      let failed = false;
      /** @type {fs.WriteStream | null} */
      let ws = null;
      if (upload.tempPath) {
        ws = fs.createWriteStream(upload.tempPath, { flags: 'a', mode: 0o600 });
        ws.on('error', (err) => {
          if (!failed) { failed = true; reject(err); }
        });
      }

      req.on('data', (chunk) => {
        if (failed) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (upload.size + buf.length > this.maxBlobBytes) {
          failed = true;
          const err = new Error(`Blob exceeds maxBlobBytes (${this.maxBlobBytes})`);
          /** @type {any} */ (err).code = 'SIZE_INVALID';
          /** @type {any} */ (err).status = 413;
          if (ws) try { ws.destroy(); } catch (e) {}
          req.resume();
          return reject(err);
        }
        upload.size += buf.length;
        upload.hasher.update(buf);
        if (ws) {
          ws.write(buf);
        } else {
          upload.chunks.push(buf);
        }
      });

      req.on('error', (err) => {
        if (!failed) {
          failed = true;
          if (ws) try { ws.destroy(); } catch (e) {}
          reject(err);
        }
      });

      req.on('end', () => {
        if (failed) return;
        if (ws) {
          ws.end(() => resolve(undefined));
        } else {
          resolve(undefined);
        }
      });
    });
  }

  /**
   * Reads a bounded request body Buffer (used for manifests).
   * @param {http.IncomingMessage} req
   * @param {number} maxBytes
   * @returns {Promise<Buffer>}
   */
  _readBoundedBody(req, maxBytes) {
    return new Promise((resolve, reject) => {
      /** @type {Buffer[]} */
      const chunks = [];
      let total = 0;
      let aborted = false;
      req.on('data', (chunk) => {
        if (aborted) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += buf.length;
        if (total > maxBytes) {
          aborted = true;
          req.resume();
          const err = new Error(`Payload exceeds ${maxBytes} bytes`);
          /** @type {any} */ (err).status = 413;
          return reject(err);
        }
        chunks.push(buf);
      });
      req.on('error', (err) => {
        if (!aborted) { aborted = true; reject(err); }
      });
      req.on('end', () => {
        if (!aborted) resolve(total > 0 ? Buffer.concat(chunks, total) : Buffer.alloc(0));
      });
    });
  }

  /** @param {http.IncomingMessage} req */
  _checkAuth(req) {
    if (!this.authToken) return true;
    const hdr = String(req.headers.authorization || '');
    if (hdr.startsWith('Bearer ')) {
      return safeEqual(hdr.slice(7).trim(), this.authToken);
    }
    return false;
  }

  /**
   * Core OCI Distribution v2 HTTP request router.
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   */
  async _handleRequest(req, res) {
    if (!this._checkAuth(req)) {
      res.writeHead(401, {
        'Content-Type': 'application/json; charset=utf-8',
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'WWW-Authenticate': 'Bearer realm="culkibo-directpush"'
      });
      res.end(JSON.stringify({ errors: [{ code: 'UNAUTHORIZED', message: 'authentication required' }] }));
      return;
    }

    const method = String(req.method || 'GET').toUpperCase();
    const parsedUrl = new URL(req.url || '/', `http://${this.host}:${this.port || 80}`);
    const pathname = parsedUrl.pathname;

    // 1. Base version probe: GET /v2/
    if (pathname === '/v2/' || pathname === '/v2') {
      if (method !== 'GET' && method !== 'HEAD') {
        return sendOciError(res, 405, 'UNSUPPORTED', 'Method not allowed');
      }
      const body = Buffer.from('{}', 'utf8');
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Length': body.length
      });
      res.end(method === 'HEAD' ? undefined : body);
      return;
    }

    // 2. Catalog listing: GET /v2/_catalog
    if (pathname === '/v2/_catalog' && method === 'GET') {
      const body = Buffer.from(JSON.stringify({ repositories: Array.from(this.manifests.keys()).sort() }), 'utf8');
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Length': body.length
      });
      res.end(body);
      return;
    }

    // 3. Tags list: GET /v2/:name/tags/list
    const tagsMatch = pathname.match(/^\/v2\/(.+)\/tags\/list$/);
    if (tagsMatch && method === 'GET') {
      const repo = tagsMatch[1];
      if (!REPO_NAME_RE.test(repo)) return sendOciError(res, 400, 'NAME_INVALID', 'Invalid repository name');
      const repoMap = this.manifests.get(repo);
      const tags = repoMap ? Array.from(repoMap.keys()).filter((k) => !DIGEST_RE.test(k)).sort() : [];
      const body = Buffer.from(JSON.stringify({ name: repo, tags }), 'utf8');
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Length': body.length
      });
      res.end(body);
      return;
    }

    // 4. Blob check / download: HEAD|GET /v2/:name/blobs/:digest
    const blobMatch = pathname.match(/^\/v2\/(.+)\/blobs\/(sha256:[a-f0-9]{64})$/);
    if (blobMatch) {
      const repo = blobMatch[1];
      const digest = blobMatch[2];
      if (!REPO_NAME_RE.test(repo)) return sendOciError(res, 400, 'NAME_INVALID', 'Invalid repository name');
      const entry = this.blobs.get(digest);
      if (!entry) {
        return sendOciError(res, 404, 'BLOB_UNKNOWN', 'blob unknown to registry', { digest });
      }
      if (method === 'HEAD') {
        // Docker/BuildKit probes HEAD before uploading a layer: 200 means delta skip!
        this.stats.blobsSkipped++;
        this.stats.bytesSaved += entry.size;
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Docker-Distribution-Api-Version': 'registry/2.0',
          'Docker-Content-Digest': digest,
          'Content-Length': entry.size
        });
        res.end();
        return;
      }
      if (method === 'GET') {
        const data = this.readBlob(digest);
        if (!data) return sendOciError(res, 404, 'BLOB_UNKNOWN', 'blob unknown to registry', { digest });
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Docker-Distribution-Api-Version': 'registry/2.0',
          'Docker-Content-Digest': digest,
          'Content-Length': data.length
        });
        res.end(data);
        return;
      }
      return sendOciError(res, 405, 'UNSUPPORTED', 'Method not allowed');
    }

    // 5. Initiate blob upload (or cross-repo mount / monolithic upload): POST /v2/:name/blobs/uploads/
    const startUploadMatch = pathname.match(/^\/v2\/(.+)\/blobs\/uploads\/?$/);
    if (startUploadMatch && method === 'POST') {
      const repo = startUploadMatch[1];
      if (!REPO_NAME_RE.test(repo)) return sendOciError(res, 400, 'NAME_INVALID', 'Invalid repository name');

      // Cross-repo mount check (`?mount=sha256:...`)
      const mountDigest = parsedUrl.searchParams.get('mount');
      if (mountDigest && DIGEST_RE.test(mountDigest) && this.blobs.has(mountDigest)) {
        const existing = /** @type {{ size: number }} */ (this.blobs.get(mountDigest));
        this.stats.blobsSkipped++;
        this.stats.bytesSaved += existing.size;
        res.writeHead(201, {
          Location: `/v2/${repo}/blobs/${mountDigest}`,
          'Docker-Content-Digest': mountDigest,
          'Docker-Distribution-Api-Version': 'registry/2.0',
          'Content-Length': 0
        });
        res.end();
        return;
      }

      if (this.uploads.size >= this.maxActiveUploads) {
        return sendOciError(res, 503, 'TOO_MANY_UPLOADS', 'Too many concurrent blob uploads');
      }

      const id = crypto.randomUUID();
      /** @type {string | null} */
      let tempPath = null;
      if (this.storageDir) {
        this._ensureStorageDirs();
        tempPath = path.join(this.storageDir, 'uploads', `${id}.part`);
      }
      const upload = {
        id,
        repo,
        tempPath,
        /** @type {Buffer[]} */
        chunks: [],
        size: 0,
        hasher: crypto.createHash('sha256'),
        createdAt: Date.now()
      };
      this.uploads.set(id, upload);

      // Monolithic upload (`POST /v2/:name/blobs/uploads/?digest=sha256:...`)
      const monoDigest = parsedUrl.searchParams.get('digest');
      if (monoDigest) {
        return this._finalizeUpload(req, res, upload, monoDigest);
      }

      res.writeHead(202, {
        Location: `/v2/${repo}/blobs/uploads/${id}`,
        'Docker-Upload-UUID': id,
        'Docker-Distribution-Api-Version': 'registry/2.0',
        Range: '0-0',
        'Content-Length': 0
      });
      res.end();
      return;
    }

    // 6. Chunked upload append / finalize / abort: PATCH|PUT|DELETE /v2/:name/blobs/uploads/:uuid
    const uploadItemMatch = pathname.match(/^\/v2\/(.+)\/blobs\/uploads\/([a-f0-9-]{8,64})$/);
    if (uploadItemMatch) {
      const repo = uploadItemMatch[1];
      const uuid = uploadItemMatch[2];
      if (!REPO_NAME_RE.test(repo) || !UPLOAD_ID_RE.test(uuid)) {
        return sendOciError(res, 400, 'BLOB_UPLOAD_INVALID', 'Invalid upload path');
      }
      const upload = this.uploads.get(uuid);
      if (!upload || upload.repo !== repo) {
        return sendOciError(res, 404, 'BLOB_UPLOAD_UNKNOWN', 'blob upload unknown to registry');
      }

      if (method === 'DELETE') {
        this._cleanupUpload(upload);
        res.writeHead(204, { 'Docker-Distribution-Api-Version': 'registry/2.0' });
        res.end();
        return;
      }

      if (method === 'PATCH') {
        try {
          await this._appendRequestToUpload(req, upload);
        } catch (err) {
          this._cleanupUpload(upload);
          return sendOciError(res, err.status || 400, err.code || 'BLOB_UPLOAD_INVALID', err.message);
        }
        const rangeEnd = upload.size > 0 ? upload.size - 1 : 0;
        res.writeHead(202, {
          Location: `/v2/${repo}/blobs/uploads/${uuid}`,
          'Docker-Upload-UUID': uuid,
          'Docker-Distribution-Api-Version': 'registry/2.0',
          Range: `0-${rangeEnd}`,
          'Content-Length': 0
        });
        res.end();
        return;
      }

      if (method === 'PUT') {
        const expectedDigest = parsedUrl.searchParams.get('digest') || '';
        return this._finalizeUpload(req, res, upload, expectedDigest);
      }

      return sendOciError(res, 405, 'UNSUPPORTED', 'Method not allowed');
    }

    // 7. Manifests: HEAD|GET|PUT /v2/:name/manifests/:ref
    const manifestMatch = pathname.match(/^\/v2\/(.+)\/manifests\/([^/]+)$/);
    if (manifestMatch) {
      const repo = manifestMatch[1];
      const ref = manifestMatch[2];
      if (!REPO_NAME_RE.test(repo)) return sendOciError(res, 400, 'NAME_INVALID', 'Invalid repository name');
      if (!REFERENCE_RE.test(ref)) return sendOciError(res, 400, 'TAG_INVALID', 'Invalid manifest reference');

      if (method === 'HEAD' || method === 'GET') {
        const stored = this.getManifest(repo, ref);
        if (!stored) return sendOciError(res, 404, 'MANIFEST_UNKNOWN', 'manifest unknown');
        res.writeHead(200, {
          'Content-Type': stored.mediaType,
          'Docker-Distribution-Api-Version': 'registry/2.0',
          'Docker-Content-Digest': stored.digest,
          'Content-Length': stored.body.length
        });
        res.end(method === 'HEAD' ? undefined : stored.body);
        return;
      }

      if (method === 'PUT') {
        let body;
        try {
          body = await this._readBoundedBody(req, this.maxManifestBytes);
        } catch (err) {
          return sendOciError(res, err.status || 400, 'MANIFEST_INVALID', err.message);
        }
        if (body.length === 0) {
          return sendOciError(res, 400, 'MANIFEST_INVALID', 'Manifest body cannot be empty');
        }
        let parsed;
        try {
          parsed = JSON.parse(body.toString('utf8'));
        } catch (e) {
          return sendOciError(res, 400, 'MANIFEST_INVALID', 'Manifest must be valid JSON');
        }
        if (!parsed || typeof parsed !== 'object') {
          return sendOciError(res, 400, 'MANIFEST_INVALID', 'Manifest must be a JSON object');
        }
        // Verify that any referenced layer/config digests exist if layers array is present
        if (Array.isArray(parsed.layers)) {
          for (const layer of parsed.layers) {
            if (layer && typeof layer.digest === 'string' && DIGEST_RE.test(layer.digest) && !this.blobs.has(layer.digest)) {
              return sendOciError(res, 400, 'MANIFEST_BLOB_UNKNOWN', `Referenced layer blob not uploaded: ${layer.digest}`, { digest: layer.digest });
            }
          }
        }
        const digest = sha256Digest(body);
        if (DIGEST_RE.test(ref) && !safeEqual(ref, digest)) {
          this.stats.digestRejections++;
          return sendOciError(res, 400, 'DIGEST_INVALID', 'Manifest digest mismatch', { expected: ref, actual: digest });
        }

        const mediaType = String(
          req.headers['content-type'] ||
          parsed.mediaType ||
          'application/vnd.oci.image.manifest.v1+json'
        ).split(';')[0].trim();

        let repoMap = this.manifests.get(repo);
        if (!repoMap) {
          repoMap = new Map();
          this.manifests.set(repo, repoMap);
        }
        const record = { digest, mediaType, body };
        repoMap.set(ref, record);
        repoMap.set(digest, record);
        this.stats.manifestsPushed++;

        res.writeHead(201, {
          Location: `/v2/${repo}/manifests/${digest}`,
          'Docker-Content-Digest': digest,
          'Docker-Distribution-Api-Version': 'registry/2.0',
          'Content-Length': 0
        });
        res.end();
        return;
      }
      return sendOciError(res, 405, 'UNSUPPORTED', 'Method not allowed');
    }

    sendOciError(res, 404, 'UNSUPPORTED', `Unknown OCI v2 endpoint: ${pathname}`);
  }

  /**
   * Appends final bytes, verifies SHA-256 strictly, and atomically commits blob.
   * Rejects tampered content with HTTP 400 `DIGEST_INVALID`.
   *
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   * @param {any} upload
   * @param {string} expectedDigest
   */
  async _finalizeUpload(req, res, upload, expectedDigest) {
    if (!DIGEST_RE.test(String(expectedDigest || ''))) {
      this._cleanupUpload(upload);
      this.stats.digestRejections++;
      return sendOciError(res, 400, 'DIGEST_INVALID', 'Missing or malformed sha256 digest query parameter');
    }

    try {
      await this._appendRequestToUpload(req, upload);
    } catch (err) {
      this._cleanupUpload(upload);
      return sendOciError(res, err.status || 400, err.code || 'BLOB_UPLOAD_INVALID', err.message);
    }

    const actualDigest = `sha256:${upload.hasher.digest('hex')}`;
    if (!safeEqual(expectedDigest, actualDigest)) {
      this._cleanupUpload(upload);
      this.stats.digestRejections++;
      return sendOciError(
        res,
        400,
        'DIGEST_INVALID',
        'provided digest did not match uploaded content',
        { expected: expectedDigest, actual: actualDigest }
      );
    }

    const alreadyStored = this.blobs.has(actualDigest);
    if (alreadyStored) {
      this._cleanupUpload(upload);
    } else if (upload.tempPath && this.storageDir) {
      const destPath = path.join(this.storageDir, 'blobs', actualDigest.slice(7));
      try {
        fs.renameSync(upload.tempPath, destPath);
      } catch (e) {
        fs.copyFileSync(upload.tempPath, destPath);
        try { fs.unlinkSync(upload.tempPath); } catch (e2) {}
      }
      this.uploads.delete(upload.id);
      this.blobs.set(actualDigest, { size: upload.size, filePath: destPath, buf: null });
    } else {
      const fullBuf = upload.chunks.length === 1
        ? upload.chunks[0]
        : (upload.chunks.length > 0 ? Buffer.concat(upload.chunks, upload.size) : Buffer.alloc(0));
      this.uploads.delete(upload.id);
      upload.chunks = [];
      this.blobs.set(actualDigest, { size: fullBuf.length, filePath: null, buf: fullBuf });
    }

    this.stats.blobsUploaded++;
    this.stats.bytesUploaded += upload.size;

    res.writeHead(201, {
      Location: `/v2/${upload.repo}/blobs/${actualDigest}`,
      'Docker-Content-Digest': actualDigest,
      'Docker-Distribution-Api-Version': 'registry/2.0',
      'Content-Length': 0
    });
    res.end();
  }

  /**
   * Starts the loopback-only OCI Distribution v2 HTTP server.
   * @param {{ port?: number, host?: string }} [opts]
   */
  start({ port = 0, host = '127.0.0.1' } = {}) {
    const cleanHost = String(host || '127.0.0.1').trim();
    if (!LOOPBACK_HOSTS.has(cleanHost)) {
      return Promise.reject(new Error(`DirectPushRegistry must bind strictly to loopback (refused host: ${cleanHost})`));
    }
    if (this.running && this.server) {
      return Promise.resolve({ running: true, host: this.host, port: this.port, url: `http://${this.host}:${this.port}` });
    }
    return new Promise((resolve, reject) => {
      const srv = http.createServer((req, res) => {
        this._handleRequest(req, res).catch((err) => {
          if (!res.headersSent) {
            sendOciError(res, 500, 'INTERNAL_ERROR', err && err.message ? err.message : 'Internal registry error');
          }
        });
      });
      srv.once('error', reject);
      srv.listen(Number(port) || 0, cleanHost, () => {
        const addr = srv.address();
        this.server = srv;
        this.host = cleanHost === 'localhost' ? '127.0.0.1' : cleanHost;
        this.port = typeof addr === 'object' && addr ? addr.port : Number(port) || 0;
        this.running = true;
        resolve({ running: true, host: this.host, port: this.port, url: `http://${this.host}:${this.port}` });
      });
    });
  }

  /**
   * Stops the loopback server and cleans any incomplete upload temp files.
   * @returns {Promise<void>}
   */
  stop() {
    for (const u of Array.from(this.uploads.values())) {
      this._cleanupUpload(u);
    }
    const srv = this.server;
    this.server = null;
    this.running = false;
    this.port = 0;
    if (!srv) return Promise.resolve();
    return new Promise((resolve) => {
      try {
        if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
        srv.close(() => resolve(undefined));
      } catch (e) {
        resolve(undefined);
      }
    });
  }
}

/**
 * Factory for creating an isolated DirectPushRegistry instance.
 * @param {ConstructorParameters<typeof DirectPushRegistry>[0]} [options]
 */
function createDirectPushRegistry(options = {}) {
  return new DirectPushRegistry(options);
}

/**
 * Builds a zero-shell (`shell: false`) SSH loopback tunnel + OCI v2 layer-delta push plan.
 * Never constructs a shell command string — every executable step is an explicit `argv` array.
 *
 * @param {{
 *   image: string,
 *   serverId?: string,
 *   localPort?: number,
 *   remotePort?: number,
 *   sshHost?: string | null,
 *   sshUser?: string | null,
 *   sshPort?: number | null,
 *   keyPath?: string | null,
 *   direction?: 'push' | 'pull',
 *   targetTag?: string | null
 * }} opts
 */
function planDirectPush(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('planDirectPush requires an options object');
  }
  const rawImage = String(opts.image || '').trim();
  if (!rawImage || FORBIDDEN_SHELL_RE.test(rawImage) || !DOCKER_IMAGE_REF_RE.test(rawImage)) {
    throw new Error(`Invalid Docker image reference: "${rawImage.slice(0, 80)}"`);
  }

  const serverId = String(opts.serverId || 'local').trim().toLowerCase();
  if (!SERVER_ID_RE.test(serverId)) {
    throw new Error(`Invalid serverId: "${serverId.slice(0, 60)}"`);
  }

  const localPort = Number(opts.localPort ?? 5055);
  if (!Number.isInteger(localPort) || localPort < 1024 || localPort > 65535) {
    throw new Error(`Invalid localPort (expected 1024..65535): ${opts.localPort}`);
  }
  const remotePort = Number(opts.remotePort ?? localPort);
  if (!Number.isInteger(remotePort) || remotePort < 1024 || remotePort > 65535) {
    throw new Error(`Invalid remotePort (expected 1024..65535): ${opts.remotePort}`);
  }

  // Optionally enrich SSH metadata lazily from serverFleetManager (never forces eager load at boot)
  /** @type {any} */
  let fleetServer = null;
  if (serverId !== 'local' && !opts.sshHost) {
    try {
      const fleet = require('./serverFleetManager');
      if (fleet && typeof fleet.getServer === 'function') {
        fleetServer = fleet.getServer(serverId);
      }
    } catch (e) {}
  }

  const sshHost = String(opts.sshHost || fleetServer?.host || (serverId === 'local' ? '127.0.0.1' : `${serverId}.internal`)).trim();
  if (!HOST_SAFE_RE.test(sshHost) || FORBIDDEN_SHELL_RE.test(sshHost)) {
    throw new Error(`Invalid sshHost: "${sshHost.slice(0, 80)}"`);
  }
  const sshUser = String(opts.sshUser || fleetServer?.sshUser || 'root').trim();
  if (!SSH_USER_RE.test(sshUser)) {
    throw new Error(`Invalid sshUser: "${sshUser.slice(0, 40)}"`);
  }
  const sshPort = Number(opts.sshPort || fleetServer?.sshPort || 22);
  if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) {
    throw new Error(`Invalid sshPort: ${sshPort}`);
  }

  // Normalize repository + tag from source image (strip any existing registry prefix)
  const withoutDigest = rawImage.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');
  const hasTag = lastColon > lastSlash;
  const rawName = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const rawTag = String(opts.targetTag || (hasTag ? withoutDigest.slice(lastColon + 1) : 'latest')).trim();
  if (!REFERENCE_RE.test(rawTag)) {
    throw new Error(`Invalid targetTag: "${rawTag.slice(0, 64)}"`);
  }
  const nameSegments = rawName.split('/');
  const repoPath = (nameSegments.length > 1 && (nameSegments[0].includes('.') || nameSegments[0].includes(':')))
    ? nameSegments.slice(1).join('/')
    : rawName;
  const cleanRepo = repoPath.toLowerCase().replace(/[^a-z0-9._/-]/g, '-').replace(/^\/+|\/+$/g, '') || 'app';
  const direction = opts.direction === 'pull' ? 'pull' : 'push';

  const tunnelRegistryAddr = `127.0.0.1:${direction === 'push' ? localPort : remotePort}`;
  const targetImageRef = `${tunnelRegistryAddr}/${cleanRepo}:${rawTag}`;

  const sshArgv = [
    'ssh',
    '-N', '-T',
    '-p', String(sshPort),
    '-o', 'BatchMode=yes',
    '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    ...(opts.keyPath && !/[\r\n\0]/.test(String(opts.keyPath)) ? ['-i', String(opts.keyPath)] : []),
    direction === 'push' ? '-L' : '-R',
    direction === 'push'
      ? `127.0.0.1:${localPort}:127.0.0.1:${remotePort}`
      : `127.0.0.1:${remotePort}:127.0.0.1:${localPort}`,
    `${sshUser}@${sshHost}`
  ];

  const steps = [
    {
      step: 1,
      id: 'open_ssh_tunnel',
      description: direction === 'push'
        ? `Forward local 127.0.0.1:${localPort} -> remote ${sshHost} 127.0.0.1:${remotePort} over SSH`
        : `Reverse-forward remote ${sshHost} 127.0.0.1:${remotePort} -> local DirectPush 127.0.0.1:${localPort}`,
      bin: sshArgv[0],
      argv: sshArgv.slice(1),
      shell: false,
      skippedForLocal: serverId === 'local'
    },
    {
      step: 2,
      id: 'tag_loopback_ref',
      description: `Tag ${rawImage} as ${targetImageRef} for loopback OCI v2 transfer`,
      bin: 'docker',
      argv: ['tag', rawImage, targetImageRef],
      shell: false
    },
    {
      step: 3,
      id: 'oci_delta_push',
      description: `Push ONLY missing SHA-256 layers to ${targetImageRef} (existing layers skipped via HEAD /v2/.../blobs/:digest)`,
      bin: 'docker',
      argv: ['push', targetImageRef],
      shell: false
    }
  ];

  return {
    schemaVersion: 'culkibo.directpush/v1',
    protocol: 'oci-distribution-v2',
    zeroRegistryRequired: true,
    deltaTransfer: true,
    shell: false,
    direction,
    serverId,
    sourceImage: rawImage,
    repository: cleanRepo,
    tag: rawTag,
    targetImageRef,
    tunnel: {
      sshHost,
      sshUser,
      sshPort,
      localPort,
      remotePort,
      loopbackOnly: true,
      forwardFlag: direction === 'push' ? '-L' : '-R'
    },
    steps
  };
}

const defaultRegistryInstance = new DirectPushRegistry({
  storageDir: path.join(os.tmpdir(), 'culkibo-directpush-default')
});

const exported = Object.assign(defaultRegistryInstance, {
  DirectPushRegistry,
  createDirectPushRegistry,
  planDirectPush,
  sha256Digest
});

module.exports = exported;
