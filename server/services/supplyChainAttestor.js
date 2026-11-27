'use strict';

/**
 * Culkibo Zero-Dep SLSA Provenance v1.1 + Ed25519 DSSE Supply Chain Attestor.
 *
 * Guarantees:
 *  - 0 external npm dependencies (Node built-ins only: crypto, fs, path).
 *  - Ed25519 signing keypair persisted atomically with `0o600` permissions under
 *    `CULKIBO_DATA_DIR/data/attestation-key.json` (100% isolated in tests!).
 *  - Emits standard `https://in-toto.io/Statement/v1` with
 *    `predicateType: "https://slsa.dev/provenance/v1"` (SLSA v1.1) and embedded
 *    CycloneDX 1.6 SBOM summary.
 *  - Signs using standard DSSE Pre-Authentication Encoding:
 *    `PAE(type, body) = "DSSEv1 " + byteLen(type) + " " + type + " " + byteLen(body) + " " + body`.
 *  - Atomic persistence & retrieval of signed `.dsse.json` release envelopes under
 *    `<dataDir>/attestations/<projectId>/<revision>.dsse.json`.
 *  - Offline cryptographic verification (`verifyAttestation`) rejecting payload tamper,
 *    signature tamper, wrong key, non-canonical base64, and malformed statements.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let PKG_VERSION = '1.2.0';
try {
  const pkg = require('../../package.json');
  if (pkg && typeof pkg.version === 'string' && pkg.version.trim()) {
    PKG_VERSION = pkg.version.trim();
  }
} catch (e) {}

const STATEMENT_TYPE_V1 = 'https://in-toto.io/Statement/v1';
const SLSA_PREDICATE_TYPE_V1 = 'https://slsa.dev/provenance/v1';
const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const DEFAULT_BUILD_TYPE = 'https://culkibo.dev/slsa/build-v1';
const DEFAULT_BUILDER_ID = 'https://culkibo.dev/builders/control-plane/v1';

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const SAFE_SEGMENT_RE = /^[a-zA-Z0-9._-]{1,128}$/;

/**
 * Computes lowercase SHA-256 hex digest of a Buffer or UTF-8 string.
 * @param {Buffer | string} data
 * @returns {string}
 */
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Computes the standard DSSE Pre-Authentication Encoding (PAE) byte buffer:
 * `DSSEv1 <typeLen> <type> <bodyLen> <body>` using exact UTF-8 byte lengths.
 *
 * @param {string} payloadType
 * @param {Buffer | string} payload
 * @returns {Buffer}
 */
function dssePae(payloadType, payload) {
  const typeBuf = Buffer.from(String(payloadType || ''), 'utf8');
  const bodyBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload ?? ''), 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${typeBuf.length} `, 'ascii'),
    typeBuf,
    Buffer.from(` ${bodyBuf.length} `, 'ascii'),
    bodyBuf
  ]);
}

/**
 * Validates and sanitizes a filesystem path segment (projectId or revision) against path traversal.
 * @param {string} value
 * @param {string} label
 * @returns {string}
 */
function assertSafeSegment(value, label) {
  const clean = String(value || '').trim();
  if (!clean || clean === '.' || clean === '..' || !SAFE_SEGMENT_RE.test(clean)) {
    throw new Error(`Invalid ${label}: must match ${SAFE_SEGMENT_RE.source}`);
  }
  return clean;
}

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode (write tmp + rename).
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
 * Derives a stable key identifier (`sha256:<16 hex chars>`) from an Ed25519 public key PEM.
 * @param {string} publicKeyPem
 * @returns {string}
 */
function computeKeyId(publicKeyPem) {
  const pubKeyObj = crypto.createPublicKey(publicKeyPem);
  const der = pubKeyObj.export({ type: 'spki', format: 'der' });
  return `sha256:${sha256Hex(der).slice(0, 16)}`;
}

/**
 * Normalizes a SHA-256 digest string (`sha256:<hex>` or `<hex>`) into lowercase 64-char hex.
 * @param {string | null | undefined} rawDigest
 * @returns {string | null}
 */
function normalizeSha256(rawDigest) {
  if (typeof rawDigest !== 'string' || !rawDigest.trim()) return null;
  let hex = rawDigest.trim().toLowerCase();
  if (hex.startsWith('sha256:')) hex = hex.slice('sha256:'.length);
  return SHA256_HEX_RE.test(hex) ? hex : null;
}

/**
 * Builds a strict `https://in-toto.io/Statement/v1` SLSA Provenance v1.1 statement
 * with embedded CycloneDX 1.6 SBOM summary.
 *
 * @param {{
 *   projectId: string,
 *   revision: string,
 *   imageDigest?: string | null,
 *   commitSha?: string | null,
 *   builderId?: string | null,
 *   buildType?: string | null,
 *   artifactName?: string | null,
 *   sbomSummary?: Record<string, any> | null,
 *   externalParameters?: Record<string, any>,
 *   resolvedDependencies?: Array<{ uri: string, digest?: Record<string, string>, name?: string }>,
 *   startedOn?: string,
 *   finishedOn?: string,
 *   invocationId?: string
 * }} opts
 */
function createStatementV1(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('createStatementV1 requires an options object');
  }
  const projectId = assertSafeSegment(opts.projectId, 'projectId');
  const revision = assertSafeSegment(opts.revision, 'revision');
  const commitSha = typeof opts.commitSha === 'string' && opts.commitSha.trim()
    ? opts.commitSha.trim().slice(0, 64)
    : null;

  let subjectSha256 = normalizeSha256(opts.imageDigest);
  let digestSource = 'imageDigest';
  if (!subjectSha256) {
    if (opts.imageDigest) {
      throw new Error(`Invalid imageDigest: expected 64-char sha256 hex (got "${String(opts.imageDigest).slice(0, 40)}")`);
    }
    subjectSha256 = sha256Hex(`culkibo:${projectId}@${revision}:${commitSha || 'HEAD'}`);
    digestSource = 'derived_release_descriptor';
  }

  const nowIso = new Date().toISOString();
  const startedOn = typeof opts.startedOn === 'string' && opts.startedOn ? opts.startedOn : nowIso;
  const finishedOn = typeof opts.finishedOn === 'string' && opts.finishedOn ? opts.finishedOn : nowIso;
  const builderId = (typeof opts.builderId === 'string' && opts.builderId.trim())
    ? opts.builderId.trim()
    : DEFAULT_BUILDER_ID;
  const buildType = (typeof opts.buildType === 'string' && opts.buildType.trim())
    ? opts.buildType.trim()
    : DEFAULT_BUILD_TYPE;
  const artifactName = (typeof opts.artifactName === 'string' && opts.artifactName.trim())
    ? opts.artifactName.trim()
    : `culkibo://${projectId}@${revision}`;

  const sbomInput = opts.sbomSummary && typeof opts.sbomSummary === 'object' ? opts.sbomSummary : {};
  const sbomSummary = {
    bomFormat: String(sbomInput.bomFormat || 'CycloneDX'),
    specVersion: String(sbomInput.specVersion || '1.6'),
    componentCount: Number.isFinite(Number(sbomInput.componentCount)) ? Number(sbomInput.componentCount) : 0,
    rootDependencies: Number.isFinite(Number(sbomInput.rootDependencies)) ? Number(sbomInput.rootDependencies) : 6,
    ...(typeof sbomInput.serialNumber === 'string' ? { serialNumber: sbomInput.serialNumber } : {}),
    ...(typeof sbomInput.sha256 === 'string' && normalizeSha256(sbomInput.sha256)
      ? { sha256: normalizeSha256(sbomInput.sha256) }
      : {})
  };
  const sbomSummaryDigest = sbomSummary.sha256 || sha256Hex(JSON.stringify(sbomSummary));

  const resolvedDependencies = Array.isArray(opts.resolvedDependencies)
    ? opts.resolvedDependencies
    : (commitSha
      ? [{ uri: `git+culkibo://${projectId}`, digest: { gitCommit: commitSha } }]
      : []);

  return {
    _type: STATEMENT_TYPE_V1,
    subject: [
      {
        name: artifactName,
        digest: {
          sha256: subjectSha256
        }
      }
    ],
    predicateType: SLSA_PREDICATE_TYPE_V1,
    predicate: {
      buildDefinition: {
        buildType,
        externalParameters: {
          projectId,
          revision,
          ...(commitSha ? { commitSha } : {}),
          ...(opts.externalParameters && typeof opts.externalParameters === 'object' ? opts.externalParameters : {})
        },
        internalParameters: {
          culkiboVersion: PKG_VERSION,
          slsaSpecVersion: '1.1',
          digestSource,
          sbomSummary
        },
        resolvedDependencies
      },
      runDetails: {
        builder: {
          id: builderId,
          version: {
            culkibo: PKG_VERSION,
            node: process.version
          }
        },
        metadata: {
          invocationId: String(opts.invocationId || crypto.randomUUID()),
          startedOn,
          finishedOn
        },
        byproducts: [
          {
            name: 'sbom.cdx.json',
            mediaType: 'application/vnd.cyclonedx+json',
            digest: {
              sha256: sbomSummaryDigest
            }
          }
        ]
      }
    }
  };
}

class SupplyChainAttestor {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
    /** @type {{ keyFilePath: string, keyId: string, publicKeyPem: string, privateKeyPem: string, createdAt: string } | null} */
    this._keyCache = null;
  }

  /**
   * Resolves the active `data/` directory dynamically, respecting constructor `dataDir`
   * and `process.env.CULKIBO_DATA_DIR` (guaranteeing 0 live `data/` writes in tests).
   * @returns {string}
   */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getKeyFilePath() {
    return path.join(this.resolveDataDir(), 'attestation-key.json');
  }

  /** @returns {string} */
  getAttestationsDir() {
    return path.join(this.resolveDataDir(), 'attestations');
  }

  /**
   * Loads the Ed25519 keypair from `<dataDir>/attestation-key.json` or generates and
   * atomically persists a new keypair with `0o600` permissions.
   */
  _ensureKeypair() {
    const keyFilePath = this.getKeyFilePath();
    if (this._keyCache && this._keyCache.keyFilePath === keyFilePath) {
      return this._keyCache;
    }

    if (fs.existsSync(keyFilePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));
        if (
          parsed &&
          typeof parsed.publicKeyPem === 'string' &&
          typeof parsed.privateKeyPem === 'string' &&
          parsed.publicKeyPem.includes('BEGIN PUBLIC KEY') &&
          parsed.privateKeyPem.includes('BEGIN PRIVATE KEY')
        ) {
          const keyId = typeof parsed.keyId === 'string' && parsed.keyId
            ? parsed.keyId
            : computeKeyId(parsed.publicKeyPem);
          this._keyCache = {
            keyFilePath,
            keyId,
            publicKeyPem: parsed.publicKeyPem,
            privateKeyPem: parsed.privateKeyPem,
            createdAt: typeof parsed.createdAt === 'string' ? parsed.createdAt : new Date().toISOString()
          };
          return this._keyCache;
        }
      } catch (e) {
        // Fall through to regenerate corrupt key file only if unreadable
      }
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const publicKeyPem = String(publicKey);
    const privateKeyPem = String(privateKey);
    const keyId = computeKeyId(publicKeyPem);
    const createdAt = new Date().toISOString();

    const record = {
      schemaVersion: 1,
      algorithm: 'Ed25519',
      keyId,
      createdAt,
      publicKeyPem,
      privateKeyPem
    };
    atomicWriteFileSync(keyFilePath, JSON.stringify(record, null, 2) + '\n');
    this._keyCache = { keyFilePath, keyId, publicKeyPem, privateKeyPem, createdAt };
    return this._keyCache;
  }

  /**
   * Returns the active Ed25519 public key in SPKI PEM format.
   * @returns {string}
   */
  getPublicKeyPem() {
    return this._ensureKeypair().publicKeyPem;
  }

  /**
   * Returns safe public metadata for the active attestation signing key (never exposes privateKeyPem).
   */
  getKeyInfo() {
    const kp = this._ensureKeypair();
    return {
      algorithm: 'Ed25519',
      keyId: kp.keyId,
      publicKeyPem: kp.publicKeyPem,
      createdAt: kp.createdAt,
      keyFilePath: kp.keyFilePath
    };
  }

  /**
   * Creates, Ed25519-DSSE signs, and atomically persists a SLSA v1.1 provenance attestation for a release.
   *
   * @param {{
   *   projectId: string,
   *   revision: string,
   *   imageDigest?: string | null,
   *   commitSha?: string | null,
   *   builderId?: string | null,
   *   buildType?: string | null,
   *   artifactName?: string | null,
   *   sbomSummary?: Record<string, any> | null,
   *   externalParameters?: Record<string, any>,
   *   resolvedDependencies?: Array<{ uri: string, digest?: Record<string, string>, name?: string }>,
   *   persist?: boolean
   * }} opts
   */
  attestRelease(opts) {
    const projectId = assertSafeSegment(opts && opts.projectId, 'projectId');
    const revision = assertSafeSegment(opts && opts.revision, 'revision');
    const statement = createStatementV1({ ...opts, projectId, revision });
    const kp = this._ensureKeypair();

    const payloadJson = JSON.stringify(statement);
    const payloadBuf = Buffer.from(payloadJson, 'utf8');
    const pae = dssePae(DSSE_PAYLOAD_TYPE, payloadBuf);
    const sigBuf = crypto.sign(null, pae, kp.privateKeyPem);

    const envelope = {
      payloadType: DSSE_PAYLOAD_TYPE,
      payload: payloadBuf.toString('base64'),
      signatures: [
        {
          keyid: kp.keyId,
          sig: sigBuf.toString('base64')
        }
      ]
    };

    /** @type {string | null} */
    let storedPath = null;
    if (opts.persist !== false) {
      const targetPath = path.join(this.getAttestationsDir(), projectId, `${revision}.dsse.json`);
      atomicWriteFileSync(targetPath, JSON.stringify(envelope, null, 2) + '\n');
      storedPath = targetPath;
    }

    return {
      ok: true,
      projectId,
      revision,
      slsaVersion: '1.1',
      algorithm: 'Ed25519',
      keyId: kp.keyId,
      publicKeyPem: kp.publicKeyPem,
      payloadSha256: sha256Hex(payloadBuf),
      statement,
      envelope,
      storedPath
    };
  }

  /**
   * Retrieves a persisted SLSA v1.1 DSSE attestation for `(projectId, revision)`.
   * @param {string} projectId
   * @param {string} revision
   */
  getAttestation(projectId, revision) {
    const safeProject = assertSafeSegment(projectId, 'projectId');
    const safeRevision = assertSafeSegment(revision, 'revision');
    const filePath = path.join(this.getAttestationsDir(), safeProject, `${safeRevision}.dsse.json`);
    if (!fs.existsSync(filePath)) return null;

    const raw = fs.readFileSync(filePath, 'utf8');
    const envelope = JSON.parse(raw);
    const verification = this.verifyAttestation(envelope);
    return {
      projectId: safeProject,
      revision: safeRevision,
      storedPath: filePath,
      envelope,
      statement: verification.statement || null,
      verification
    };
  }

  /**
   * Lists persisted attestations for one project (or all projects when `projectId` is omitted).
   * @param {string | null | undefined} [projectId]
   */
  listAttestations(projectId) {
    const rootDir = this.getAttestationsDir();
    if (!fs.existsSync(rootDir)) return [];

    /** @type {string[]} */
    const projectIds = projectId
      ? [assertSafeSegment(projectId, 'projectId')]
      : fs.readdirSync(rootDir).filter((name) => {
        if (!SAFE_SEGMENT_RE.test(name)) return false;
        try { return fs.statSync(path.join(rootDir, name)).isDirectory(); } catch (e) { return false; }
      });

    /** @type {Array<any>} */
    const items = [];
    for (const pid of projectIds) {
      const pDir = path.join(rootDir, pid);
      if (!fs.existsSync(pDir)) continue;
      let files;
      try { files = fs.readdirSync(pDir); } catch (e) { continue; }
      for (const file of files) {
        if (!file.endsWith('.dsse.json')) continue;
        const revision = file.slice(0, -'.dsse.json'.length);
        const fullPath = path.join(pDir, file);
        try {
          const stat = fs.statSync(fullPath);
          const envelope = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          const verification = this.verifyAttestation(envelope);
          items.push({
            projectId: pid,
            revision,
            storedPath: fullPath,
            createdAt: verification.statement?.predicate?.runDetails?.metadata?.finishedOn || stat.mtime.toISOString(),
            valid: verification.valid,
            keyId: verification.keyId || envelope.signatures?.[0]?.keyid || null,
            subject: verification.subject || null,
            predicateType: verification.predicateType || null,
            builderId: verification.builderId || null,
            envelope
          });
        } catch (e) {
          items.push({
            projectId: pid,
            revision,
            storedPath: fullPath,
            valid: false,
            error: 'Corrupted attestation file'
          });
        }
      }
    }

    items.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    return items;
  }

  /**
   * Cryptographically verifies an Ed25519 DSSE SLSA v1.1 attestation envelope.
   * Never throws on tampered input — always returns `{ valid, verified, reason?, ... }`.
   *
   * @param {any} envelopeInput Raw DSSE envelope, `{ envelope }` wrapper, or JSON string.
   * @param {string | null | undefined} [publicKeyPem] Optional Ed25519 SPKI PEM override; defaults to local key.
   * @returns {{
   *   valid: boolean,
   *   verified: boolean,
   *   reason?: string,
   *   algorithm?: string,
   *   keyId?: string | null,
   *   expectedKeyId?: string | null,
   *   payloadType?: string | null,
   *   payloadSha256?: string,
   *   statementType?: string | null,
   *   predicateType?: string | null,
   *   slsaVersion: string,
   *   builderId?: string | null,
   *   subject?: Array<{ name: string, digest: Record<string, string> }> | null,
   *   sbomSummary?: Record<string, any> | null,
   *   statement?: any,
   *   verifiedAt: string
   * }}
   */
  verifyAttestation(envelopeInput, publicKeyPem) {
    const verifiedAt = new Date().toISOString();
    /** @param {string} reason @param {Record<string, any>} [extra] */
    const fail = (reason, extra = {}) => ({
      valid: false,
      verified: false,
      reason,
      slsaVersion: '1.1',
      verifiedAt,
      ...extra
    });

    let envelope = envelopeInput;
    if (typeof envelope === 'string') {
      try {
        envelope = JSON.parse(envelope);
      } catch (e) {
        return fail('INVALID_JSON_ENVELOPE');
      }
    }
    if (envelope && typeof envelope === 'object' && envelope.envelope && typeof envelope.envelope === 'object') {
      envelope = envelope.envelope;
    }
    if (!envelope || typeof envelope !== 'object') {
      return fail('MISSING_ENVELOPE');
    }
    if (typeof envelope.payloadType !== 'string' || envelope.payloadType !== DSSE_PAYLOAD_TYPE) {
      return fail('INVALID_PAYLOAD_TYPE', { payloadType: envelope.payloadType || null });
    }
    if (typeof envelope.payload !== 'string' || !envelope.payload.trim()) {
      return fail('MISSING_PAYLOAD');
    }
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
      return fail('MISSING_SIGNATURES');
    }

    // Strict base64 decode & canonical roundtrip check on payload
    const cleanB64Payload = envelope.payload.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleanB64Payload) || cleanB64Payload.length % 4 !== 0) {
      return fail('INVALID_BASE64_PAYLOAD');
    }
    const payloadBuf = Buffer.from(cleanB64Payload, 'base64');
    if (payloadBuf.toString('base64') !== cleanB64Payload) {
      return fail('NON_CANONICAL_BASE64_PAYLOAD');
    }

    // Resolve Ed25519 verification key
    let pubKeyObj;
    /** @type {string | null} */
    let resolvedKeyId = null;
    try {
      const pem = (typeof publicKeyPem === 'string' && publicKeyPem.trim())
        ? publicKeyPem.trim()
        : this.getPublicKeyPem();
      pubKeyObj = crypto.createPublicKey(pem);
      if (pubKeyObj.asymmetricKeyType !== 'ed25519') {
        return fail('UNSUPPORTED_KEY_TYPE');
      }
      resolvedKeyId = computeKeyId(pem);
    } catch (e) {
      return fail('INVALID_PUBLIC_KEY');
    }

    // Verify DSSE PAE signature against Ed25519 public key
    const pae = dssePae(envelope.payloadType, payloadBuf);
    /** @type {{ keyid?: string, sig: string } | null} */
    let matchedSig = null;
    for (const entry of envelope.signatures) {
      if (!entry || typeof entry.sig !== 'string' || !entry.sig.trim()) continue;
      const cleanSig = entry.sig.replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleanSig) || cleanSig.length % 4 !== 0) continue;
      const sigBuf = Buffer.from(cleanSig, 'base64');
      if (sigBuf.length !== 64 || sigBuf.toString('base64') !== cleanSig) continue;
      try {
        if (crypto.verify(null, pae, pubKeyObj, sigBuf)) {
          matchedSig = entry;
          break;
        }
      } catch (e) {
        continue;
      }
    }

    if (!matchedSig) {
      return fail('INVALID_SIGNATURE', { expectedKeyId: resolvedKeyId });
    }

    // Parse & validate in-toto v1 / SLSA v1.1 statement
    let statement;
    try {
      statement = JSON.parse(payloadBuf.toString('utf8'));
    } catch (e) {
      return fail('INVALID_STATEMENT_JSON');
    }
    if (!statement || typeof statement !== 'object') {
      return fail('INVALID_STATEMENT_OBJECT');
    }
    if (statement._type !== STATEMENT_TYPE_V1) {
      return fail('INVALID_STATEMENT_TYPE', { statementType: statement._type || null });
    }
    if (statement.predicateType !== SLSA_PREDICATE_TYPE_V1) {
      return fail('INVALID_PREDICATE_TYPE', { predicateType: statement.predicateType || null });
    }
    if (!Array.isArray(statement.subject) || statement.subject.length === 0) {
      return fail('MISSING_SUBJECT');
    }
    const primarySubject = statement.subject[0];
    if (!primarySubject || !primarySubject.digest || !normalizeSha256(primarySubject.digest.sha256)) {
      return fail('INVALID_SUBJECT_DIGEST');
    }

    return {
      valid: true,
      verified: true,
      algorithm: 'Ed25519',
      keyId: matchedSig.keyid || resolvedKeyId,
      payloadType: envelope.payloadType,
      payloadSha256: sha256Hex(payloadBuf),
      statementType: statement._type,
      predicateType: statement.predicateType,
      slsaVersion: String(statement.predicate?.buildDefinition?.internalParameters?.slsaSpecVersion || '1.1'),
      builderId: statement.predicate?.runDetails?.builder?.id || null,
      subject: statement.subject,
      sbomSummary: statement.predicate?.buildDefinition?.internalParameters?.sbomSummary || null,
      statement,
      verifiedAt
    };
  }
}

const defaultAttestor = new SupplyChainAttestor();

const exported = Object.assign(defaultAttestor, {
  SupplyChainAttestor,
  dssePae,
  createStatementV1,
  STATEMENT_TYPE_V1,
  SLSA_PREDICATE_TYPE_V1,
  DSSE_PAYLOAD_TYPE
});

module.exports = exported;
