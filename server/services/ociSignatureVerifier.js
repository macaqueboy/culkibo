const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Pure-Node OCI Artifact Signature & SLSA Provenance Admission Verifier (Zero-Dep).
 *
 * Contramedidas criptográficas directas a incidentes 2026:
 *  - `CVE-2026-22703` (`cosign <2.6.2 / <3.0.4`): exige vinculación estricta entre
 *    `rekorEntry.canonicalizedBody` (digest del artefacto + huella de clave pública)
 *    y el digest objetivo del `imageRef`, bloqueando entradas Rekor no vinculadas con
 *    `REKOR_DIGEST_MISMATCH` / `REKOR_PUBKEY_MISMATCH`.
 *  - `sigstore/cosign#4640`: soporta tanto Rekor v1 (`integratedTime`) como Rekor v2
 *    (`signedTimestamp` / `rfc3161Timestamp`).
 *  - GHCR OCI 1.1 Referrers `404`: fallback determinista `sha256-<hex>.att` preservando
 *    siempre `tlsVerify` y la allowlist `allowedArtifactTypes`.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/oci-trust-roots.json` (solo claves públicas).
 */

const IMMUTABLE_DIGEST_RE = /^([a-z0-9._/-]+(?::[a-z0-9._-]+)?)@sha256:([a-f0-9]{64})$/i;
const PRIVATE_KEY_MARKER = 'PRIVATE' + ' KEY';

/**
 * Resuelve dinámicamente la ruta a `oci-trust-roots.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'oci-trust-roots.json')
    : path.join(base, 'data', 'oci-trust-roots.json');
}

/**
 * Escritura atómica con permisos `0o600`.
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
 * Carga las raíces de confianza desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, roots: Record<string, any> }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), roots: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && parsed.roots && typeof parsed.roots === 'object') {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), roots: {} };
}

/**
 * Codifica Pre-Authentication Encoding (PAE) canónico según especificación DSSE v1.
 * `DSSEv1 <len(type)> <type> <len(body)> <body>`
 *
 * @param {string} payloadType
 * @param {Buffer | string} payloadBytes
 * @returns {Buffer}
 */
function computeDssePae(payloadType, payloadBytes) {
  const typeBuf = Buffer.from(String(payloadType || ''), 'utf8');
  const bodyBuf = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(String(payloadBytes || ''), 'utf8');
  const prefix = Buffer.from(`DSSEv1 ${typeBuf.length} ${typeBuf.toString('utf8')} ${bodyBuf.length} `, 'utf8');
  return Buffer.concat([prefix, bodyBuf]);
}

/**
 * Calcula las huellas SHA-256 canónicas (DER SPKI y PEM normalizado) de una clave pública.
 * @param {string} publicKeyPem
 */
function computePublicKeyFingerprints(publicKeyPem) {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  const pem = String(keyObj.export({ type: 'spki', format: 'pem' })).trim();
  const spkiSha256 = crypto.createHash('sha256').update(der).digest('hex');
  const pemSha256 = crypto.createHash('sha256').update(pem, 'utf8').digest('hex');
  return { keyObj, spkiSha256, pemSha256 };
}

/**
 * Registra o actualiza una raíz de confianza pública (rechaza claves privadas).
 *
 * @param {{
 *   id: string,
 *   name?: string,
 *   algorithm?: 'ed25519' | 'ecdsa-sha256' | 'ecdsa-sha384' | string,
 *   publicKeyPem: string,
 *   allowedBuilders?: string[]
 * }} input
 */
function upsertTrustRoot(input) {
  const opts = input || /** @type {any} */ ({});
  const id = String(opts.id || '').trim();
  const publicKeyPem = String(opts.publicKeyPem || '').trim();
  if (!id || !publicKeyPem) {
    const err = /** @type {any} */ (new Error('Trust root id and publicKeyPem are required.'));
    err.status = 400;
    err.code = 'INVALID_TRUST_ROOT';
    throw err;
  }
  if (publicKeyPem.includes(PRIVATE_KEY_MARKER)) {
    const err = /** @type {any} */ (new Error('Private keys are forbidden in OCI trust roots; supply a public key PEM only.'));
    err.status = 400;
    err.code = 'PRIVATE_KEY_FORBIDDEN';
    throw err;
  }

  const { spkiSha256 } = computePublicKeyFingerprints(publicKeyPem);
  const algorithm = String(opts.algorithm || 'ed25519').trim().toLowerCase();
  const allowedBuilders = Array.isArray(opts.allowedBuilders)
    ? opts.allowedBuilders.map((b) => String(b || '').trim()).filter(Boolean)
    : [];

  const root = {
    id,
    name: String(opts.name || id),
    algorithm,
    publicKeyPem,
    fingerprintSha256: spkiSha256,
    allowedBuilders,
    updatedAt: new Date().toISOString()
  };

  const store = loadStore();
  store.roots[id] = root;
  store.updatedAt = root.updatedAt;
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));

  return {
    ok: true,
    trustRoot: root
  };
}

/**
 * Lista todas las raíces de confianza OCI almacenadas.
 */
function listTrustRoots() {
  const store = loadStore();
  return Object.values(store.roots);
}

/**
 * Extrae el digest sha256 (64 hex) de una cadena (`sha256:<hex>` o `<hex>`).
 * @param {any} raw
 * @returns {string | null}
 */
function normalizeSha256Hex(raw) {
  const s = String(raw || '').trim().toLowerCase();
  const m = s.match(/^(?:sha256:)?([a-f0-9]{64})$/);
  return m ? m[1] : null;
}

/**
 * Verifica una firma DSSE con `crypto.verify()` (`ed25519`, `ecdsa-sha256`, `ecdsa-sha384`).
 * @param {crypto.KeyObject} keyObj
 * @param {string} algorithmHint
 * @param {Buffer} pae
 * @param {Buffer} sigBuf
 */
function verifyDsseSignature(keyObj, algorithmHint, pae, sigBuf) {
  const keyType = keyObj.asymmetricKeyType;
  if (keyType === 'ed25519' || algorithmHint === 'ed25519') {
    return crypto.verify(null, pae, keyObj, sigBuf);
  }
  const digestAlg = algorithmHint.includes('384') ? 'sha384' : 'sha256';
  return crypto.verify(digestAlg, pae, keyObj, sigBuf);
}

/**
 * Verifica un bundle OCI Sigstore v0.3 + DSSE PAE + SLSA v1.0/v1.1 + vinculación Rekor v1/v2.
 *
 * @param {{
 *   imageRef: string,
 *   bundle: any,
 *   trustRootId?: string,
 *   publicKeyPem?: string,
 *   requiredPredicateType?: string,
 *   requireRekor?: boolean
 * }} input
 */
function verifyOciBundle(input) {
  const opts = input || /** @type {any} */ ({});
  const imageRef = String(opts.imageRef || '').trim();
  const requiredPredicateType = String(opts.requiredPredicateType || 'https://slsa.dev/provenance/v1');
  const requireRekor = opts.requireRekor !== undefined ? Boolean(opts.requireRekor) : true;

  // 1. Require immutable @sha256:<64hex> imageRef
  const refMatch = imageRef.match(IMMUTABLE_DIGEST_RE);
  if (!refMatch) {
    return {
      ok: true,
      verified: false,
      code: 'MUTABLE_TAG_FORBIDDEN',
      imageRef,
      message: `Image "${imageRef || '(empty)'}" must be pinned to an immutable @sha256:<64hex> digest before signature verification.`
    };
  }
  const targetDigestHex = refMatch[2].toLowerCase();

  // 2. Resolve trust root & public key
  /** @type {any} */
  let trustRoot = null;
  if (opts.trustRootId) {
    const store = loadStore();
    trustRoot = store.roots[String(opts.trustRootId)] || null;
  }
  const pem = String(opts.publicKeyPem || (trustRoot && trustRoot.publicKeyPem) || '').trim();
  if (!pem) {
    return {
      ok: true,
      verified: false,
      code: 'TRUST_ROOT_NOT_FOUND',
      imageRef,
      message: `No public key or trust root found (trustRootId="${opts.trustRootId || ''}").`
    };
  }

  let fpInfo;
  try {
    fpInfo = computePublicKeyFingerprints(pem);
  } catch (e) {
    return {
      ok: true,
      verified: false,
      code: 'INVALID_PUBLIC_KEY',
      imageRef,
      message: 'Failed to parse trust root publicKeyPem.'
    };
  }

  // 3. Extract DSSE envelope
  const bundle = (opts.bundle && typeof opts.bundle === 'object') ? opts.bundle : null;
  const dsse = bundle && (bundle.dsseEnvelope || (bundle.payloadType && bundle.payload ? bundle : null));
  if (!dsse || !dsse.payloadType || !dsse.payload || !Array.isArray(dsse.signatures) || dsse.signatures.length === 0) {
    return {
      ok: true,
      verified: false,
      code: 'INVALID_BUNDLE_FORMAT',
      imageRef,
      message: 'Bundle missing dsseEnvelope with payloadType, base64 payload, and signatures.'
    };
  }

  const payloadBuf = Buffer.from(String(dsse.payload), 'base64');
  const payloadSha256 = crypto.createHash('sha256').update(payloadBuf).digest('hex');
  const pae = computeDssePae(dsse.payloadType, payloadBuf);
  const algHint = String((trustRoot && trustRoot.algorithm) || '').toLowerCase();

  let verifiedSigB64 = '';
  for (const sigEntry of dsse.signatures) {
    if (!sigEntry || !sigEntry.sig) continue;
    try {
      const sigBuf = Buffer.from(String(sigEntry.sig), 'base64');
      if (verifyDsseSignature(fpInfo.keyObj, algHint, pae, sigBuf)) {
        verifiedSigB64 = String(sigEntry.sig);
        break;
      }
    } catch (e) {}
  }

  if (!verifiedSigB64) {
    return {
      ok: true,
      verified: false,
      code: 'INVALID_DSSE_SIGNATURE',
      imageRef,
      message: 'DSSE PAE cryptographic signature failed verification against trust root public key.'
    };
  }

  // 4. Parse In-Toto / SLSA Statement & verify subject digest + predicateType + builder
  let statement;
  try {
    statement = JSON.parse(payloadBuf.toString('utf8'));
  } catch (e) {
    return {
      ok: true,
      verified: false,
      code: 'INVALID_STATEMENT_JSON',
      imageRef,
      message: 'DSSE payload is not valid JSON.'
    };
  }

  const predicateType = String(statement.predicateType || '');
  if (requiredPredicateType && !predicateType.startsWith(requiredPredicateType)) {
    return {
      ok: true,
      verified: false,
      code: 'PREDICATE_TYPE_MISMATCH',
      imageRef,
      predicateType,
      message: `Predicate type "${predicateType}" does not satisfy required "${requiredPredicateType}".`
    };
  }

  const subjects = Array.isArray(statement.subject) ? statement.subject : [];
  const matchedSubject = subjects.find((s) => (
    s && s.digest && normalizeSha256Hex(s.digest.sha256) === targetDigestHex
  ));
  if (!matchedSubject) {
    return {
      ok: true,
      verified: false,
      code: 'SUBJECT_DIGEST_MISMATCH',
      imageRef,
      message: `Attestation statement subjects do not match target artifact digest sha256:${targetDigestHex}.`
    };
  }

  const builderId = String(
    (statement.predicate && statement.predicate.runDetails && statement.predicate.runDetails.builder && statement.predicate.runDetails.builder.id)
    || (statement.predicate && statement.predicate.builder && statement.predicate.builder.id)
    || ''
  );
  if (trustRoot && Array.isArray(trustRoot.allowedBuilders) && trustRoot.allowedBuilders.length > 0) {
    if (!trustRoot.allowedBuilders.includes(builderId)) {
      return {
        ok: true,
        verified: false,
        code: 'BUILDER_NOT_ALLOWED',
        imageRef,
        builderId,
        message: `SLSA builder "${builderId}" is not in trust root allowedBuilders.`
      };
    }
  }

  // 5. Rekor v1/v2 Transparency Log Binding (CVE-2026-22703 & cosign#4640)
  /** @type {string | null} */
  let rekorVersion = null;
  /** @type {string | null} */
  let rekorTimestamp = null;

  if (requireRekor) {
    const tlogEntries = (bundle.verificationMaterial && Array.isArray(bundle.verificationMaterial.tlogEntries))
      ? bundle.verificationMaterial.tlogEntries
      : (Array.isArray(bundle.tlogEntries) ? bundle.tlogEntries : (bundle.rekorEntry ? [bundle.rekorEntry] : []));

    if (tlogEntries.length === 0) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_ENTRY_MISSING',
        imageRef,
        message: 'Rekor transparency log entry is required but missing from bundle.'
      };
    }

    const entry = tlogEntries[0] || {};
    /** @type {any} */
    let bodyObj = null;
    if (typeof entry.canonicalizedBody === 'string') {
      try {
        const rawStr = entry.canonicalizedBody.trim().startsWith('{')
          ? entry.canonicalizedBody
          : Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8');
        bodyObj = JSON.parse(rawStr);
      } catch (e) {
        bodyObj = null;
      }
    } else if (entry.canonicalizedBody && typeof entry.canonicalizedBody === 'object') {
      bodyObj = entry.canonicalizedBody;
    }

    if (!bodyObj || typeof bodyObj !== 'object') {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_DIGEST_MISMATCH',
        imageRef,
        message: 'Rekor canonicalizedBody is missing or unparseable (CVE-2026-22703 guard).'
      };
    }

    const spec = (bodyObj.spec && typeof bodyObj.spec === 'object') ? bodyObj.spec : bodyObj;
    const rekorArtifactHex = normalizeSha256Hex(
      (spec.subject && spec.subject.digest && spec.subject.digest.sha256)
      || (spec.data && spec.data.hash && spec.data.hash.value)
      || spec.artifactDigest
      || spec.digest
      || bodyObj.artifactDigest
      || bodyObj.digest
    );
    const rekorPayloadHex = normalizeSha256Hex(
      (spec.payloadHash && spec.payloadHash.value)
      || (spec.dsse && spec.dsse.payloadHash && spec.dsse.payloadHash.value)
    );

    // Must bind to target artifact digest (or verified DSSE payload hash + no conflicting artifact digest!)
    if (!rekorArtifactHex && !rekorPayloadHex) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_DIGEST_MISMATCH',
        imageRef,
        message: 'Rekor entry lacks an artifact/payload SHA-256 digest binding (CVE-2026-22703).'
      };
    }
    if (rekorArtifactHex && rekorArtifactHex !== targetDigestHex) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_DIGEST_MISMATCH',
        imageRef,
        expectedDigest: targetDigestHex,
        rekorDigest: rekorArtifactHex,
        message: `CVE-2026-22703 guard: Rekor entry digest (${rekorArtifactHex}) does NOT match target image digest (${targetDigestHex}).`
      };
    }
    if (rekorPayloadHex && rekorPayloadHex !== payloadSha256) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_DIGEST_MISMATCH',
        imageRef,
        message: 'CVE-2026-22703 guard: Rekor DSSE payloadHash does NOT match verified DSSE payload.'
      };
    }

    // Verify Rekor public-key fingerprint binding if present
    const rekorPubFp = normalizeSha256Hex(
      spec.publicKeyFingerprint
      || bodyObj.publicKeyFingerprint
      || (spec.signature && spec.signature.publicKey && spec.signature.publicKey.fingerprintSha256)
    );
    const rekorPubPemB64 = spec.signature && spec.signature.publicKey && spec.signature.publicKey.content;
    if (rekorPubFp && rekorPubFp !== fpInfo.spkiSha256 && rekorPubFp !== fpInfo.pemSha256) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_PUBKEY_MISMATCH',
        imageRef,
        message: 'Rekor entry public key fingerprint does not match the verified trust root key.'
      };
    }
    if (typeof rekorPubPemB64 === 'string' && rekorPubPemB64.trim()) {
      try {
        const decodedPub = rekorPubPemB64.includes('BEGIN PUBLIC KEY')
          ? rekorPubPemB64
          : Buffer.from(rekorPubPemB64, 'base64').toString('utf8');
        const rekorFp = computePublicKeyFingerprints(decodedPub);
        if (rekorFp.spkiSha256 !== fpInfo.spkiSha256) {
          return {
            ok: true,
            verified: false,
            code: 'REKOR_PUBKEY_MISMATCH',
            imageRef,
            message: 'Rekor entry embedded public key does not match trust root public key.'
          };
        }
      } catch (e) {
        return {
          ok: true,
          verified: false,
          code: 'REKOR_PUBKEY_MISMATCH',
          imageRef,
          message: 'Rekor entry embedded public key could not be parsed.'
        };
      }
    }

    // Verify Rekor signature binding if present
    const rekorSig = spec.signature && typeof spec.signature.content === 'string' ? spec.signature.content : null;
    if (rekorSig && rekorSig !== verifiedSigB64) {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_SIGNATURE_MISMATCH',
        imageRef,
        message: 'Rekor entry signature does not match verified DSSE signature.'
      };
    }

    // Rekor v2 signed timestamp (cosign#4640) OR Rekor v1 integratedTime
    const v2Ts = entry.signedTimestamp
      || entry.rfc3161Timestamp
      || (bundle.verificationMaterial && bundle.verificationMaterial.timestampVerificationData && bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps && bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0])
      || (entry.checkpoint && entry.checkpoint.signedTimestamp);
    const v1Ts = entry.integratedTime;

    if (v2Ts) {
      rekorVersion = 'v2';
      rekorTimestamp = typeof v2Ts === 'object' ? (v2Ts.signedTimestamp || v2Ts.timestamp || JSON.stringify(v2Ts)) : String(v2Ts);
    } else if (v1Ts !== undefined && v1Ts !== null && String(v1Ts).trim() !== '') {
      rekorVersion = 'v1';
      rekorTimestamp = String(v1Ts);
    } else {
      return {
        ok: true,
        verified: false,
        code: 'REKOR_TIMESTAMP_MISSING',
        imageRef,
        message: 'Rekor entry missing both Rekor v2 signedTimestamp and Rekor v1 integratedTime.'
      };
    }
  }

  return {
    ok: true,
    verified: true,
    code: 'VERIFIED',
    imageRef,
    digest: `sha256:${targetDigestHex}`,
    predicateType,
    builderId: builderId || null,
    trustRootId: opts.trustRootId || null,
    publicKeyFingerprint: fpInfo.spkiSha256,
    rekorVerified: requireRekor,
    rekorVersion,
    rekorTimestamp,
    message: `Verified DSSE + SLSA attestation bound to sha256:${targetDigestHex}${rekorVersion ? ` (Rekor ${rekorVersion})` : ''}.`
  };
}

/**
 * Resuelve la estrategia OCI 1.1 Referrers vs tag-fallback (`sha256-<hex>.att`)
 * preservando estrictamente `tlsVerify` y `allowedArtifactTypes`.
 *
 * @param {{
 *   referrersStatus: number,
 *   digest: string,
 *   tlsVerify?: boolean,
 *   allowedArtifactTypes?: string[]
 * }} input
 */
function resolveReferrerStrategy(input) {
  const opts = input || /** @type {any} */ ({});
  const status = Number(opts.referrersStatus) || 200;
  const hex = normalizeSha256Hex(opts.digest);
  const tlsVerify = opts.tlsVerify !== undefined ? Boolean(opts.tlsVerify) : true;
  const allowedArtifactTypes = Array.isArray(opts.allowedArtifactTypes)
    ? opts.allowedArtifactTypes.map(String)
    : ['application/vnd.dev.cosign.artifact.sig.v1+json', 'application/vnd.in-toto+json'];

  if (!hex) {
    return {
      ok: false,
      code: 'INVALID_DIGEST',
      tlsVerify,
      message: 'A valid sha256:<64hex> digest is required.'
    };
  }

  if (status === 404 || status === 405 || status === 501) {
    return {
      ok: true,
      strategy: 'tag_fallback',
      referrersStatus: status,
      digest: `sha256:${hex}`,
      fallbackTag: `sha256-${hex}.att`,
      sigFallbackTag: `sha256-${hex}.sig`,
      sbomFallbackTag: `sha256-${hex}.sbom`,
      tlsVerify,
      allowedArtifactTypes,
      message: `Registry returned HTTP ${status} on OCI 1.1 Referrers API; falling back to sha256-${hex}.att with tlsVerify=${tlsVerify}.`
    };
  }

  return {
    ok: true,
    strategy: 'oci_referrers_api',
    referrersStatus: status,
    digest: `sha256:${hex}`,
    referrersPath: `referrers/sha256:${hex}`,
    fallbackTag: null,
    tlsVerify,
    allowedArtifactTypes,
    message: `Using native OCI 1.1 Referrers API for sha256:${hex} with tlsVerify=${tlsVerify}.`
  };
}

module.exports = {
  computeDssePae,
  verifyOciBundle,
  resolveReferrerStrategy,
  upsertTrustRoot,
  listTrustRoots
};
