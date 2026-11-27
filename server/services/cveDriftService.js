'use strict';

/**
 * Culkibo Zero-Dep Runtime SBOM CVE Drift Scanner (OSV.dev Batch API).
 *
 * Guarantees:
 *  - 0 external npm dependencies (Node built-ins + native global `fetch` only).
 *  - Strictly allowlists ONLY `https://api.osv.dev/v1/querybatch` (zero arbitrary egress).
 *  - Chunks CycloneDX 1.6 PURLs into `<= 500`-item batches per OSV.dev batch limits.
 *  - Caches scan results for 24 hours atomically (`0o600`) in `CULKIBO_DATA_DIR/data/cve-cache.json`.
 *  - Clean offline-safe fallback (`offline: true`, `cached: boolean`) whenever network is disabled or unreachable.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const MAX_BATCH_SIZE = 500;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_TIMEOUT_MS = 10000;

/** @type {Record<string, number>} */
const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode.
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
 * Classifies an OSV vulnerability object into `'critical' | 'high' | 'medium' | 'low'`.
 * @param {any} vuln
 * @returns {'critical' | 'high' | 'medium' | 'low'}
 */
function classifyVulnSeverity(vuln) {
  if (!vuln || typeof vuln !== 'object') return 'low';

  const dbSev = String(vuln.database_specific?.severity || vuln.severityLabel || '').trim().toUpperCase();
  if (dbSev === 'CRITICAL') return 'critical';
  if (dbSev === 'HIGH') return 'high';
  if (dbSev === 'MODERATE' || dbSev === 'MEDIUM') return 'medium';
  if (dbSev === 'LOW') return 'low';

  if (typeof vuln.cvssScore === 'number' && Number.isFinite(vuln.cvssScore)) {
    if (vuln.cvssScore >= 9.0) return 'critical';
    if (vuln.cvssScore >= 7.0) return 'high';
    if (vuln.cvssScore >= 4.0) return 'medium';
    return 'low';
  }

  if (Array.isArray(vuln.severity)) {
    for (const entry of vuln.severity) {
      const rawScore = String(entry && entry.score || '').trim();
      const num = Number(rawScore);
      if (Number.isFinite(num) && num > 0) {
        if (num >= 9.0) return 'critical';
        if (num >= 7.0) return 'high';
        if (num >= 4.0) return 'medium';
        return 'low';
      }
      if (/^CVSS:3\./i.test(rawScore)) {
        if (/AV:N\/AC:L\/PR:N\/UI:N/.test(rawScore) && /C:H\/I:H\/A:H/.test(rawScore)) return 'critical';
        if (/C:H|I:H|A:H/.test(rawScore)) return 'high';
        return 'medium';
      }
    }
  }

  return 'medium';
}

/**
 * Extracts and deduplicates package URLs (`purl`) from a CycloneDX 1.6 SBOM, component list,
 * or falls back to Culkibo's local CycloneDX generator / `package-lock.json`.
 *
 * @param {{ sbom?: any, components?: Array<any> | null, rootDir?: string | null }} [opts]
 * @returns {Array<{ purl: string, name: string, version: string }>}
 */
function extractPurlsFromSbom(opts = {}) {
  /** @type {Map<string, { purl: string, name: string, version: string }>} */
  const map = new Map();

  /** @param {string} purl @param {string} [name] @param {string} [version] */
  const addPurl = (purl, name, version) => {
    const clean = String(purl || '').trim();
    if (!clean.startsWith('pkg:')) return;
    if (!map.has(clean)) {
      const derivedName = name || clean.replace(/^pkg:[^/]+\//, '').split('@')[0];
      const derivedVer = version || (clean.includes('@') ? clean.slice(clean.lastIndexOf('@') + 1) : '');
      map.set(clean, {
        purl: clean,
        name: String(derivedName || clean),
        version: String(derivedVer || '')
      });
    }
  };

  if (Array.isArray(opts.components) && opts.components.length > 0) {
    for (const c of opts.components) {
      if (typeof c === 'string') {
        addPurl(c);
      } else if (c && typeof c === 'object' && typeof c.purl === 'string') {
        addPurl(c.purl, c.name, c.version);
      }
    }
  } else if (opts.sbom && typeof opts.sbom === 'object' && Array.isArray(opts.sbom.components)) {
    for (const c of opts.sbom.components) {
      if (c && typeof c.purl === 'string') {
        addPurl(c.purl, c.name, c.version);
      }
    }
  } else {
    // Fallback 1: Culkibo's zero-dep CycloneDX 1.6 provenance generator
    try {
      const prov = require('../../scripts/release-provenance');
      if (prov && typeof prov.generateCycloneDxSbom === 'function') {
        const generated = prov.generateCycloneDxSbom(opts.rootDir ? { rootDir: opts.rootDir } : {});
        if (generated && Array.isArray(generated.components)) {
          for (const c of generated.components) {
            if (c && typeof c.purl === 'string') addPurl(c.purl, c.name, c.version);
          }
        }
      }
    } catch (e) {}

    // Fallback 2: package-lock.json directly
    if (map.size === 0) {
      try {
        const lockPath = path.join(opts.rootDir ? path.resolve(opts.rootDir) : path.resolve(__dirname, '..', '..'), 'package-lock.json');
        if (fs.existsSync(lockPath)) {
          const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
          if (lock && lock.packages && typeof lock.packages === 'object') {
            for (const [pkgPath, meta] of Object.entries(lock.packages)) {
              if (!pkgPath || !meta || meta.dev === true) continue;
              const idx = pkgPath.lastIndexOf('node_modules/');
              if (idx === -1) continue;
              const name = meta.name || pkgPath.slice(idx + 'node_modules/'.length);
              const ver = String(meta.version || '').trim();
              if (name && ver) {
                addPurl(`pkg:npm/${name.replace('@', '%40')}@${encodeURIComponent(ver)}`, name, ver);
              }
            }
          }
        }
      } catch (e) {}
    }
  }

  return Array.from(map.values()).sort((a, b) => a.purl.localeCompare(b.purl));
}

class CveDriftService {
  /**
   * @param {{ dataDir?: string | null, cacheTtlMs?: number }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
    this.cacheTtlMs = Number.isFinite(Number(opts.cacheTtlMs)) && Number(opts.cacheTtlMs) >= 1000
      ? Math.round(Number(opts.cacheTtlMs))
      : CACHE_TTL_MS;
    /** @type {any} */
    this._lastScanMemory = null;
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
  getCacheFilePath() {
    return path.join(this.resolveDataDir(), 'cve-cache.json');
  }

  /** @returns {any} */
  _loadCache() {
    const filePath = this.getCacheFilePath();
    if (!fs.existsSync(filePath)) return null;
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (e) {
      return null;
    }
  }

  /** @param {any} entry */
  _saveCache(entry) {
    // Respect test isolation: only write disk cache when CULKIBO_DATA_DIR or explicit dataDir is set, or outside NODE_ENV=test
    if (process.env.NODE_ENV === 'test' && !process.env.CULKIBO_DATA_DIR && !this._explicitDataDir) {
      this._lastScanMemory = entry.report;
      return;
    }
    atomicWriteFileSync(this.getCacheFilePath(), JSON.stringify(entry, null, 2) + '\n');
    this._lastScanMemory = entry.report;
  }

  /**
   * Returns the latest persisted or in-memory CVE drift scan report (or `null` if none).
   */
  getLastScan() {
    const disk = this._loadCache();
    if (disk && disk.report) return disk.report;
    return this._lastScanMemory;
  }

  /**
   * Scans CycloneDX 1.6 SBOM PURLs against strictly allowlisted `https://api.osv.dev/v1/querybatch`
   * in `<= 500`-item chunks, with 24h local caching and clean offline fallback.
   *
   * @param {{
   *   sbom?: any,
   *   components?: Array<any> | null,
   *   rootDir?: string | null,
   *   allowNetwork?: boolean,
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   forceRefresh?: boolean,
   *   timeoutMs?: number,
   *   nowMs?: number
   * }} [opts]
   */
  async scanSbom(opts = {}) {
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const allowNetwork = Boolean(opts.allowNetwork);
    const hasCustomFetch = typeof opts.fetchImpl === 'function';
    const forceRefresh = Boolean(opts.forceRefresh);
    const timeoutMs = Number.isFinite(Number(opts.timeoutMs)) && Number(opts.timeoutMs) >= 200
      ? Math.round(Number(opts.timeoutMs))
      : DEFAULT_TIMEOUT_MS;

    const packages = extractPurlsFromSbom({
      sbom: opts.sbom,
      components: opts.components,
      rootDir: opts.rootDir
    });
    const purlListHash = crypto
      .createHash('sha256')
      .update(packages.map((p) => p.purl).join('\n'), 'utf8')
      .digest('hex');

    const diskCache = this._loadCache();
    const cacheValid = Boolean(
      !forceRefresh &&
      diskCache &&
      diskCache.purlListHash === purlListHash &&
      typeof diskCache.cachedAtMs === 'number' &&
      (nowMs - diskCache.cachedAtMs) < this.cacheTtlMs &&
      diskCache.report
    );

    if (cacheValid) {
      return {
        ...diskCache.report,
        cached: true,
        offline: !allowNetwork && !hasCustomFetch
      };
    }

    // Offline mode (network disabled & no injected fetchImpl)
    if (!allowNetwork && !hasCustomFetch) {
      if (diskCache && diskCache.report) {
        return {
          ...diskCache.report,
          cached: true,
          offline: true,
          staleCache: true
        };
      }
      const offlineReport = {
        ok: true,
        source: 'offline_fallback',
        osvEndpoint: OSV_BATCH_URL,
        scannedPackages: packages.length,
        batchesSent: 0,
        vulnerablePackages: 0,
        totalVulnerabilities: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        offline: true,
        cached: false,
        scannedAt: new Date(nowMs).toISOString(),
        findings: []
      };
      this._lastScanMemory = offlineReport;
      return offlineReport;
    }

    // Online / injected-fetch mode: chunk strictly <= 500 items per OSV batch spec
    const fetcher = hasCustomFetch ? /** @type {any} */ (opts.fetchImpl) : globalThis.fetch;
    if (typeof fetcher !== 'function') {
      throw new Error('Global fetch is unavailable in this Node runtime');
    }

    /** @type {Array<any>} */
    const findings = [];
    const vulnerablePurlSet = new Set();
    let batchesSent = 0;

    try {
      for (let i = 0; i < packages.length; i += MAX_BATCH_SIZE) {
        const chunk = packages.slice(i, i + MAX_BATCH_SIZE);
        batchesSent++;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        if (timer.unref) timer.unref();

        let res;
        try {
          res = await fetcher(OSV_BATCH_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Accept: 'application/json',
              'User-Agent': 'culkibo-cve-drift-scanner/1.2'
            },
            body: JSON.stringify({
              queries: chunk.map((pkg) => ({ package: { purl: pkg.purl } }))
            }),
            signal: controller.signal
          });
        } finally {
          clearTimeout(timer);
        }

        if (!res || !res.ok) {
          throw new Error(`OSV.dev querybatch returned HTTP ${res ? res.status : 'unknown'}`);
        }
        const body = await res.json();
        const results = Array.isArray(body && body.results) ? body.results : [];

        for (let j = 0; j < chunk.length; j++) {
          const pkg = chunk[j];
          const entry = results[j];
          const vulns = Array.isArray(entry && entry.vulns) ? entry.vulns : [];
          if (vulns.length === 0) continue;
          vulnerablePurlSet.add(pkg.purl);
          for (const v of vulns) {
            if (!v || !v.id) continue;
            const severity = classifyVulnSeverity(v);
            findings.push({
              id: String(v.id),
              aliases: Array.isArray(v.aliases) ? v.aliases.slice(0, 8) : [],
              severity,
              severityRank: SEVERITY_RANK[severity] || 1,
              purl: pkg.purl,
              packageName: pkg.name,
              packageVersion: pkg.version,
              summary: String(v.summary || v.details || `Vulnerability ${v.id}`).slice(0, 240),
              modified: v.modified || null,
              referenceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(String(v.id))}`
            });
          }
        }
      }
    } catch (err) {
      const errMsg = err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : 'OSV network error';
      if (diskCache && diskCache.report) {
        return {
          ...diskCache.report,
          cached: true,
          offline: true,
          staleCache: true,
          networkError: errMsg
        };
      }
      return {
        ok: true,
        source: 'offline_fallback',
        osvEndpoint: OSV_BATCH_URL,
        scannedPackages: packages.length,
        batchesSent,
        vulnerablePackages: 0,
        totalVulnerabilities: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        offline: true,
        cached: false,
        networkError: errMsg,
        scannedAt: new Date(nowMs).toISOString(),
        findings: []
      };
    }

    findings.sort((a, b) => (b.severityRank - a.severityRank) || a.id.localeCompare(b.id));

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.severity in bySeverity) {
        bySeverity[/** @type {'critical' | 'high' | 'medium' | 'low'} */ (f.severity)]++;
      }
    }

    const report = {
      ok: true,
      source: 'osv.dev',
      osvEndpoint: OSV_BATCH_URL,
      scannedPackages: packages.length,
      batchesSent,
      vulnerablePackages: vulnerablePurlSet.size,
      totalVulnerabilities: findings.length,
      bySeverity,
      offline: false,
      cached: false,
      scannedAt: new Date(nowMs).toISOString(),
      findings
    };

    this._saveCache({
      schemaVersion: 1,
      cachedAtMs: nowMs,
      purlListHash,
      report
    });

    return report;
  }
}

const defaultCveDriftService = new CveDriftService();

const exported = Object.assign(defaultCveDriftService, {
  CveDriftService,
  OSV_BATCH_URL,
  MAX_BATCH_SIZE,
  CACHE_TTL_MS,
  extractPurlsFromSbom,
  classifyVulnSeverity
});

module.exports = exported;
