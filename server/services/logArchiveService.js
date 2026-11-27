'use strict';

/**
 * Culkibo Zero-Dep Compressed `.ndjson.gz` Persistent Log Archive & ReDoS-Safe Search.
 *
 * Cures `coolify#12170` & `dokploy#2270/#6112` (lost container logs across redeploys):
 *  - Appends native RFC 1952 concatenated gzip NDJSON chunks per project & UTC day under
 *    `CULKIBO_DATA_DIR/data/log-archives/<safeProjectId>/<YYYY-MM-DD>.ndjson.gz` (`0o600`).
 *  - Enforces strict `retentionDays` and `maxArchiveMb` pruning (deleting oldest shards first)
 *    so VPS disk never exhausts.
 *  - ReDoS-safe regex validator (`assertSafeRegex`) rejecting nested quantifiers (`(a+)+`,
 *    `([a-zA-Z]+)*`), lookarounds, backreferences, and oversized patterns before compilation.
 *  - 0 external npm dependencies (`fs`, `path`, `zlib` only).
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const DEFAULT_MAX_ARCHIVE_MB = 50;
const DEFAULT_RETENTION_DAYS = 30;
const MAX_REGEX_LENGTH = 120;
const MAX_SEARCH_LIMIT = 2000;
const SAFE_PROJECT_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const DATE_SHARD_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validates that a user-supplied regex pattern is safe against catastrophic backtracking (ReDoS).
 * Rejects patterns > 120 chars, backreferences (`\1..\9`), lookarounds (`(?<=`, `(?<!`, `(?=`, `(?!`),
 * and any quantified group containing nested quantifiers or alternations (e.g. `(a+)+`, `([a-zA-Z]+)*`, `(a|aa)+`).
 *
 * @param {string} pattern
 * @returns {RegExp}
 */
function assertSafeRegex(pattern) {
  /** @param {string} msg */
  const fail = (msg) => {
    const err = /** @type {any} */ (new Error(msg));
    err.code = 'UNSAFE_REGEX';
    err.status = 400;
    throw err;
  };

  if (typeof pattern !== 'string' || !pattern.trim()) {
    fail('Regex pattern must be a non-empty string');
  }
  if (pattern.length > MAX_REGEX_LENGTH) {
    fail(`Regex pattern exceeds max length (${MAX_REGEX_LENGTH} chars)`);
  }
  if (/[\r\n\0]/.test(pattern)) {
    fail('Regex pattern contains disallowed control characters');
  }
  // Block backreferences (\1..\9) and lookahead/lookbehind assertions
  if (/\\[1-9]/.test(pattern) || /\(\?[<!=]/.test(pattern)) {
    fail('Backreferences and lookaround assertions are not allowed in log search regex');
  }
  // Direct consecutive or character-class nested quantifiers: `a++`, `[a-z]+*`, `a**`
  if (/(?:[+*?]|\{\d+,?\d*\})\s*[+*?{]/.test(pattern)) {
    fail('Nested quantifiers detected in regex (ReDoS risk)');
  }

  // Structural parenthesis stack check: reject any group containing `+`, `*`, `?`, `{`, or `|`
  // that is itself repeated by `+`, `*`, `?`, or `{m,n}` (catches `(a+)+`, `([a-zA-Z]+)*`, `((a+))+`, `(a|aa)+`)
  /** @type {Array<{ hasQuantOrAlt: boolean }>} */
  const stack = [];
  let inCharClass = false;
  let escaped = false;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === ']' && inCharClass) {
      inCharClass = false;
      continue;
    }
    if (inCharClass) continue;

    if (ch === '(') {
      stack.push({ hasQuantOrAlt: false });
      continue;
    }
    if (ch === ')') {
      const grp = stack.pop();
      const next = pattern[i + 1] || '';
      const groupQuantified = next === '+' || next === '*' || next === '?' || next === '{';
      if (grp && grp.hasQuantOrAlt && groupQuantified) {
        fail('Catastrophic backtracking nested quantifier group rejected (ReDoS protection)');
      }
      if (grp && (grp.hasQuantOrAlt || groupQuantified) && stack.length > 0) {
        stack[stack.length - 1].hasQuantOrAlt = true;
      }
      continue;
    }
    if ((ch === '+' || ch === '*' || ch === '?' || ch === '{' || ch === '|') && stack.length > 0) {
      stack[stack.length - 1].hasQuantOrAlt = true;
    }
  }

  try {
    return new RegExp(pattern, 'i');
  } catch (e) {
    fail(`Invalid regular expression syntax: ${e && /** @type {any} */ (e).message}`);
    throw new Error('unreachable');
  }
}

/**
 * Validates `projectId` strictly against path traversal and illegal path characters.
 * @param {string} projectId
 * @returns {string}
 */
function assertSafeProjectId(projectId) {
  const clean = String(projectId || '').trim();
  if (!clean || clean.includes('..') || !SAFE_PROJECT_ID_RE.test(clean)) {
    const err = /** @type {any} */ (new Error(`Invalid projectId for log archive: "${clean.slice(0, 64)}"`));
    err.code = 'INVALID_PROJECT_ID';
    err.status = 400;
    throw err;
  }
  return clean;
}

/**
 * Resolves a UTC date shard string (`YYYY-MM-DD`).
 * @param {string | Date | number | null | undefined} [raw]
 * @returns {string}
 */
function normalizeDateShard(raw) {
  if (typeof raw === 'string' && DATE_SHARD_RE.test(raw.trim())) {
    return raw.trim();
  }
  const dt = raw instanceof Date ? raw : (raw !== undefined && raw !== null ? new Date(raw) : new Date());
  if (Number.isNaN(dt.getTime())) return new Date().toISOString().slice(0, 10);
  return dt.toISOString().slice(0, 10);
}

class LogArchiveService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
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
  getArchivesRootDir() {
    return path.join(this.resolveDataDir(), 'log-archives');
  }

  /**
   * Resolves and verifies containment of `<dataDir>/log-archives/<safeProjectId>`.
   * @param {string} projectId
   * @returns {string}
   */
  getProjectArchiveDir(projectId) {
    const safeId = assertSafeProjectId(projectId);
    const root = path.resolve(this.getArchivesRootDir());
    const target = path.resolve(root, safeId);
    const rel = path.relative(root, target);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
      const err = /** @type {any} */ (new Error('Log archive path escaped archive root'));
      err.code = 'PATH_TRAVERSAL_BLOCKED';
      err.status = 400;
      throw err;
    }
    return target;
  }

  /**
   * Lists `.ndjson.gz` shard files for a project sorted oldest-first by date string.
   * @param {string} projectDir
   * @returns {Array<{ date: string, name: string, filePath: string, sizeBytes: number }>}
   */
  _listProjectShards(projectDir) {
    if (!fs.existsSync(projectDir)) return [];
    /** @type {Array<{ date: string, name: string, filePath: string, sizeBytes: number }>} */
    const shards = [];
    for (const name of fs.readdirSync(projectDir)) {
      if (!name.endsWith('.ndjson.gz')) continue;
      const date = name.slice(0, -'.ndjson.gz'.length);
      if (!DATE_SHARD_RE.test(date)) continue;
      const filePath = path.join(projectDir, name);
      try {
        const stat = fs.statSync(filePath);
        if (stat.isFile()) {
          shards.push({ date, name, filePath, sizeBytes: stat.size });
        }
      } catch (e) {}
    }
    shards.sort((a, b) => a.date.localeCompare(b.date));
    return shards;
  }

  /**
   * Prunes expired shards older than `retentionDays` and oldest shards exceeding `maxArchiveMb`.
   *
   * @param {string} projectId
   * @param {{ maxArchiveMb?: number, retentionDays?: number, nowMs?: number }} [opts]
   */
  pruneArchives(projectId, opts = {}) {
    const projectDir = this.getProjectArchiveDir(projectId);
    const maxArchiveMb = Number.isFinite(Number(opts.maxArchiveMb)) && Number(opts.maxArchiveMb) > 0
      ? Number(opts.maxArchiveMb)
      : DEFAULT_MAX_ARCHIVE_MB;
    const retentionDays = Number.isFinite(Number(opts.retentionDays)) && Number(opts.retentionDays) >= 1
      ? Math.round(Number(opts.retentionDays))
      : DEFAULT_RETENTION_DAYS;
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const maxBytes = Math.max(128, Math.round(maxArchiveMb * 1024 * 1024));
    const cutoffDateStr = new Date(nowMs - retentionDays * 86400 * 1000).toISOString().slice(0, 10);

    const shards = this._listProjectShards(projectDir);
    /** @type {string[]} */
    const prunedFiles = [];
    let prunedBytes = 0;

    // 1. Prune by retentionDays (oldest dates first)
    /** @type {typeof shards} */
    const kept = [];
    for (const sh of shards) {
      if (sh.date < cutoffDateStr) {
        try {
          fs.unlinkSync(sh.filePath);
          prunedFiles.push(sh.name);
          prunedBytes += sh.sizeBytes;
        } catch (e) {
          kept.push(sh);
        }
      } else {
        kept.push(sh);
      }
    }

    // 2. Prune oldest shards while total size exceeds maxArchiveMb (keep newest shard if only 1 left)
    let totalBytes = kept.reduce((acc, s) => acc + s.sizeBytes, 0);
    while (totalBytes > maxBytes && kept.length > 1) {
      const oldest = kept.shift();
      if (!oldest) break;
      try {
        fs.unlinkSync(oldest.filePath);
        prunedFiles.push(oldest.name);
        prunedBytes += oldest.sizeBytes;
        totalBytes -= oldest.sizeBytes;
      } catch (e) {
        break;
      }
    }

    return {
      ok: true,
      projectId,
      prunedFiles,
      prunedBytes,
      remainingFiles: kept.length,
      totalBytes
    };
  }

  /**
   * Appends compressed NDJSON log records to `<projectId>/<YYYY-MM-DD>.ndjson.gz`
   * (RFC 1952 concatenated gzip stream) and enforces retention + MB pruning automatically.
   *
   * @param {string} projectId
   * @param {Array<{ ts?: string, level?: string, releaseId?: string | null, stream?: string, message: string }>} entries
   * @param {{ dateStr?: string, maxArchiveMb?: number, retentionDays?: number, nowMs?: number }} [opts]
   */
  appendLogs(projectId, entries, opts = {}) {
    const safeId = assertSafeProjectId(projectId);
    const projectDir = this.getProjectArchiveDir(safeId);
    const list = Array.isArray(entries) ? entries : [];
    const shardDate = normalizeDateShard(opts.dateStr || (list[0] && list[0].ts) || null);
    const shardPath = path.join(projectDir, `${shardDate}.ndjson.gz`);

    if (list.length === 0) {
      const stats = this.getArchiveStats(safeId);
      return {
        ok: true,
        projectId: safeId,
        file: `${shardDate}.ndjson.gz`,
        appended: 0,
        bytesAdded: 0,
        prunedFiles: [],
        totalBytes: stats.totalBytes
      };
    }

    const lines = [];
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      const rec = {
        ts: typeof raw.ts === 'string' && raw.ts.trim() ? raw.ts.trim() : `${shardDate}T${new Date().toISOString().slice(11)}`,
        level: String(raw.level || 'info').trim().toLowerCase().slice(0, 16),
        releaseId: raw.releaseId ? String(raw.releaseId).trim().slice(0, 128) : null,
        stream: String(raw.stream || 'stdout').trim().toLowerCase().slice(0, 16),
        message: String(raw.message ?? '').slice(0, 8192)
      };
      lines.push(JSON.stringify(rec));
    }

    const ndjson = lines.join('\n') + '\n';
    const gzChunk = zlib.gzipSync(Buffer.from(ndjson, 'utf8'), { level: 6 });

    fs.mkdirSync(projectDir, { recursive: true });
    fs.appendFileSync(shardPath, gzChunk, { mode: 0o600 });
    try { fs.chmodSync(shardPath, 0o600); } catch (e) {}

    const pruneRes = this.pruneArchives(safeId, {
      maxArchiveMb: opts.maxArchiveMb,
      retentionDays: opts.retentionDays,
      nowMs: opts.nowMs
    });

    return {
      ok: true,
      projectId: safeId,
      file: `${shardDate}.ndjson.gz`,
      appended: lines.length,
      bytesAdded: gzChunk.length,
      prunedFiles: pruneRes.prunedFiles,
      totalBytes: pruneRes.totalBytes
    };
  }

  /**
   * Searches compressed `.ndjson.gz` log shards for a project with strict ReDoS regex validation.
   *
   * @param {{
   *   projectId: string,
   *   since?: string | null,
   *   until?: string | null,
   *   level?: string | null,
   *   releaseId?: string | null,
   *   query?: string | null,
   *   regex?: string | null,
   *   limit?: number
   * }} opts
   */
  searchArchives(opts) {
    if (!opts || typeof opts !== 'object') {
      throw new Error('searchArchives requires an options object');
    }
    const safeId = assertSafeProjectId(opts.projectId);
    const compiledRegex = opts.regex ? assertSafeRegex(opts.regex) : null;
    const limit = Math.max(1, Math.min(MAX_SEARCH_LIMIT, Math.round(Number(opts.limit) || 200)));

    const levelFilter = opts.level ? String(opts.level).trim().toLowerCase() : null;
    const releaseFilter = opts.releaseId ? String(opts.releaseId).trim() : null;
    const queryLower = opts.query ? String(opts.query).trim().toLowerCase() : null;
    const sinceDate = opts.since ? String(opts.since).trim().slice(0, 10) : null;
    const untilDate = opts.until ? String(opts.until).trim().slice(0, 10) : null;
    const sinceMs = opts.since && Number.isFinite(Date.parse(opts.since)) ? Date.parse(opts.since) : null;
    const untilMs = opts.until && Number.isFinite(Date.parse(opts.until)) ? Date.parse(opts.until) : null;

    const projectDir = this.getProjectArchiveDir(safeId);
    const allShards = this._listProjectShards(projectDir);
    const matchingShards = allShards.filter((sh) => {
      if (sinceDate && DATE_SHARD_RE.test(sinceDate) && sh.date < sinceDate) return false;
      if (untilDate && DATE_SHARD_RE.test(untilDate) && sh.date > untilDate) return false;
      return true;
    });

    /** @type {Array<any>} */
    const entries = [];
    let filesScanned = 0;
    let totalMatches = 0;
    let truncated = false;

    for (const sh of matchingShards) {
      filesScanned++;
      let plain;
      try {
        plain = zlib.gunzipSync(fs.readFileSync(sh.filePath)).toString('utf8');
      } catch (e) {
        continue;
      }
      const lines = plain.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        let rec;
        try { rec = JSON.parse(line); } catch (e) { continue; }
        if (!rec || typeof rec !== 'object') continue;

        if (levelFilter && String(rec.level || '').toLowerCase() !== levelFilter) continue;
        if (releaseFilter && String(rec.releaseId || '') !== releaseFilter) continue;
        if (sinceMs !== null || untilMs !== null) {
          const recMs = Date.parse(String(rec.ts || ''));
          if (Number.isFinite(recMs)) {
            if (sinceMs !== null && recMs < sinceMs) continue;
            if (untilMs !== null && recMs > untilMs) continue;
          }
        }
        const msg = String(rec.message || '');
        if (queryLower && !msg.toLowerCase().includes(queryLower)) continue;
        if (compiledRegex && !compiledRegex.test(msg)) continue;

        totalMatches++;
        if (entries.length < limit) {
          entries.push({ ...rec, shard: sh.date });
        } else {
          truncated = true;
        }
      }
    }

    return {
      ok: true,
      projectId: safeId,
      filesScanned,
      totalMatches,
      truncated,
      entries
    };
  }

  /**
   * Returns compressed archive statistics for one project or across all archived projects.
   * @param {string | null | undefined} [projectId]
   */
  getArchiveStats(projectId) {
    if (projectId) {
      const safeId = assertSafeProjectId(projectId);
      const shards = this._listProjectShards(this.getProjectArchiveDir(safeId));
      const totalBytes = shards.reduce((acc, s) => acc + s.sizeBytes, 0);
      return {
        projectId: safeId,
        shardCount: shards.length,
        totalBytes,
        totalMb: Number((totalBytes / (1024 * 1024)).toFixed(4)),
        oldestDate: shards.length > 0 ? shards[0].date : null,
        newestDate: shards.length > 0 ? shards[shards.length - 1].date : null,
        shards: shards.map((s) => ({ date: s.date, file: s.name, sizeBytes: s.sizeBytes }))
      };
    }

    const root = this.getArchivesRootDir();
    if (!fs.existsSync(root)) {
      return { projectCount: 0, shardCount: 0, totalBytes: 0, totalMb: 0, projects: [] };
    }
    const projects = [];
    let totalBytes = 0;
    let shardCount = 0;
    for (const dirName of fs.readdirSync(root)) {
      if (!SAFE_PROJECT_ID_RE.test(dirName)) continue;
      const full = path.join(root, dirName);
      try {
        if (!fs.statSync(full).isDirectory()) continue;
      } catch (e) {
        continue;
      }
      const st = this.getArchiveStats(dirName);
      projects.push(st);
      totalBytes += st.totalBytes;
      shardCount += st.shardCount;
    }
    return {
      projectCount: projects.length,
      shardCount,
      totalBytes,
      totalMb: Number((totalBytes / (1024 * 1024)).toFixed(4)),
      projects
    };
  }
}

const defaultLogArchiveService = new LogArchiveService();

const exported = Object.assign(defaultLogArchiveService, {
  LogArchiveService,
  assertSafeRegex,
  DEFAULT_MAX_ARCHIVE_MB,
  DEFAULT_RETENTION_DAYS,
  SAFE_PROJECT_ID_RE
});

module.exports = exported;
