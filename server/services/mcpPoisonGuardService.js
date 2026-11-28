'use strict';

/**
 * Culkibo Zero-Trust MCP Tool-Poisoning & Rug-Pull Manifest Guard.
 *
 * Cures `CVE-2025-54136` ("MCPoison" — CVSS 7.2 name-bound trust enabling post-approval
 * MCP rug-pull RCE) and covert tool-description prompt injection / Unicode Tag steganography
 * in zero runtime npm dependencies:
 *  - Atomic `0o600` pinned manifest store in `CULKIBO_DATA_DIR/data/mcp-poison-guard.json`.
 *  - Canonical sorted-key SHA-256 hashing over every tool's `(name, description, inputSchema, command)`.
 *  - `pinToolManifest` (defaults `dryRun: true`) pins approved tool hashes per `serverId`.
 *  - `verifyToolManifest` detects ANY post-approval 1-char drift, unpinned addition, or tampering
 *    (`MCP_RUG_PULL_DETECTED`).
 *  - `scanToolPoisoning` catches `<IMPORTANT>` / `<SYSTEM>` covert tags, instruction overrides,
 *    `.ssh`/`.env`/credential exfiltration prompts, and invisible Unicode Tag runes
 *    `U+E0000..U+E007F` (`MCP_TOOL_POISONING_DETECTED`).
 *  - `auditAgentToolScope` enforces least-privilege role-to-tool scopes (`EXCESSIVE_TOOL_SCOPE`).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROLE_DENIED_TOOL_PATTERNS = Object.freeze({
  viewer: [/(?:delete|destroy|exec|shell|reap|kill|rotate|promote|write|mutate|deploy|restart|rollback|revoke|issue)/i],
  developer: [/(?:rotate_kek|destroy_node|delete_team|grant_superadmin)/i],
  admin: []
});

const POISONING_RULES = Object.freeze([
  Object.freeze({
    id: 'COVERT_DIRECTIVE_TAG',
    severity: 'critical',
    pattern: /<\s*(?:IMPORTANT|SYSTEM|HIDDEN|INSTRUCTIONS|ASSISTANT_OVERRIDE)\s*>/i,
    reason: 'Covert XML-style prompt-injection directive tag detected inside MCP metadata/output'
  }),
  Object.freeze({
    id: 'PROMPT_OVERRIDE_DIRECTIVE',
    severity: 'critical',
    pattern: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?previous|do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user|override\s+system\s+prompt)\b/i,
    reason: 'Prompt-override or user-concealment instruction detected'
  }),
  Object.freeze({
    id: 'SENSITIVE_FILE_EXFIL_PROMPT',
    severity: 'critical',
    pattern: /(?:~\/\.ssh\/|\.ssh\/id_(?:rsa|ed25519)|\.aws\/credentials|\/etc\/shadow|\bread\s+(?:the\s+)?(?:\.env|id_rsa|private\s+key)|exfiltrat(?:e|ion)\s+.*(?:secret|token|key|\.env|ssh))/i,
    reason: 'Covert credential / SSH key / .env exfiltration instruction detected'
  }),
  Object.freeze({
    id: 'COVERT_SHELL_EXEC_PROMPT',
    severity: 'high',
    pattern: /\b(?:curl|wget)\s+[^\n]*\|\s*(?:sh|bash)\b/i,
    reason: 'Covert remote shell pipe execution instruction embedded in tool metadata'
  })
]);

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
 * Creates an HTTP-annotated Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function poisonError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Deterministic canonical JSON serialization (recursive lexicographical key sort).
 * @param {any} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',') + '}';
}

/**
 * Computes the canonical SHA-256 hex digest over an MCP tool definition's security-critical fields:
 * `(name, description, inputSchema, command)`.
 *
 * @param {{
 *   name?: string,
 *   description?: string,
 *   inputSchema?: any,
 *   command?: any
 * }} toolDef
 * @returns {string}
 */
function hashToolDefinition(toolDef) {
  const src = toolDef && typeof toolDef === 'object' ? toolDef : {};
  const canonicalPayload = canonicalJson({
    name: typeof src.name === 'string' ? src.name : '',
    description: typeof src.description === 'string' ? src.description : '',
    inputSchema: src.inputSchema !== undefined ? src.inputSchema : null,
    command: src.command !== undefined ? src.command : null
  });
  return crypto.createHash('sha256').update(canonicalPayload, 'utf8').digest('hex');
}

/**
 * Scans arbitrary text (or an array of tool definitions) for covert prompt injections,
 * credential exfiltration directives, and invisible Unicode Tag runes (`U+E0000..U+E007F`).
 *
 * @param {{
 *   text?: string,
 *   source?: string,
 *   tools?: any[]
 * } | string} input
 */
function scanToolPoisoning(input) {
  const src = typeof input === 'string'
    ? { text: input, source: 'raw_text' }
    : (input && typeof input === 'object' ? input : {});
  const source = typeof src.source === 'string' && src.source.trim()
    ? src.source.trim().slice(0, 128)
    : 'tool_description';

  /** @type {Array<{ label: string, content: string }>} */
  const targets = [];
  if (typeof src.text === 'string' && src.text.length > 0) {
    targets.push({ label: source, content: src.text });
  }
  if (Array.isArray(src.tools)) {
    for (const t of src.tools) {
      if (!t || typeof t !== 'object') continue;
      const name = String(t.name || 'unnamed_tool');
      const combined = [
        typeof t.description === 'string' ? t.description : '',
        t.inputSchema ? JSON.stringify(t.inputSchema) : '',
        t.command ? (typeof t.command === 'string' ? t.command : JSON.stringify(t.command)) : ''
      ].join('\n');
      targets.push({ label: `tool:${name}`, content: combined });
    }
  }

  /** @type {Array<{ ruleId: string, severity: 'critical' | 'high', location: string, reason: string }>} */
  const findings = [];
  let invisibleTagCount = 0;

  for (const target of targets) {
    // 1. Scan for invisible Unicode Tag block runes U+E0000..U+E007F (smuggled covert instructions!)
    let targetTagRunes = 0;
    for (const ch of target.content) {
      const cp = ch.codePointAt(0);
      if (cp !== undefined && cp >= 0xE0000 && cp <= 0xE007F) {
        targetTagRunes += 1;
      }
    }
    if (targetTagRunes > 0) {
      invisibleTagCount += targetTagRunes;
      findings.push({
        ruleId: 'INVISIBLE_UNICODE_TAG_RUNES',
        severity: 'critical',
        location: target.label,
        reason: `Detected ${targetTagRunes} invisible Unicode Tag rune(s) in U+E0000..U+E007F (covert prompt smuggling)`
      });
    }

    // 2. Scan regex rules for covert directive tags & exfil prompts
    for (const rule of POISONING_RULES) {
      if (rule.pattern.test(target.content)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          location: target.label,
          reason: rule.reason
        });
      }
    }
  }

  const blocked = findings.length > 0;
  const riskScore = Math.min(
    100,
    findings.reduce((sum, f) => sum + (f.severity === 'critical' ? 45 : 25), 0)
  );

  return {
    ok: true,
    safe: !blocked,
    blocked,
    code: blocked ? 'MCP_TOOL_POISONING_DETECTED' : 'CLEAN',
    source,
    invisibleTagCount,
    findingCount: findings.length,
    findings,
    riskScore
  };
}

/**
 * Audits requested MCP tools against an agent role's explicit allowlist and least-privilege bounds.
 *
 * @param {{
 *   role?: string,
 *   allowedTools?: string[] | null,
 *   requestedTools?: string[]
 * }} [input]
 */
function auditAgentToolScope(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const role = String(src.role || 'viewer').trim().toLowerCase();
  const requestedTools = Array.isArray(src.requestedTools)
    ? Array.from(new Set(src.requestedTools.map((t) => String(t || '').trim()).filter(Boolean)))
    : [];
  const hasExplicitAllowlist = Array.isArray(src.allowedTools);
  const allowedTools = hasExplicitAllowlist
    ? Array.from(new Set(/** @type {string[]} */ (src.allowedTools).map((t) => String(t || '').trim()).filter(Boolean)))
    : [];
  const allowedSet = new Set(allowedTools);
  const roleDeniedPatterns = /** @type {RegExp[]} */ (
    ROLE_DENIED_TOOL_PATTERNS[/** @type {'viewer' | 'developer' | 'admin'} */ (role)] || ROLE_DENIED_TOOL_PATTERNS.viewer
  );

  /** @type {Array<{ tool: string, reason: string }>} */
  const excessiveTools = [];
  for (const tool of requestedTools) {
    if (hasExplicitAllowlist && !allowedSet.has(tool) && !allowedSet.has('*')) {
      excessiveTools.push({
        tool,
        reason: `Tool "${tool}" is outside explicit allowlist for role "${role}"`
      });
      continue;
    }
    if (!hasExplicitAllowlist && roleDeniedPatterns.some((re) => re.test(tool))) {
      excessiveTools.push({
        tool,
        reason: `Tool "${tool}" violates least-privilege scope for role "${role}"`
      });
    }
  }

  const blocked = excessiveTools.length > 0;
  return {
    ok: true,
    allowed: !blocked,
    blocked,
    code: blocked ? 'EXCESSIVE_TOOL_SCOPE' : 'SCOPE_VALID',
    role,
    requestedTools,
    allowedTools,
    excessiveTools
  };
}

class McpPoisonGuardService {
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
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'mcp-poison-guard.json');
  }

  /** @returns {Record<string, any>} */
  _loadManifests() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && parsed.manifests && typeof parsed.manifests === 'object' ? parsed.manifests : {};
    } catch (e) {
      return {};
    }
  }

  /** @param {Record<string, any>} manifests */
  _saveManifests(manifests) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), manifests }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `hashToolDefinition`.
   * @param {Record<string, any>} toolDef
   */
  hashToolDefinition(toolDef) {
    return hashToolDefinition(toolDef);
  }

  /**
   * Delegates to `scanToolPoisoning`.
   * @param {any} input
   */
  scanToolPoisoning(input) {
    return scanToolPoisoning(input);
  }

  /**
   * Delegates to `auditAgentToolScope`.
   * @param {Record<string, any>} [input]
   */
  auditAgentToolScope(input) {
    return auditAgentToolScope(input);
  }

  /**
   * Computes canonical SHA-256 hashes for all tools of `serverId` and pins the manifest.
   * Refuses to pin poisoned tools automatically. Defaults to `dryRun: true`.
   *
   * @param {{
   *   serverId: string,
   *   tools: any[],
   *   approver?: string,
   *   dryRun?: boolean
   * }} input
   */
  pinToolManifest(input) {
    if (!input || typeof input !== 'object') {
      throw poisonError('INVALID_INPUT', 'pinToolManifest requires { serverId, tools }');
    }
    const serverId = typeof input.serverId === 'string' ? input.serverId.trim().slice(0, 128) : '';
    if (!serverId) throw poisonError('INVALID_SERVER_ID', 'serverId is required');
    if (!Array.isArray(input.tools) || input.tools.length === 0) {
      throw poisonError('INVALID_TOOLS', 'tools must be a non-empty array of MCP tool definitions');
    }
    const approver = typeof input.approver === 'string' && input.approver.trim()
      ? input.approver.trim().slice(0, 128)
      : 'admin';
    const dryRun = input.dryRun !== undefined ? Boolean(input.dryRun) : true;

    // Pre-pin poisoning scan prevents pinning already-poisoned metadata
    const scan = scanToolPoisoning({ tools: input.tools, source: `server:${serverId}` });
    if (scan.blocked) {
      return {
        ok: false,
        pinned: false,
        blocked: true,
        dryRun,
        code: /** @type {'MCP_TOOL_POISONING_DETECTED'} */ ('MCP_TOOL_POISONING_DETECTED'),
        serverId,
        findings: scan.findings,
        invisibleTagCount: scan.invisibleTagCount,
        message: 'Refusing to pin MCP tool manifest containing covert prompt-injection or Unicode Tag poisoning.'
      };
    }

    /** @type {Record<string, string>} */
    const toolHashes = {};
    const sortedTools = input.tools
      .map((t) => ({
        name: String((t && t.name) || '').trim(),
        sha256: hashToolDefinition(t)
      }))
      .filter((t) => t.name.length > 0)
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const item of sortedTools) {
      toolHashes[item.name] = item.sha256;
    }

    const manifestHash = crypto
      .createHash('sha256')
      .update(canonicalJson(toolHashes), 'utf8')
      .digest('hex');
    const pinnedAt = new Date().toISOString();

    const record = {
      serverId,
      manifestHash,
      toolCount: sortedTools.length,
      toolHashes,
      approver,
      pinnedAt
    };

    if (!dryRun) {
      const manifests = this._loadManifests();
      manifests[serverId] = record;
      this._saveManifests(manifests);
    }

    return {
      ok: true,
      pinned: !dryRun,
      blocked: false,
      dryRun,
      code: dryRun ? 'MANIFEST_PIN_PREVIEW' : 'MANIFEST_PINNED',
      ...record
    };
  }

  /**
   * Re-verifies a live tool manifest against its pinned SHA-256 hashes (`CVE-2025-54136`).
   * Falls back to caller-supplied `pinnedHashes` for stateless dry-run previews when `serverId`
   * is not yet persisted on disk. Any 1-character drift triggers `MCP_RUG_PULL_DETECTED`.
   *
   * @param {{
   *   serverId: string,
   *   tools: any[],
   *   pinnedHashes?: Record<string, string> | null,
   *   pinnedManifestHash?: string | null
   * }} input
   */
  verifyToolManifest(input) {
    if (!input || typeof input !== 'object') {
      throw poisonError('INVALID_INPUT', 'verifyToolManifest requires { serverId, tools }');
    }
    const serverId = typeof input.serverId === 'string' ? input.serverId.trim().slice(0, 128) : '';
    if (!serverId) throw poisonError('INVALID_SERVER_ID', 'serverId is required');
    const tools = Array.isArray(input.tools) ? input.tools : [];

    const manifests = this._loadManifests();
    const inlineHashes = input.pinnedHashes && typeof input.pinnedHashes === 'object' && !Array.isArray(input.pinnedHashes)
      && Object.keys(input.pinnedHashes).length > 0
      ? input.pinnedHashes
      : null;
    const pinned = manifests[serverId] || (inlineHashes
      ? {
          toolHashes: inlineHashes,
          manifestHash: typeof input.pinnedManifestHash === 'string' ? input.pinnedManifestHash : null
        }
      : null);
    if (!pinned) {
      return {
        ok: true,
        verified: false,
        blocked: true,
        code: /** @type {'MANIFEST_NOT_PINNED'} */ ('MANIFEST_NOT_PINNED'),
        serverId,
        driftedTools: [],
        message: `MCP server "${serverId}" has no pinned cryptographic tool manifest.`
      };
    }

    const pinnedHashes = pinned.toolHashes || {};
    /** @type {Record<string, string>} */
    const liveHashes = {};
    for (const t of tools) {
      const name = String((t && t.name) || '').trim();
      if (!name) continue;
      liveHashes[name] = hashToolDefinition(t);
    }

    /** @type {Array<{ name: string, kind: 'MODIFIED' | 'UNPINNED_ADDED' | 'REMOVED', expectedHash: string | null, actualHash: string | null }>} */
    const driftedTools = [];

    for (const [name, expectedHash] of Object.entries(pinnedHashes)) {
      if (!(name in liveHashes)) {
        driftedTools.push({ name, kind: 'REMOVED', expectedHash, actualHash: null });
      } else if (liveHashes[name] !== expectedHash) {
        driftedTools.push({ name, kind: 'MODIFIED', expectedHash, actualHash: liveHashes[name] });
      }
    }
    for (const [name, actualHash] of Object.entries(liveHashes)) {
      if (!(name in pinnedHashes)) {
        driftedTools.push({ name, kind: 'UNPINNED_ADDED', expectedHash: null, actualHash });
      }
    }

    // Also run poisoning scan on live tools
    const poisonScan = scanToolPoisoning({ tools, source: `verify:${serverId}` });
    const rugPull = driftedTools.length > 0;
    const blocked = rugPull || poisonScan.blocked;

    return {
      ok: true,
      verified: !blocked,
      blocked,
      code: rugPull
        ? 'MCP_RUG_PULL_DETECTED'
        : (poisonScan.blocked ? 'MCP_TOOL_POISONING_DETECTED' : 'MANIFEST_VERIFIED'),
      serverId,
      pinnedManifestHash: pinned.manifestHash,
      driftedTools,
      poisonFindings: poisonScan.findings,
      invisibleTagCount: poisonScan.invisibleTagCount,
      verifiedAt: new Date().toISOString()
    };
  }

  /**
   * Lists all pinned MCP server manifests, newest first.
   */
  listPinnedManifests() {
    return Object.values(this._loadManifests())
      .sort((a, b) => String(b.pinnedAt || '').localeCompare(String(a.pinnedAt || '')));
  }
}

const defaultMcpPoisonGuardService = new McpPoisonGuardService();

const exported = Object.assign(defaultMcpPoisonGuardService, {
  McpPoisonGuardService,
  hashToolDefinition: McpPoisonGuardService.prototype.hashToolDefinition.bind(defaultMcpPoisonGuardService),
  pinToolManifest: McpPoisonGuardService.prototype.pinToolManifest.bind(defaultMcpPoisonGuardService),
  verifyToolManifest: McpPoisonGuardService.prototype.verifyToolManifest.bind(defaultMcpPoisonGuardService),
  scanToolPoisoning: McpPoisonGuardService.prototype.scanToolPoisoning.bind(defaultMcpPoisonGuardService),
  auditAgentToolScope: McpPoisonGuardService.prototype.auditAgentToolScope.bind(defaultMcpPoisonGuardService),
  listPinnedManifests: McpPoisonGuardService.prototype.listPinnedManifests.bind(defaultMcpPoisonGuardService)
});

module.exports = exported;
