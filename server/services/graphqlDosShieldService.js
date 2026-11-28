'use strict';

/**
 * Culkibo GraphQL Depth, Fragment-Spread Alias & Introspection Shield.
 *
 * Cures `CVE-2026-47707` (`strawberry-graphql <= 0.315.6` `FragmentSpreadNode` alias bypass),
 * `CVE-2026-35441` (Directus `< 11.17.0` alias DB-pool DoS), and `CVE-2025-32031`
 * (`@apollo/gateway < 2.10.1` exponential fragment fan-out) in zero runtime npm dependencies:
 *  - Atomic `0o600` per-project policy store in `CULKIBO_DATA_DIR/data/graphql-dos-shield.json`.
 *  - Zero-dep GraphQL lexer + recursive-descent selection-set parser.
 *  - Recursively expands named `...FragmentName` spreads (with cycle & linear hard-cap guard)
 *    to measure true expanded depth, true expanded alias count, fragment fan-out, HTTP batching,
 *    and production `__schema` / `__type` introspection.
 *  - Flags `GRAPHQL_DEPTH_EXCEEDED`, `GRAPHQL_ALIAS_AMPLIFICATION`,
 *    `GRAPHQL_FRAGMENT_FANOUT_DOS`, `GRAPHQL_BATCH_LIMIT_EXCEEDED`, and
 *    `GRAPHQL_INTROSPECTION_BLOCKED`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_GRAPHQL_POLICY = Object.freeze({
  maxDepth: 7,
  maxAliases: 15,
  maxFragmentExpansions: 8,
  maxBatchSize: 10,
  allowIntrospection: false
});

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
 * Zero-dep GraphQL tokenizer skipping comments, whitespace, commas, and string literals cleanly.
 * @param {string} source
 * @returns {Array<{ type: 'NAME' | 'PUNCT' | 'SPREAD' | 'STRING', value: string }>}
 */
function tokenizeGraphql(source) {
  /** @type {Array<{ type: 'NAME' | 'PUNCT' | 'SPREAD' | 'STRING', value: string }>} */
  const tokens = [];
  const len = source.length;
  let i = 0;

  while (i < len) {
    const ch = source[i];
    // Whitespace & commas
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',' || ch === '\uFEFF') {
      i += 1;
      continue;
    }
    // Comment until EOL
    if (ch === '#') {
      while (i < len && source[i] !== '\n') i += 1;
      continue;
    }
    // Block string """..."""
    if (ch === '"' && source.slice(i, i + 3) === '"""') {
      i += 3;
      while (i < len && source.slice(i, i + 3) !== '"""') {
        if (source[i] === '\\' && source.slice(i + 1, i + 4) === '"""') i += 4;
        else i += 1;
      }
      i += 3;
      tokens.push({ type: 'STRING', value: '' });
      continue;
    }
    // Quoted string "..."
    if (ch === '"') {
      i += 1;
      while (i < len && source[i] !== '"') {
        if (source[i] === '\\') i += 2;
        else i += 1;
      }
      i += 1;
      tokens.push({ type: 'STRING', value: '' });
      continue;
    }
    // Spread ...
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push({ type: 'SPREAD', value: '...' });
      i += 3;
      continue;
    }
    // Punctuators
    if ('{}():@[]=!|$'.includes(ch)) {
      tokens.push({ type: 'PUNCT', value: ch });
      i += 1;
      continue;
    }
    // Names / numbers
    if (/[A-Za-z0-9_.-]/.test(ch)) {
      let start = i;
      while (i < len && /[A-Za-z0-9_.-]/.test(source[i])) i += 1;
      tokens.push({ type: 'NAME', value: source.slice(start, i) });
      continue;
    }
    i += 1;
  }

  return tokens;
}

/**
 * Parses GraphQL operations and named fragment definitions into a lightweight AST.
 * @param {string} source
 */
function parseGraphqlDocument(source) {
  const tokens = tokenizeGraphql(source);
  let pos = 0;

  const peek = (offset = 0) => tokens[pos + offset] || null;
  const consume = () => tokens[pos++] || null;

  /** Skips balanced `(...)` arguments or variable definitions. */
  const skipParens = () => {
    if (!peek() || peek().value !== '(') return;
    let depth = 0;
    while (pos < tokens.length) {
      const t = consume();
      if (!t) break;
      if (t.value === '(') depth += 1;
      else if (t.value === ')') {
        depth -= 1;
        if (depth <= 0) break;
      }
    }
  };

  /** Skips `@directive(...)` annotations. */
  const skipDirectives = () => {
    while (peek() && peek().value === '@') {
      consume(); // @
      if (peek() && peek().type === 'NAME') consume();
      if (peek() && peek().value === '(') skipParens();
    }
  };

  /** @returns {any[]} */
  const parseSelectionSet = () => {
    if (!peek() || peek().value !== '{') return [];
    consume(); // '{'
    /** @type {any[]} */
    const selections = [];

    while (pos < tokens.length) {
      const tok = peek();
      if (!tok) break;
      if (tok.value === '}') {
        consume();
        break;
      }

      if (tok.type === 'SPREAD') {
        consume(); // '...'
        const next = peek();
        if (next && next.type === 'NAME' && next.value === 'on') {
          consume(); // 'on'
          if (peek() && peek().type === 'NAME') consume(); // typeCondition
          skipDirectives();
          const sub = parseSelectionSet();
          selections.push({ kind: 'InlineFragment', selections: sub });
        } else if (next && (next.value === '@' || next.value === '{')) {
          skipDirectives();
          const sub = parseSelectionSet();
          selections.push({ kind: 'InlineFragment', selections: sub });
        } else if (next && next.type === 'NAME') {
          const fragName = consume().value;
          skipDirectives();
          selections.push({ kind: 'FragmentSpread', name: fragName });
        }
        continue;
      }

      if (tok.type === 'NAME') {
        /** @type {string | null} */
        let alias = null;
        let name = consume().value;
        if (peek() && peek().value === ':') {
          consume(); // ':'
          alias = name;
          name = peek() && peek().type === 'NAME' ? consume().value : name;
        }
        if (peek() && peek().value === '(') skipParens();
        skipDirectives();
        const sub = peek() && peek().value === '{' ? parseSelectionSet() : [];
        selections.push({ kind: 'Field', name, alias, selections: sub });
        continue;
      }

      consume();
    }

    return selections;
  };

  /** @type {Record<string, any[]>} */
  const fragments = {};
  /** @type {any[][]} */
  const operations = [];

  while (pos < tokens.length) {
    const tok = peek();
    if (!tok) break;

    if (tok.type === 'NAME' && tok.value === 'fragment') {
      consume(); // 'fragment'
      const fragName = peek() && peek().type === 'NAME' ? consume().value : '';
      if (peek() && peek().type === 'NAME' && peek().value === 'on') {
        consume();
        if (peek() && peek().type === 'NAME') consume();
      }
      skipDirectives();
      const body = parseSelectionSet();
      if (fragName) fragments[fragName] = body;
      continue;
    }

    if (tok.type === 'NAME' && (tok.value === 'query' || tok.value === 'mutation' || tok.value === 'subscription')) {
      consume();
      if (peek() && peek().type === 'NAME') consume(); // optional op name
      if (peek() && peek().value === '(') skipParens();
      skipDirectives();
      operations.push(parseSelectionSet());
      continue;
    }

    if (tok.value === '{') {
      operations.push(parseSelectionSet());
      continue;
    }

    consume();
  }

  return { fragments, operations };
}

/**
 * Evaluates a GraphQL document (or batched query array) with recursive fragment expansion.
 *
 * @param {{
 *   query?: string | string[],
 *   batchSize?: number,
 *   maxDepth?: number,
 *   maxAliases?: number,
 *   maxFragmentExpansions?: number,
 *   maxBatchSize?: number,
 *   allowIntrospection?: boolean,
 *   env?: string
 * }} [input]
 */
function analyzeGraphqlDocument(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const maxDepth = Math.max(1, Math.min(64, Math.round(Number(src.maxDepth ?? DEFAULT_GRAPHQL_POLICY.maxDepth) || 7)));
  const maxAliases = Math.max(1, Math.min(500, Math.round(Number(src.maxAliases ?? DEFAULT_GRAPHQL_POLICY.maxAliases) || 15)));
  const maxFragmentExpansions = Math.max(
    1,
    Math.min(500, Math.round(Number(src.maxFragmentExpansions ?? DEFAULT_GRAPHQL_POLICY.maxFragmentExpansions) || 8))
  );
  const maxBatchSize = Math.max(1, Math.min(200, Math.round(Number(src.maxBatchSize ?? DEFAULT_GRAPHQL_POLICY.maxBatchSize) || 10)));
  const env = String(src.env || 'production').trim().toLowerCase();
  const allowIntrospection = src.allowIntrospection !== undefined
    ? Boolean(src.allowIntrospection)
    : (env === 'development' || env === 'dev');

  const queryList = Array.isArray(src.query)
    ? src.query.map((q) => String(q || ''))
    : [typeof src.query === 'string' ? src.query : ''];
  const effectiveBatchSize = Math.max(
    queryList.length,
    Number.isFinite(Number(src.batchSize)) ? Math.max(1, Math.round(Number(src.batchSize))) : 1
  );

  let maxObservedDepth = 0;
  let expandedAliases = 0;
  let fragmentExpansions = 0;
  let fragmentCycleDetected = false;
  let fanoutBudgetExceeded = false;
  let introspectionUsed = false;

  const expansionHardCap = Math.max(maxFragmentExpansions * 8, 250);

  for (const queryText of queryList) {
    if (!queryText.trim()) continue;
    const { fragments, operations } = parseGraphqlDocument(queryText);

    /**
     * @param {any[]} selections
     * @param {number} depth
     * @param {Set<string>} activeStack
     */
    const walk = (selections, depth, activeStack) => {
      for (const node of selections) {
        if (!node) continue;
        if (node.kind === 'Field') {
          if (node.name === '__schema' || node.name === '__type') {
            introspectionUsed = true;
          }
          if (node.alias) {
            expandedAliases += 1;
          }
          const nextDepth = depth + 1;
          if (nextDepth > maxObservedDepth) maxObservedDepth = nextDepth;
          if (Array.isArray(node.selections) && node.selections.length > 0 && nextDepth <= maxDepth + 32) {
            walk(node.selections, nextDepth, activeStack);
          }
        } else if (node.kind === 'InlineFragment') {
          if (Array.isArray(node.selections) && node.selections.length > 0) {
            walk(node.selections, depth, activeStack);
          }
        } else if (node.kind === 'FragmentSpread') {
          fragmentExpansions += 1;
          if (activeStack.has(node.name)) {
            fragmentCycleDetected = true;
            fanoutBudgetExceeded = true;
            continue;
          }
          if (fragmentExpansions > maxFragmentExpansions) {
            fanoutBudgetExceeded = true;
          }
          if (fragmentExpansions > expansionHardCap) {
            fanoutBudgetExceeded = true;
            return;
          }
          const target = fragments[node.name];
          if (Array.isArray(target) && target.length > 0) {
            activeStack.add(node.name);
            walk(target, depth, activeStack);
            activeStack.delete(node.name);
          }
        }
      }
    };

    for (const opSelections of operations) {
      walk(opSelections, 0, new Set());
    }
  }

  /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, remediation: string }>} */
  const findings = [];

  if (maxObservedDepth > maxDepth) {
    findings.push({
      code: 'GRAPHQL_DEPTH_EXCEEDED',
      severity: 'high',
      message: `Expanded GraphQL query depth (${maxObservedDepth}) exceeds maxDepth (${maxDepth}).`,
      remediation: `Enforce fragment-expanded depth limit <= ${maxDepth} before resolver execution.`
    });
  }

  if (expandedAliases > maxAliases) {
    findings.push({
      code: 'GRAPHQL_ALIAS_AMPLIFICATION',
      severity: 'critical',
      message: `Fragment-expanded alias count (${expandedAliases}) exceeds maxAliases (${maxAliases}) (CVE-2026-47707 / CVE-2026-35441).`,
      remediation: `Count aliases AFTER recursive fragment spread expansion and cap at <= ${maxAliases}.`
    });
  }

  if (fanoutBudgetExceeded || fragmentCycleDetected) {
    findings.push({
      code: 'GRAPHQL_FRAGMENT_FANOUT_DOS',
      severity: 'critical',
      message: fragmentCycleDetected
        ? 'Cyclic GraphQL fragment spread detected (infinite expansion DoS).'
        : `Fragment spread expansions (${fragmentExpansions}) exceeded budget (${maxFragmentExpansions}) (CVE-2025-32031).`,
      remediation: 'Reject cyclic fragments and cap total fragment spread expansions per operation.'
    });
  }

  if (effectiveBatchSize > maxBatchSize) {
    findings.push({
      code: 'GRAPHQL_BATCH_LIMIT_EXCEEDED',
      severity: 'high',
      message: `HTTP GraphQL batch size (${effectiveBatchSize}) exceeds maxBatchSize (${maxBatchSize}).`,
      remediation: `Disable HTTP array batching or cap batchSize <= ${maxBatchSize}.`
    });
  }

  if (introspectionUsed && !allowIntrospection) {
    findings.push({
      code: 'GRAPHQL_INTROSPECTION_BLOCKED',
      severity: 'high',
      message: `GraphQL schema introspection (__schema/__type) is blocked in "${env}" environment.`,
      remediation: 'Disable introspection in production and serve typed schemas out-of-band.'
    });
  }

  const blocked = findings.length > 0;
  return {
    ok: true,
    safe: !blocked,
    blocked,
    status: blocked ? 'BLOCKED' : 'SAFE',
    env,
    metrics: {
      maxObservedDepth,
      expandedAliases,
      fragmentExpansions,
      fragmentCycleDetected,
      batchSize: effectiveBatchSize,
      introspectionUsed
    },
    limits: {
      maxDepth,
      maxAliases,
      maxFragmentExpansions,
      maxBatchSize,
      allowIntrospection
    },
    findings,
    findingCodes: Array.from(new Set(findings.map((f) => f.code))),
    inspectedAt: new Date().toISOString()
  };
}

class GraphqlDosShieldService {
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
    return path.join(this.resolveDataDir(), 'graphql-dos-shield.json');
  }

  /** @returns {Record<string, any>} */
  _loadPolicies() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {};
    } catch (e) {
      return {};
    }
  }

  /** @param {Record<string, any>} policies */
  _savePolicies(policies) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), policies }, null, 2) + '\n'
    );
  }

  /**
   * Inspects a GraphQL query (inheriting any persisted project policy defaults if `projectId` is given).
   * @param {Record<string, any>} [input]
   */
  inspectGraphqlQuery(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const projectId = typeof src.projectId === 'string' && src.projectId.trim() ? src.projectId.trim() : null;
    const saved = projectId ? this._loadPolicies()[projectId] : null;
    return analyzeGraphqlDocument({
      ...(saved || {}),
      ...src
    });
  }

  /**
   * Upserts a per-project GraphQL DoS shield policy (`dryRun: true` default).
   * @param {string} projectId
   * @param {Record<string, any>} [policyInput]
   */
  upsertGraphqlShieldPolicy(projectId, policyInput = {}) {
    const id = String(projectId || 'default').trim().slice(0, 128) || 'default';
    const src = policyInput && typeof policyInput === 'object' ? policyInput : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;

    const record = {
      projectId: id,
      maxDepth: Math.max(1, Math.min(64, Math.round(Number(src.maxDepth ?? DEFAULT_GRAPHQL_POLICY.maxDepth) || 7))),
      maxAliases: Math.max(1, Math.min(500, Math.round(Number(src.maxAliases ?? DEFAULT_GRAPHQL_POLICY.maxAliases) || 15))),
      maxFragmentExpansions: Math.max(
        1,
        Math.min(500, Math.round(Number(src.maxFragmentExpansions ?? DEFAULT_GRAPHQL_POLICY.maxFragmentExpansions) || 8))
      ),
      maxBatchSize: Math.max(1, Math.min(200, Math.round(Number(src.maxBatchSize ?? DEFAULT_GRAPHQL_POLICY.maxBatchSize) || 10))),
      allowIntrospection: src.allowIntrospection !== undefined ? Boolean(src.allowIntrospection) : false,
      updatedAt: new Date().toISOString()
    };

    if (!dryRun) {
      const policies = this._loadPolicies();
      policies[id] = record;
      this._savePolicies(policies);
    }

    return {
      ok: true,
      dryRun,
      projectId: id,
      policy: record
    };
  }

  /**
   * Lists persisted GraphQL DoS shield policies.
   */
  listGraphqlShieldPolicies() {
    return Object.values(this._loadPolicies());
  }
}

const defaultGraphqlDosShieldService = new GraphqlDosShieldService();

const exported = Object.assign(defaultGraphqlDosShieldService, {
  GraphqlDosShieldService,
  DEFAULT_GRAPHQL_POLICY,
  inspectGraphqlQuery: GraphqlDosShieldService.prototype.inspectGraphqlQuery.bind(defaultGraphqlDosShieldService),
  upsertGraphqlShieldPolicy: GraphqlDosShieldService.prototype.upsertGraphqlShieldPolicy.bind(defaultGraphqlDosShieldService),
  listGraphqlShieldPolicies: GraphqlDosShieldService.prototype.listGraphqlShieldPolicies.bind(defaultGraphqlDosShieldService)
});

module.exports = exported;
