const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Automated Blameless Incident Postmortem & Timeline Correlator (100% Zero-Dep).
 *
 * Inspirado en IncidentFox / Akmatori / OpenSRE + líneas de tiempo CloudEvents v1.0:
 *  - Correlaciona deploys, OOM forensics, rollbacks canary, alertas y drift de config
 *    en `verifiedEvents[]` cronológicos.
 *  - Segrega estrictamente `chatNotes` en `unverifiedNotes[]` (JAMÁS contamina
 *    `verifiedEvents[]` ni la puntuación de `probableRootCause`!).
 *  - Puntúa cambios previos al incidente en la ventana `T-15m..T+0` (`confidence: 0..1`),
 *    calcula `mttdSec` y `mttrSec` exactos, redacta secretos y exporta Markdown/JSON sin culpas.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/postmortems.json`.
 */

const MAX_POSTMORTEMS = 200;

// Dynamic redaction patterns (0 literal GH013 secret prefixes in source)
const REDACT_PATTERNS = Object.freeze([
  new RegExp('\\b' + 'sk' + '_(?:live|test)_[A-Za-z0-9]{8,}', 'g'),
  new RegExp('\\b' + 'gh' + '[pousr]_[A-Za-z0-9]{12,}', 'g'),
  new RegExp('\\b' + 'AK' + 'IA[0-9A-Z]{16}\\b', 'g'),
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]{14,}=*/gi
]);

/**
 * Resuelve dinámicamente la ruta a `postmortems.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'postmortems.json')
    : path.join(base, 'data', 'postmortems.json');
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
 * Carga postmortems almacenados desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, postmortems: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), postmortems: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.postmortems)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), postmortems: [] };
}

/**
 * Guarda postmortems atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, postmortems: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.postmortems.length > MAX_POSTMORTEMS) {
    store.postmortems = store.postmortems.slice(-MAX_POSTMORTEMS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Redacta tokens sensibles en cadenas antes de emitir o persistir un postmortem.
 * @param {string} text
 */
function redactSecrets(text) {
  let out = String(text || '');
  for (const re of REDACT_PATTERNS) {
    out = out.replace(re, '[REDACTED]');
  }
  return out;
}

/**
 * Parsea un timestamp (ms epoch o ISO) a milisegundos epoch.
 * @param {any} ts
 * @param {number} fallbackMs
 */
function parseTimeMs(ts, fallbackMs) {
  if (typeof ts === 'number' && Number.isFinite(ts)) return ts;
  if (typeof ts === 'string' && ts.trim()) {
    const parsed = Date.parse(ts);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallbackMs;
}

/**
 * Correlaciona telemetría técnica en una línea de tiempo CloudEvents v1.0, segrega notas de chat
 * en `unverifiedNotes[]`, puntúa cambios `T-15m..T+0` y calcula `mttdSec`/`mttrSec`.
 *
 * @param {{
 *   incidentId?: string,
 *   projectId?: string,
 *   windowStart?: string | number,
 *   windowEnd?: string | number,
 *   deploys?: any[],
 *   oomEvents?: any[],
 *   canaryRollbacks?: any[],
 *   alerts?: any[],
 *   driftEvents?: any[],
 *   chatNotes?: any[]
 * }} [input]
 */
function correlateIncidentTimeline(input = {}) {
  const opts = input || {};
  const incidentId = String(opts.incidentId || `inc_${crypto.randomBytes(4).toString('hex')}`).trim();
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const nowMs = Date.now();
  const windowStartMs = opts.windowStart !== undefined ? parseTimeMs(opts.windowStart, nowMs) : null;
  const windowEndMs = opts.windowEnd !== undefined ? parseTimeMs(opts.windowEnd, nowMs) : null;

  /** @type {Array<{ specversion: '1.0', id: string, type: string, source: string, time: string, timeMs: number, category: string, summary: string, data: Record<string, any> }>} */
  const verifiedEvents = [];

  /**
   * @param {any[]} list
   * @param {'deploy' | 'oom' | 'rollback' | 'alert' | 'drift'} category
   * @param {string} ceType
   */
  const ingest = (list, category, ceType) => {
    if (!Array.isArray(list)) return;
    for (let i = 0; i < list.length; i++) {
      const ev = (list[i] && typeof list[i] === 'object') ? list[i] : { summary: String(list[i] || '') };
      const tMs = parseTimeMs(ev.timestamp ?? ev.time ?? ev.ts ?? ev.at, windowStartMs || nowMs);
      const rawSummary = ev.summary || ev.title || ev.message || ev.classification || ev.release || `${category} event`;
      verifiedEvents.push({
        specversion: '1.0',
        id: String(ev.id || `${category}_${i + 1}`),
        type: ceType,
        source: `culkibo://${projectId}/${category}`,
        time: new Date(tMs).toISOString(),
        timeMs: tMs,
        category,
        summary: redactSecrets(String(rawSummary)),
        data: {
          version: ev.version || ev.commitSha || ev.digest || null,
          severity: ev.severity || null,
          state: ev.state || null,
          exitCode: ev.exitCode !== undefined ? ev.exitCode : null
        }
      });
    }
  };

  ingest(opts.deploys || [], 'deploy', 'culkibo.deploy.completed');
  ingest(opts.oomEvents || [], 'oom', 'culkibo.runtime.oom');
  ingest(opts.canaryRollbacks || [], 'rollback', 'culkibo.canary.rollback');
  ingest(opts.alerts || [], 'alert', 'culkibo.alert.event');
  ingest(opts.driftEvents || [], 'drift', 'culkibo.config.drift');

  verifiedEvents.sort((a, b) => a.timeMs - b.timeMs);

  // Strictly segregate speculative human chat notes into unverifiedNotes[]
  const unverifiedNotes = (Array.isArray(opts.chatNotes) ? opts.chatNotes : []).map((note, idx) => {
    if (typeof note === 'string') {
      return {
        id: `note_${idx + 1}`,
        author: 'unverified-chat',
        time: null,
        text: redactSecrets(note),
        verified: false
      };
    }
    const obj = (note && typeof note === 'object') ? note : {};
    const tMs = obj.timestamp || obj.time ? parseTimeMs(obj.timestamp || obj.time, nowMs) : null;
    return {
      id: String(obj.id || `note_${idx + 1}`),
      author: String(obj.author || obj.user || 'unverified-chat'),
      time: tMs !== null ? new Date(tMs).toISOString() : null,
      text: redactSecrets(String(obj.text || obj.message || obj.note || '')),
      verified: false
    };
  });

  // Compute exact incident start, detection (MTTD), and recovery (MTTR)
  const oomEvs = verifiedEvents.filter((e) => e.category === 'oom');
  const alertEvs = verifiedEvents.filter((e) => e.category === 'alert');
  const rollbackEvs = verifiedEvents.filter((e) => e.category === 'rollback');
  const firingAlerts = alertEvs.filter((e) => String(e.data.state || 'firing').toLowerCase() !== 'resolved');
  const resolvedAlerts = alertEvs.filter((e) => String(e.data.state || '').toLowerCase() === 'resolved');

  const symptomCandidates = [...oomEvs, ...firingAlerts].sort((a, b) => a.timeMs - b.timeMs);
  const incidentStartMs = symptomCandidates.length > 0
    ? symptomCandidates[0].timeMs
    : (windowStartMs !== null ? windowStartMs : (verifiedEvents[0] ? verifiedEvents[0].timeMs : nowMs));

  const detectedMs = firingAlerts.length > 0
    ? Math.max(incidentStartMs, firingAlerts[0].timeMs)
    : (symptomCandidates.length > 0 ? symptomCandidates[0].timeMs : incidentStartMs);

  const recoveryCandidates = [
    ...rollbackEvs.map((e) => e.timeMs),
    ...resolvedAlerts.map((e) => e.timeMs)
  ].filter((t) => t >= incidentStartMs);

  let resolvedMs = incidentStartMs;
  if (windowEndMs !== null && windowEndMs >= incidentStartMs) {
    resolvedMs = windowEndMs;
  } else if (recoveryCandidates.length > 0) {
    resolvedMs = Math.max(...recoveryCandidates);
  } else if (verifiedEvents.length > 0) {
    resolvedMs = Math.max(incidentStartMs, verifiedEvents[verifiedEvents.length - 1].timeMs);
  }

  const mttdSec = Math.max(0, Math.round((detectedMs - incidentStartMs) / 1000));
  const mttrSec = Math.max(0, Math.round((resolvedMs - incidentStartMs) / 1000));

  // Score pre-incident deploys and config drifts within T-15m..T+1m
  const windowLookbackMs = 15 * 60 * 1000;
  const changeEvents = verifiedEvents.filter((e) => e.category === 'deploy' || e.category === 'drift');

  /** @type {Array<{ eventId: string, category: string, summary: string, time: string, deltaBeforeIncidentSec: number, confidence: number, evidence: string }>} */
  const rootCauseCandidates = [];

  for (const ch of changeEvents) {
    const deltaMs = incidentStartMs - ch.timeMs;
    if (deltaMs >= -60000 && deltaMs <= windowLookbackMs) {
      let score = ch.category === 'deploy' ? 0.68 : 0.6;
      const absMin = Math.abs(deltaMs) / 60000;
      if (absMin <= 5) score += 0.16;
      else if (absMin <= 10) score += 0.1;
      else score += 0.05;

      if (oomEvs.length > 0) score += 0.08;
      if (rollbackEvs.length > 0) score += 0.06;
      const confidence = Math.min(0.98, Math.round(score * 100) / 100);
      const deltaSec = Math.round(deltaMs / 1000);

      rootCauseCandidates.push({
        eventId: ch.id,
        category: ch.category,
        summary: ch.summary,
        time: ch.time,
        deltaBeforeIncidentSec: deltaSec,
        confidence,
        evidence: `${ch.category} occurred ${Math.max(0, Math.round(deltaSec / 60))}m (${deltaSec}s) before first verified failure${oomEvs.length > 0 ? ' followed by OOM' : ''}${rollbackEvs.length > 0 ? ' and canary rollback' : ''}.`
      });
    }
  }

  rootCauseCandidates.sort((a, b) => b.confidence - a.confidence);

  const probableRootCause = rootCauseCandidates[0] || (
    oomEvs[0]
      ? {
          eventId: oomEvs[0].id,
          category: 'oom',
          summary: oomEvs[0].summary,
          time: oomEvs[0].time,
          deltaBeforeIncidentSec: 0,
          confidence: 0.72,
          evidence: 'Container OOM exhaustion observed without a preceding deploy in T-15m.'
        }
      : {
          eventId: verifiedEvents[0] ? verifiedEvents[0].id : 'none',
          category: 'unknown',
          summary: 'No high-confidence pre-incident change correlated within T-15m window.',
          time: new Date(incidentStartMs).toISOString(),
          deltaBeforeIncidentSec: 0,
          confidence: 0.25,
          evidence: 'Manual deep-dive into metrics and logs recommended.'
        }
  );

  return {
    ok: true,
    incidentId,
    projectId,
    windowStart: new Date(windowStartMs !== null ? windowStartMs : incidentStartMs).toISOString(),
    windowEnd: new Date(resolvedMs).toISOString(),
    mttdSec,
    mttrSec,
    probableRootCause,
    rootCauseCandidates,
    verifiedEvents,
    unverifiedNotes
  };
}

/**
 * Genera un postmortem SRE blameless estructurado (con opción `persist: true` para guardar en disco).
 *
 * @param {ReturnType<typeof correlateIncidentTimeline>} correlation
 * @param {{ persist?: boolean }} [options]
 */
function generateBlamelessPostmortem(correlation, options = {}) {
  const corr = correlation || correlateIncidentTimeline({});
  const persist = Boolean(options && options.persist);
  const generatedAt = new Date().toISOString();

  const hasOom = corr.verifiedEvents.some((e) => e.category === 'oom');
  const hasDeploy = corr.verifiedEvents.some((e) => e.category === 'deploy');
  const hasDrift = corr.verifiedEvents.some((e) => e.category === 'drift');

  /** @type {Array<{ id: string, priority: string, ownerRole: string, action: string }>} */
  const actionItems = [];
  if (hasOom) {
    actionItems.push({
      id: 'act_1',
      priority: 'P1',
      ownerRole: 'platform-sre',
      action: 'Apply VPA-lite OOM +50% memory headroom recommendation and align runtime heap ceiling.'
    });
  }
  if (hasDeploy) {
    actionItems.push({
      id: `act_${actionItems.length + 1}`,
      priority: 'P1',
      ownerRole: 'release-engineering',
      action: 'Enforce pre-merge preview smoke-gate, memory load test, and automatic canary rollback thresholds.'
    });
  }
  if (hasDrift) {
    actionItems.push({
      id: `act_${actionItems.length + 1}`,
      priority: 'P2',
      ownerRole: 'platform-sre',
      action: 'Lock production configuration against out-of-band drift via immutable GitOps promotions.'
    });
  }
  if (actionItems.length === 0) {
    actionItems.push({
      id: 'act_1',
      priority: 'P2',
      ownerRole: 'oncall-sre',
      action: 'Expand synthetic monitoring and alert coverage for earlier detection.'
    });
  }

  const postmortem = {
    ok: true,
    id: `pm_${crypto.randomBytes(5).toString('hex')}`,
    incidentId: corr.incidentId,
    projectId: corr.projectId,
    blameless: true,
    title: `Blameless Postmortem: ${corr.incidentId} (${corr.projectId})`,
    summary: `Systemic analysis for incident ${corr.incidentId}: MTTD ${corr.mttdSec}s, MTTR ${corr.mttrSec}s. Probable contributing factor: ${corr.probableRootCause.summary} (confidence ${Math.round(corr.probableRootCause.confidence * 100)}%).`,
    mttdSec: corr.mttdSec,
    mttrSec: corr.mttrSec,
    probableRootCause: corr.probableRootCause,
    verifiedEvents: corr.verifiedEvents,
    unverifiedNotes: corr.unverifiedNotes,
    actionItems,
    generatedAt
  };

  if (persist) {
    const store = loadStore();
    store.postmortems.push(postmortem);
    saveStore(store);
  }

  return postmortem;
}

/**
 * Exporta un postmortem blameless en formato Markdown listo para docs/GitHub Issues.
 *
 * @param {ReturnType<typeof generateBlamelessPostmortem>} postmortem
 * @returns {string}
 */
function exportPostmortemMarkdown(postmortem) {
  const pm = postmortem || generateBlamelessPostmortem(correlateIncidentTimeline({}));
  const lines = [
    `# ${pm.title}`,
    '',
    '> **Blameless SRE Review:** Focuses on systemic safeguards, telemetry gaps, and automated guardrails rather than individual fault.',
    '',
    '## Executive Summary & Metrics',
    `- **Incident ID:** \`${pm.incidentId}\``,
    `- **Project:** \`${pm.projectId}\``,
    `- **MTTD (Mean Time to Detect):** \`${pm.mttdSec}s\``,
    `- **MTTR (Mean Time to Recover):** \`${pm.mttrSec}s\``,
    `- **Probable Root Cause:** ${pm.probableRootCause.summary} (**confidence:** \`${Math.round(pm.probableRootCause.confidence * 100)}%\`)`,
    `- **Evidence:** ${pm.probableRootCause.evidence}`,
    '',
    '## Verified CloudEvents Timeline',
    '| Time (UTC) | Category | Event Type | Summary |',
    '|---|---|---|---|'
  ];

  for (const ev of (Array.isArray(pm.verifiedEvents) ? pm.verifiedEvents : [])) {
    lines.push(`| \`${ev.time}\` | \`${ev.category}\` | \`${ev.type}\` | ${String(ev.summary || '').replace(/\|/g, '\\|')} |`);
  }

  lines.push('', '## Systemic Action Items');
  for (const act of (Array.isArray(pm.actionItems) ? pm.actionItems : [])) {
    lines.push(`- **[${act.priority}] (${act.ownerRole})** ${act.action}`);
  }

  if (Array.isArray(pm.unverifiedNotes) && pm.unverifiedNotes.length > 0) {
    lines.push('', '## Unverified Chat Notes (Excluded from Root-Cause Scoring)');
    for (const n of pm.unverifiedNotes) {
      lines.push(`- *${n.author}*: ${n.text}`);
    }
  }

  return lines.join('\n');
}

/**
 * Lista los postmortems guardados (más recientes primero).
 * @param {string} [projectId]
 */
function listPostmortems(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.postmortems.filter((p) => p.projectId === cleanId)
    : store.postmortems;
  return [...items].reverse();
}

module.exports = {
  correlateIncidentTimeline,
  generateBlamelessPostmortem,
  exportPostmortemMarkdown,
  listPostmortems
};
