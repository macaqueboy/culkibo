/**
 * Culkibo MCP Apps Renderer (`modelcontextprotocol/ext-apps` 2026-01-26).
 *
 * Genera recursos HTML interactivos autocontenidos (`ui://culkibo/*`,
 * `mimeType: "text/html;profile=mcp-app"`) que hosts compatibles (Claude,
 * Antigravity, Cursor, Windsurf y el panel de Culkibo) renderizan en un
 * iframe aislado con puente JSON-RPC `window.parent.postMessage`.
 *
 * Garantías de seguridad (cero dependencias npm, cero URLs externas):
 *  - CSP estricta: `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`
 *    sin peticiones de red externas, fuentes externas ni scripts remotos.
 *  - Inyección de datos inmune a XSS (`safeJsonForScript` escapa `<`, `>`, `&`, U+2028, U+2029).
 *  - Redacción defensiva de secretos antes de serializar cualquier snapshot de estado.
 */

const MCP_APP_MIME_TYPE = 'text/html;profile=mcp-app';
const MCP_APPS_SPEC_VERSION = '2026-01-26';
const MCP_APP_CSP_POLICY = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'";

const MCP_APP_CSP_META = Object.freeze({
  policy: MCP_APP_CSP_POLICY,
  connectDomains: Object.freeze([]),
  resourceDomains: Object.freeze([]),
  frameDomains: Object.freeze([]),
  baseUriDomains: Object.freeze([])
});

const SECRET_KEY_RE = /(token|password|passwd|secret|apikey|api_key|authorization|credential|connectionstring|passphrase|privatekey|private_key|sshkey|ssh_key|signingsecret|masterkey|confirmtoken)/i;
const SECRET_VAL_RE = /(gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|sk_(?:live|test)_[A-Za-z0-9]{10,}|sk-(?:proj-|ant-)[A-Za-z0-9_-]{10,}|bearer\s+[A-Za-z0-9._~+/=-]{8,}|ck(?:[stihprm]|et)_[A-Za-z0-9._-]{6,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/i;

/**
 * Metadatos canónicos de los 3 MCP Apps nativos de Culkibo.
 * @type {ReadonlyArray<{ uri: string, name: string, title: string, description: string, mimeType: string, scope: string, tools: ReadonlyArray<string>, _meta: { ui: { csp: typeof MCP_APP_CSP_META, prefersBorder: boolean, specVersion: string } } }>}
 */
const MCP_APP_RESOURCES = Object.freeze([
  Object.freeze({
    uri: 'ui://culkibo/topology',
    name: 'Culkibo Live Topology App',
    title: 'Interactive Service, DB, Domain & Fleet Topology',
    description: 'Interactive sandboxed MCP App rendering live domains, projects, managed databases, caches, and SSH fleet servers with 1-click inspection and safe deploy bridges.',
    mimeType: MCP_APP_MIME_TYPE,
    scope: 'projects:read',
    tools: Object.freeze(['culkibo_list_projects', 'culkibo_list_pods']),
    _meta: Object.freeze({
      ui: Object.freeze({
        csp: MCP_APP_CSP_META,
        prefersBorder: true,
        specVersion: MCP_APPS_SPEC_VERSION
      })
    })
  }),
  Object.freeze({
    uri: 'ui://culkibo/incident-remediator',
    name: 'Culkibo Incident Remediator App',
    title: 'Live OOM/Crash Diagnostics & 2-Phase Safe Remediator',
    description: 'Interactive sandboxed MCP App correlating OOMKilled/CrashLoop/logs/uptime signals with a 2-phase dryRun -> HMAC confirmToken remediation bridge.',
    mimeType: MCP_APP_MIME_TYPE,
    scope: 'observability:read',
    tools: Object.freeze(['culkibo_diagnose_incident', 'culkibo_auto_remediate']),
    _meta: Object.freeze({
      ui: Object.freeze({
        csp: MCP_APP_CSP_META,
        prefersBorder: true,
        specVersion: MCP_APPS_SPEC_VERSION
      })
    })
  }),
  Object.freeze({
    uri: 'ui://culkibo/coolify-migration-diff',
    name: 'Culkibo Coolify v4 Migration Diff App',
    title: 'Coolify v4 Parity Score & Traefik -> Caddy Edge Diff',
    description: 'Interactive sandboxed MCP App visualizing Coolify v4 resource parity, redacted magic-var translations (${vault.*}), Traefik->Caddy rules, and zero-downtime cutover checks.',
    mimeType: MCP_APP_MIME_TYPE,
    scope: 'migrations:read',
    tools: Object.freeze(['culkibo_migrate_coolify']),
    _meta: Object.freeze({
      ui: Object.freeze({
        csp: MCP_APP_CSP_META,
        prefersBorder: true,
        specVersion: MCP_APPS_SPEC_VERSION
      })
    })
  })
]);

/** Mapa herramienta -> recurso MCP App asociado (`_meta.ui.resourceUri`). */
const TOOL_UI_RESOURCE_MAP = Object.freeze({
  culkibo_list_projects: 'ui://culkibo/topology',
  culkibo_list_pods: 'ui://culkibo/topology',
  culkibo_diagnose_incident: 'ui://culkibo/incident-remediator',
  culkibo_migrate_coolify: 'ui://culkibo/coolify-migration-diff'
});

/**
 * Escapa texto arbitrario para inserción segura en HTML.
 * @param {any} value
 * @returns {string}
 */
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Redacta recursivamente cualquier clave o valor sensible antes de inyectar datos en HTML.
 * @param {any} value
 * @param {number} [depth]
 * @returns {any}
 */
function sanitizeAppData(value, depth = 0) {
  if (depth > 6) return '[truncated]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (SECRET_VAL_RE.test(value)) return '[REDACTED]';
    return value.length > 600 ? `${value.slice(0, 600)}…` : value;
  }
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.slice(0, 80).map((item) => sanitizeAppData(item, depth + 1));
  }
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SECRET_KEY_RE.test(k)) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = sanitizeAppData(v, depth + 1);
    }
  }
  return out;
}

/**
 * Serializa JSON de forma segura para embeber en `<script type="application/json">` sin XSS.
 * Escapa `<`, `>`, `&`, `\u2028` y `\u2029` para impedir ruptura de etiquetas `</script>`.
 * @param {any} value
 * @returns {string}
 */
function safeJsonForScript(value) {
  const sanitized = sanitizeAppData(value);
  return JSON.stringify(sanitized ?? {})
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Base HTML compartida con estilos autocontenidos, CSP estricta y puente JSON-RPC `ext-apps`.
 * @param {{ uri: string, title: string, subtitle: string, badge: string, initialData: any, bodyHtml: string, appScript: string }} cfg
 * @returns {string}
 */
function renderAppShell(cfg) {
  const jsonPayload = safeJsonForScript(cfg.initialData);
  const safeUri = escapeHtml(cfg.uri);
  const safeTitle = escapeHtml(cfg.title);
  const safeSubtitle = escapeHtml(cfg.subtitle);
  const safeBadge = escapeHtml(cfg.badge);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${MCP_APP_CSP_POLICY}">
<title>${safeTitle} — Culkibo MCP App</title>
<style>
  :root {
    --bg: #0b1120;
    --surface: #111a2e;
    --surface-2: #17233c;
    --border: #243352;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --ok: #10b981;
    --warn: #f59e0b;
    --danger: #f43f5e;
    --accent: #38bdf8;
    --indigo: #818cf8;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-2: #f1f5f9;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --ok: #059669;
      --warn: #d97706;
      --danger: #e11d48;
      --accent: #0284c7;
      --indigo: #4f46e5;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 14px;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 13px;
    line-height: 1.45;
  }
  .shell {
    max-width: 960px;
    margin: 0 auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
  }
  .hdr {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    background: var(--surface-2);
  }
  .hdr-title { font-weight: 700; font-size: 14px; letter-spacing: -0.01em; }
  .hdr-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .pill.ok { color: var(--ok); border-color: var(--ok); }
  .pill.warn { color: var(--warn); border-color: var(--warn); }
  .pill.danger { color: var(--danger); border-color: var(--danger); }
  .pill.accent { color: var(--accent); border-color: var(--accent); }
  .mono { font-family: var(--mono); font-size: 11px; }
  .body { padding: 14px 16px; display: flex; flex-direction: column; gap: 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 10px; }
  .card {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
  }
  .card-title { font-size: 12px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; gap: 6px; }
  .muted { color: var(--muted); font-size: 11px; }
  .btn {
    appearance: none;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
  }
  .btn:hover { border-color: var(--accent); }
  .btn.primary { background: var(--indigo); color: #ffffff; border-color: var(--indigo); }
  .btn.ok { background: var(--ok); color: #ffffff; border-color: var(--ok); }
  .btn.danger { background: var(--danger); color: #ffffff; border-color: var(--danger); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .tabs { display: flex; gap: 6px; flex-wrap: wrap; }
  .tab { padding: 5px 10px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--muted); font-size: 11px; font-weight: 600; cursor: pointer; }
  .tab.active { background: var(--indigo); color: #fff; border-color: var(--indigo); }
  .logbox {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
    font-family: var(--mono);
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 140px;
    overflow-y: auto;
  }
  .svg-wrap {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px;
    overflow-x: auto;
  }
  .status-bar {
    padding: 8px 16px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: var(--muted);
    background: var(--surface-2);
  }
</style>
</head>
<body>
<div class="shell" data-mcp-app="${safeUri}">
  <div class="hdr">
    <div>
      <div class="hdr-title">${safeTitle}</div>
      <div class="hdr-sub">${safeSubtitle}</div>
    </div>
    <div class="row">
      <span class="pill accent">${safeBadge}</span>
      <span class="pill mono">${safeUri}</span>
    </div>
  </div>
  <div class="body">${cfg.bodyHtml}</div>
  <div class="status-bar">
    <span id="bridge-status" class="mono">MCP Apps ext-apps/${escapeHtml(MCP_APPS_SPEC_VERSION)} · CSP strict · 0 external requests</span>
    <span id="action-feedback" class="mono">Ready</span>
  </div>
</div>
<script id="culkibo-initial-data" type="application/json">${jsonPayload}</script>
<script>
(function () {
  var initialEl = document.getElementById('culkibo-initial-data');
  var STATE = {};
  try { STATE = JSON.parse((initialEl && initialEl.textContent) || '{}'); } catch (e) { STATE = {}; }
  var pending = Object.create(null);
  var nextId = 1;

  function setFeedback(msg) {
    var el = document.getElementById('action-feedback');
    if (el) el.textContent = String(msg || '');
  }

  function postRpc(method, params) {
    var id = 'ckapp_' + (nextId++);
    var msg = { jsonrpc: '2.0', id: id, method: method, params: params || {} };
    return new Promise(function (resolve, reject) {
      pending[id] = { resolve: resolve, reject: reject };
      try {
        window.parent.postMessage(msg, '*');
      } catch (err) {
        delete pending[id];
        reject(err);
      }
      setTimeout(function () {
        if (pending[id]) {
          delete pending[id];
          resolve({ simulated: true, note: 'Host bridge did not respond (standalone preview mode).' });
        }
      }, 4500);
    });
  }

  function callTool(name, args) {
    setFeedback('Calling ' + name + '...');
    return postRpc('tools/call', { name: name, arguments: args || {} }).then(function (res) {
      setFeedback(res && res.simulated ? 'Preview mode: emitted tools/call ' + name : 'Completed ' + name);
      return res;
    });
  }

  window.addEventListener('message', function (ev) {
    var data = ev && ev.data;
    if (!data || typeof data !== 'object' || data.jsonrpc !== '2.0') return;
    if (data.id !== undefined && pending[data.id]) {
      var h = pending[data.id];
      delete pending[data.id];
      if (data.error) h.reject(data.error);
      else h.resolve(data.result);
      return;
    }
    if (data.method === 'ui/notifications/tool-result' && data.params && typeof window.__culkiboOnToolResult === 'function') {
      window.__culkiboOnToolResult(data.params);
    }
  });

  try {
    window.parent.postMessage({
      jsonrpc: '2.0',
      id: 'init_0',
      method: 'ui/initialize',
      params: {
        protocolVersion: '${escapeHtml(MCP_APPS_SPEC_VERSION)}',
        appInfo: { name: 'culkibo-mcp-app', version: '1.1.0', resourceUri: '${safeUri}' },
        appCapabilities: { tools: true }
      }
    }, '*');
  } catch (e) {}

  window.__CULKIBO_APP__ = { state: STATE, callTool: callTool, postRpc: postRpc, setFeedback: setFeedback };
  ${cfg.appScript}
})();
</script>
</body>
</html>`;
}

/**
 * Renderiza `ui://culkibo/topology`.
 * @param {any} payload
 */
function renderTopologyApp(payload = {}) {
  const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
  const edges = Array.isArray(payload.edges) ? payload.edges : [];
  const summary = payload.summary || {
    projects: nodes.filter((n) => n.kind === 'project').length,
    databases: nodes.filter((n) => n.kind === 'database' || n.kind === 'cache').length,
    domains: nodes.filter((n) => n.kind === 'domain').length,
    servers: nodes.filter((n) => n.kind === 'server').length
  };

  const lanes = [
    { key: 'domain', label: 'Domains & TLS', x: 24, color: '#38bdf8' },
    { key: 'project', label: 'Projects', x: 244, color: '#818cf8' },
    { key: 'database', label: 'DB & Cache', x: 464, color: '#f59e0b' },
    { key: 'server', label: 'Fleet Nodes', x: 684, color: '#10b981' }
  ];

  const byLane = {
    domain: nodes.filter((n) => n.kind === 'domain').slice(0, 6),
    project: nodes.filter((n) => n.kind === 'project').slice(0, 6),
    database: nodes.filter((n) => n.kind === 'database' || n.kind === 'cache' || n.kind === 'catalog').slice(0, 6),
    server: nodes.filter((n) => n.kind === 'server').slice(0, 6)
  };
  const maxRows = Math.max(1, byLane.domain.length, byLane.project.length, byLane.database.length, byLane.server.length);
  const svgH = Math.max(180, 56 + maxRows * 58);

  /** @type {Record<string, { x: number, y: number }>} */
  const coords = {};
  let rectsSvg = '';
  for (const lane of lanes) {
    rectsSvg += `<text x="${lane.x}" y="22" fill="#94a3b8" font-size="11" font-weight="600">${escapeHtml(lane.label)}</text>`;
    const items = byLane[lane.key] || [];
    if (items.length === 0) {
      rectsSvg += `<rect x="${lane.x}" y="36" width="184" height="42" rx="8" fill="none" stroke="#334155" stroke-dasharray="4 4"/><text x="${lane.x + 12}" y="61" fill="#64748b" font-size="11">None configured</text>`;
    } else {
      items.forEach((n, idx) => {
        const y = 36 + idx * 54;
        coords[n.id] = { x: lane.x + 92, y: y + 21 };
        const hColor = n.health === 'down' ? '#f43f5e' : (n.health === 'degraded' || n.health === 'sleeping' ? '#f59e0b' : '#10b981');
        const label = String(n.label || n.id).slice(0, 20);
        const sub = String(n.sublabel || n.status || '').slice(0, 22);
        rectsSvg += `<g class="topo-node" data-node-id="${escapeHtml(n.id)}" style="cursor:pointer">`;
        rectsSvg += `<rect x="${lane.x}" y="${y}" width="184" height="42" rx="8" fill="#17233c" stroke="${lane.color}" stroke-opacity="0.55"/>`;
        rectsSvg += `<circle cx="${lane.x + 14}" cy="${y + 15}" r="4" fill="${hColor}"/>`;
        rectsSvg += `<text x="${lane.x + 25}" y="${y + 18}" fill="#f1f5f9" font-size="11" font-weight="600">${escapeHtml(label)}</text>`;
        rectsSvg += `<text x="${lane.x + 14}" y="${y + 33}" fill="#94a3b8" font-size="10">${escapeHtml(sub)}</text>`;
        rectsSvg += `</g>`;
      });
    }
  }

  let edgesSvg = '';
  for (const e of edges.slice(0, 40)) {
    const a = coords[e.from];
    const b = coords[e.to];
    if (!a || !b) continue;
    const mx = Math.round((a.x + b.x) / 2);
    edgesSvg += `<path d="M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}" fill="none" stroke="#475569" stroke-width="1.5" stroke-opacity="0.7"/>`;
  }

  const bodyHtml = `
    <div class="row">
      <span class="pill accent">Projects: ${Number(summary.projects || 0)}</span>
      <span class="pill warn">Databases: ${Number(summary.databases || 0)}</span>
      <span class="pill ok">Domains: ${Number(summary.domains || 0)}</span>
      <span class="pill">Servers: ${Number(summary.servers || 1)}</span>
      <span class="pill">Edges: ${edges.length}</span>
    </div>
    <div class="svg-wrap">
      <svg viewBox="0 0 896 ${svgH}" width="100%" height="${svgH}" role="img" aria-label="Culkibo live service topology">
        ${edgesSvg}
        ${rectsSvg}
      </svg>
    </div>
    <div class="card" id="topo-inspector">
      <div class="card-title">
        <span id="topo-sel-title">Select a node or trigger a live action</span>
        <div class="row">
          <button type="button" class="btn" id="btn-refresh-topo">Refresh Projects</button>
          <button type="button" class="btn primary" id="btn-diagnose-sel" disabled>Diagnose Project</button>
          <button type="button" class="btn ok" id="btn-ship-sel" disabled>Ship &amp; Verify (dryRun)</button>
        </div>
      </div>
      <div id="topo-sel-meta" class="muted mono" style="margin-top:6px">Click any project, database, domain, or server node above to inspect RBAC-safe metadata.</div>
    </div>
  `;

  const appScript = `
    var app = window.__CULKIBO_APP__;
    var nodes = Array.isArray(app.state.nodes) ? app.state.nodes : [];
    var selectedNode = null;
    var btnDiag = document.getElementById('btn-diagnose-sel');
    var btnShip = document.getElementById('btn-ship-sel');
    var selTitle = document.getElementById('topo-sel-title');
    var selMeta = document.getElementById('topo-sel-meta');

    function selectById(id) {
      selectedNode = nodes.find(function (n) { return n.id === id; }) || null;
      if (!selectedNode) return;
      selTitle.textContent = (selectedNode.label || selectedNode.id) + ' (' + selectedNode.kind + ' · ' + (selectedNode.health || selectedNode.status || 'ok') + ')';
      selMeta.textContent = JSON.stringify(selectedNode.meta || { id: selectedNode.id, status: selectedNode.status });
      var isProj = selectedNode.kind === 'project' && selectedNode.entityId;
      btnDiag.disabled = !isProj;
      btnShip.disabled = !isProj;
    }

    var els = document.querySelectorAll('.topo-node');
    for (var i = 0; i < els.length; i++) {
      els[i].addEventListener('click', function () { selectById(this.getAttribute('data-node-id')); });
    }
    document.getElementById('btn-refresh-topo').addEventListener('click', function () {
      app.callTool('culkibo_list_projects', {});
    });
    btnDiag.addEventListener('click', function () {
      if (selectedNode && selectedNode.entityId) app.callTool('culkibo_diagnose_incident', { projectId: selectedNode.entityId });
    });
    btnShip.addEventListener('click', function () {
      if (selectedNode && selectedNode.entityId) app.callTool('culkibo_ship_and_verify', { projectId: selectedNode.entityId, dryRun: true });
    });
  `;

  return renderAppShell({
    uri: 'ui://culkibo/topology',
    title: 'Culkibo Live Topology',
    subtitle: 'RBAC-scoped live map of Domains, Projects, Managed DBs, and SSH Fleet Nodes',
    badge: 'MCP App · Topology',
    initialData: { summary, nodes, edges },
    bodyHtml,
    appScript
  });
}

/**
 * Renderiza `ui://culkibo/incident-remediator`.
 * @param {any} payload
 */
function renderIncidentRemediatorApp(payload = {}) {
  const severity = String(payload.severity || 'healthy');
  const sevClass = severity === 'critical' ? 'danger' : (severity === 'degraded' || severity === 'warning' ? 'warn' : 'ok');
  const rootCauses = Array.isArray(payload.rootCauses) ? payload.rootCauses : [];
  const plan = Array.isArray(payload.remediationPlan) ? payload.remediationPlan : [];
  const excerpts = Array.isArray(payload.signals?.logs?.excerpts) ? payload.signals.logs.excerpts : [];

  const causesHtml = rootCauses.length === 0
    ? '<div class="card"><div class="card-title">No active critical incidents detected</div><div class="muted" style="margin-top:4px">Run a fresh live diagnosis for a specific projectId to inspect OOMKilled, CrashLoop, logs, uptime, and System Doctor signals.</div></div>'
    : rootCauses.slice(0, 6).map((c) => {
        const badgeCls = c.severity === 'critical' ? 'danger' : (c.severity === 'high' ? 'warn' : 'accent');
        return `<div class="card">
          <div class="card-title"><span>${escapeHtml(c.title || c.code)}</span><span class="pill ${badgeCls}">${escapeHtml(c.code)}</span></div>
          <div class="muted" style="margin-top:4px">${escapeHtml(c.evidence || '')}</div>
        </div>`;
      }).join('');

  const actionsHtml = (plan.length > 0
    ? plan.slice(0, 4)
    : [{
        action: 'restart_service',
        projectId: payload.scope && payload.scope !== 'instance' ? payload.scope : '',
        rationale: 'Preview safe 2-phase remediation (dryRun -> HMAC confirmToken -> apply).'
      }]
  ).map((step, idx) => {
    const act = step.action || 'restart_service';
    const pid = (step.args && step.args.projectId) || step.projectId || '';
    return `<div class="card" data-rem-idx="${idx}">
      <div class="card-title">
        <span class="mono">${escapeHtml(act)}${pid ? ' · ' + escapeHtml(pid) : ''}</span>
        <span class="pill accent">2-Phase Safe</span>
      </div>
      <div class="muted" style="margin:4px 0 8px">${escapeHtml(step.rationale || 'Requires dryRun: true before execution.')}</div>
      <div class="row">
        <button type="button" class="btn primary btn-dryrun" data-action="${escapeHtml(act)}" data-project="${escapeHtml(pid)}">1. Preview Plan (dryRun: true)</button>
        <button type="button" class="btn danger btn-apply" data-action="${escapeHtml(act)}" data-project="${escapeHtml(pid)}" disabled>2. Confirm &amp; Apply (confirmToken)</button>
      </div>
    </div>`;
  }).join('');

  const bodyHtml = `
    <div class="row">
      <span class="pill ${sevClass}">Severity: ${escapeHtml(severity.toUpperCase())}</span>
      <span class="pill mono">Scope: ${escapeHtml(payload.scope || 'instance')}</span>
      <span class="pill">Root Causes: ${rootCauses.length}</span>
      <button type="button" class="btn" id="btn-rediagnose">Run culkibo_diagnose_incident</button>
    </div>
    <div class="grid">${causesHtml}</div>
    ${excerpts.length > 0 ? `<div class="logbox">${escapeHtml(excerpts.join('\n'))}</div>` : ''}
    <div class="grid" id="remediation-actions">${actionsHtml}</div>
    <div class="logbox" id="rem-output">Waiting for Phase 1 dryRun preview. confirmToken is single-use HMAC-SHA256 (5 min TTL) and never persisted.</div>
  `;

  const appScript = `
    var app = window.__CULKIBO_APP__;
    var mintedTokens = Object.create(null);
    var outBox = document.getElementById('rem-output');

    function extractStructured(res) {
      if (!res) return null;
      if (res.structuredContent) return res.structuredContent;
      if (res.result && res.result.structuredContent) return res.result.structuredContent;
      return res;
    }

    document.getElementById('btn-rediagnose').addEventListener('click', function () {
      var args = app.state.scope && app.state.scope !== 'instance' ? { projectId: app.state.scope } : {};
      app.callTool('culkibo_diagnose_incident', args).then(function (r) {
        outBox.textContent = JSON.stringify(extractStructured(r), null, 2);
      });
    });

    var dryBtns = document.querySelectorAll('.btn-dryrun');
    for (var i = 0; i < dryBtns.length; i++) {
      dryBtns[i].addEventListener('click', function () {
        var btn = this;
        var act = btn.getAttribute('data-action');
        var pid = btn.getAttribute('data-project');
        var args = { action: act, dryRun: true };
        if (pid) args.projectId = pid;
        app.callTool('culkibo_auto_remediate', args).then(function (res) {
          var sc = extractStructured(res);
          outBox.textContent = JSON.stringify(sc, null, 2);
          if (sc && typeof sc.confirmToken === 'string' && sc.confirmToken.indexOf('ckr_') === 0) {
            mintedTokens[act + ':' + pid] = sc.confirmToken;
            var applyBtn = btn.parentElement.querySelector('.btn-apply');
            if (applyBtn) applyBtn.disabled = false;
          }
        });
      });
    }

    var applyBtns = document.querySelectorAll('.btn-apply');
    for (var j = 0; j < applyBtns.length; j++) {
      applyBtns[j].addEventListener('click', function () {
        var btn = this;
        var act = btn.getAttribute('data-action');
        var pid = btn.getAttribute('data-project');
        var tok = mintedTokens[act + ':' + pid];
        if (!tok) return;
        var args = { action: act, dryRun: false, confirmToken: tok };
        if (pid) args.projectId = pid;
        btn.disabled = true;
        delete mintedTokens[act + ':' + pid];
        app.callTool('culkibo_auto_remediate', args).then(function (res) {
          outBox.textContent = JSON.stringify(extractStructured(res), null, 2);
        });
      });
    }
  `;

  return renderAppShell({
    uri: 'ui://culkibo/incident-remediator',
    title: 'Culkibo Incident Remediator',
    subtitle: 'Correlates OOMKilled, CrashLoop, logs, uptime & System Doctor -> 2-phase HMAC confirmToken fix',
    badge: 'MCP App · Self-Healing',
    initialData: payload,
    bodyHtml,
    appScript
  });
}

/**
 * Renderiza `ui://culkibo/coolify-migration-diff`.
 * @param {any} payload
 */
function renderCoolifyDiffApp(payload = {}) {
  const parityScore = Number.isFinite(Number(payload.parityScore)) ? Number(payload.parityScore) : 100;
  const resources = payload.resources || { apps: [], databases: [], services: [] };
  const magicVars = Array.isArray(payload.magicVars) ? payload.magicVars : [
    { from: '${SERVICE_FQDN_APP}', to: 'https://app.example.com', kind: 'domain' },
    { from: '${SERVICE_PASSWORD_POSTGRES}', to: '${vault.SERVICE_PASSWORD_POSTGRES}', kind: 'vault-secret' },
    { from: '${SERVICE_BASE64_64_AUTH}', to: '${vault.SERVICE_BASE64_64_AUTH}', kind: 'vault-secret' }
  ];
  const traefikDiffs = Array.isArray(payload.traefikDiffs) ? payload.traefikDiffs : [
    { traefik: 'traefik.http.routers.app.rule=Host(`app.example.com`)', caddy: 'domainManager route -> TLS ACME + HTTP/3' },
    { traefik: 'traefik.http.middlewares.auth.basicauth.users=...', caddy: 'domain.basicAuth (bcrypt native, $$ unescaped)' },
    { traefik: 'traefik.http.middlewares.sec.headers.stsSeconds=31536000', caddy: 'domain.hstsMaxAge + securityHeaders: true' }
  ];

  const magicRows = magicVars.slice(0, 12).map((m) =>
    `<div class="card"><div class="card-title"><span class="mono">${escapeHtml(m.from)}</span><span class="pill ok">→ ${escapeHtml(m.to)}</span></div><div class="muted" style="margin-top:3px">Redacted safe translation (${escapeHtml(m.kind || 'env')})</div></div>`
  ).join('');

  const traefikRows = traefikDiffs.slice(0, 12).map((t) =>
    `<div class="card"><div class="mono muted">${escapeHtml(t.traefik)}</div><div class="mono" style="margin-top:4px;color:var(--ok)">→ ${escapeHtml(t.caddy)}</div></div>`
  ).join('');

  const bodyHtml = `
    <div class="row">
      <span class="pill ok">Parity Score: ${parityScore}%</span>
      <span class="pill accent">Apps: ${Array.isArray(resources.apps) ? resources.apps.length : 0}</span>
      <span class="pill warn">Databases: ${Array.isArray(resources.databases) ? resources.databases.length : 0}</span>
      <span class="pill">Services: ${Array.isArray(resources.services) ? resources.services.length : 0}</span>
    </div>
    <div class="tabs">
      <button type="button" class="tab active" data-tab="magic">Magic Vars → Vault (${magicVars.length})</button>
      <button type="button" class="tab" data-tab="traefik">Traefik → Caddy Diff (${traefikDiffs.length})</button>
      <button type="button" class="tab" data-tab="cutover">Zero-Downtime Cutover</button>
    </div>
    <div id="pane-magic" class="grid">${magicRows}</div>
    <div id="pane-traefik" class="grid" style="display:none">${traefikRows}</div>
    <div id="pane-cutover" class="card" style="display:none">
      <div class="card-title">Zero-Downtime Cutover Safety Net</div>
      <ol class="muted" style="padding-left:18px;margin:6px 0">
        <li>Run <span class="mono">culkibo_migrate_coolify(mode: "preview")</span> to inspect parity &amp; redacted vault mappings.</li>
        <li>Import selectively with <span class="mono">mode: "import"</span> — original Coolify server stays untouched.</li>
        <li>Verify TLS &amp; HTTP parity with <span class="mono">culkibo_diagnose_domain</span> + <span class="mono">culkibo_smoke_test_run</span> before DNS flip.</li>
      </ol>
      <div class="row">
        <button type="button" class="btn primary" id="btn-reconcile">Preview Reconcile Ingress (dryRun)</button>
        <button type="button" class="btn" id="btn-list-projects">Verify Imported Projects</button>
      </div>
    </div>
  `;

  const appScript = `
    var app = window.__CULKIBO_APP__;
    var tabs = document.querySelectorAll('.tab');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].addEventListener('click', function () {
        var target = this.getAttribute('data-tab');
        for (var j = 0; j < tabs.length; j++) tabs[j].classList.remove('active');
        this.classList.add('active');
        document.getElementById('pane-magic').style.display = target === 'magic' ? 'grid' : 'none';
        document.getElementById('pane-traefik').style.display = target === 'traefik' ? 'grid' : 'none';
        document.getElementById('pane-cutover').style.display = target === 'cutover' ? 'block' : 'none';
      });
    }
    document.getElementById('btn-reconcile').addEventListener('click', function () {
      app.callTool('culkibo_auto_remediate', { action: 'reconcile_ingress', dryRun: true });
    });
    document.getElementById('btn-list-projects').addEventListener('click', function () {
      app.callTool('culkibo_list_projects', {});
    });
  `;

  return renderAppShell({
    uri: 'ui://culkibo/coolify-migration-diff',
    title: 'Coolify v4 Parity & Traefik → Caddy Diff',
    subtitle: 'Redacted Magic Variables, native Caddy edge translation & zero-downtime cutover plan',
    badge: 'MCP App · Migration Diff',
    initialData: { parityScore, resources, magicVars, traefikDiffs },
    bodyHtml,
    appScript
  });
}

/**
 * Renderiza el recurso `ui://culkibo/*` solicitado en HTML autocontenido con CSP estricta.
 * @param {string} uri
 * @param {any} [payload]
 * @returns {{ uri: string, mimeType: string, text: string, _meta: { ui: { csp: typeof MCP_APP_CSP_META, prefersBorder: boolean, specVersion: string } } } | null}
 */
function renderMcpApp(uri, payload = {}) {
  const clean = String(uri || '').trim();
  const meta = {
    ui: {
      csp: MCP_APP_CSP_META,
      prefersBorder: true,
      specVersion: MCP_APPS_SPEC_VERSION
    }
  };
  if (clean === 'ui://culkibo/topology') {
    return { uri: clean, mimeType: MCP_APP_MIME_TYPE, text: renderTopologyApp(payload), _meta: meta };
  }
  if (clean === 'ui://culkibo/incident-remediator') {
    return { uri: clean, mimeType: MCP_APP_MIME_TYPE, text: renderIncidentRemediatorApp(payload), _meta: meta };
  }
  if (clean === 'ui://culkibo/coolify-migration-diff') {
    return { uri: clean, mimeType: MCP_APP_MIME_TYPE, text: renderCoolifyDiffApp(payload), _meta: meta };
  }
  return null;
}

module.exports = {
  MCP_APP_MIME_TYPE,
  MCP_APPS_SPEC_VERSION,
  MCP_APP_CSP_POLICY,
  MCP_APP_CSP_META,
  MCP_APP_RESOURCES,
  TOOL_UI_RESOURCE_MAP,
  escapeHtml,
  sanitizeAppData,
  safeJsonForScript,
  renderMcpApp
};
