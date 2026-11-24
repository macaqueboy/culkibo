/**
 * Adaptador Cloudflare Workers + D1 (coste cero hasta 100.000 envíos/día)
 * Implementa el mismo contrato `POST /v1/ingest` y `/admin/api/*` que `server.js`.
 */

const ALLOWED_TYPES = new Set([
  'instance_heartbeat',
  'server_crash',
  'api_error_5xx',
  'operation_failure',
  'client_error',
  'feature_usage',
]);
const ISSUE_TYPES = new Set(['server_crash', 'api_error_5xx', 'operation_failure', 'client_error']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function constantTimeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function scrub(text, max = 300) {
  return String(text ?? '')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '<email>')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<ip>')
    .replace(/\b(Bearer|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 <redacted>')
    .slice(0, max);
}

async function sendAlert(env, issue) {
  const title = `🚨 Nuevo fallo Culkibo (${issue.type} · v${issue.appVersion})`;
  const text = `${title}\n${issue.title}\nFP: ${issue.fingerprint}`;
  const jobs = [];
  if (env.ALERT_TELEGRAM_BOT_TOKEN && env.ALERT_TELEGRAM_CHAT_ID) {
    jobs.push(fetch(`https://api.telegram.org/bot${encodeURIComponent(env.ALERT_TELEGRAM_BOT_TOKEN)}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.ALERT_TELEGRAM_CHAT_ID, text }),
    }));
  }
  if (env.ALERT_DISCORD_WEBHOOK) {
    jobs.push(fetch(env.ALERT_DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: text }),
    }));
  }
  if (jobs.length > 0) await Promise.allSettled(jobs);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'GET' && pathname === '/health') {
      return json({ ok: true, service: 'culkibo-telemetry-worker' });
    }

    if (request.method === 'POST' && pathname === '/v1/ingest') {
      const contentLen = Number(request.headers.get('content-length') || 0);
      if (contentLen > 64 * 1024) return json({ error: 'Payload demasiado grande' }, 413);
      const raw = await request.text();
      if (raw.length > 64 * 1024) return json({ error: 'Payload demasiado grande' }, 413);

      let body;
      try { body = JSON.parse(raw); } catch { return json({ error: 'JSON malformado' }, 400); }
      if (!body || body.schemaVersion !== 1 || !UUID_RE.test(String(body.instanceId || '')) || !Array.isArray(body.events)) {
        return json({ error: 'Sobre Schema v1 inválido' }, 400);
      }

      const now = new Date().toISOString();
      const day = now.slice(0, 10);
      const instanceId = body.instanceId.trim();
      const appVersion = String(body.appVersion || 'unknown').slice(0, 32);
      const events = body.events.slice(0, 50).filter((e) => e && ALLOWED_TYPES.has(e.type));
      if (events.length === 0) return json({ error: 'Sin eventos válidos' }, 400);

      await env.DB.prepare(`
        INSERT INTO instances (instance_id, first_seen, last_seen, app_version, event_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(instance_id) DO UPDATE SET
          last_seen = excluded.last_seen,
          app_version = excluded.app_version,
          event_count = instances.event_count + excluded.event_count
      `).bind(instanceId, now, now, appVersion, events.length).run();

      const alerts = [];
      for (const ev of events) {
        const occ = Math.max(1, Math.min(10000, Number(ev.occurrences) || 1));
        const fp = ISSUE_TYPES.has(ev.type) && typeof ev.fingerprint === 'string' ? ev.fingerprint.slice(0, 32) : null;
        const summary = scrub(ev.data?.message || ev.type, 160);
        await env.DB.prepare(`
          INSERT INTO events (event_id, instance_id, type, fingerprint, app_version, occurrences, ts, received_at, summary, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          String(ev.id || crypto.randomUUID()).slice(0, 64),
          instanceId,
          ev.type,
          fp,
          appVersion,
          occ,
          typeof ev.ts === 'string' ? ev.ts : now,
          now,
          summary,
          JSON.stringify(ev.data || {}).slice(0, 4096)
        ).run();

        if (ev.type === 'instance_heartbeat' && ev.data) {
          await env.DB.prepare(`
            UPDATE instances SET node_version = ?, platform = ?, arch = ?, ram_bucket = ?, install_method = ?, docker_available = ?, caddy_available = ?
            WHERE instance_id = ?
          `).bind(
            ev.data.nodeVersion || null,
            ev.data.os?.platform || null,
            ev.data.os?.arch || null,
            ev.data.ramBucket || null,
            ev.data.installMethod || null,
            ev.data.capabilities?.dockerAvailable === true ? 1 : ev.data.capabilities?.dockerAvailable === false ? 0 : null,
            ev.data.capabilities?.caddyAvailable === true ? 1 : ev.data.capabilities?.caddyAvailable === false ? 0 : null,
            instanceId
          ).run();
        }

        if (ev.type === 'feature_usage' && ev.data?.counters) {
          for (const [k, v] of Object.entries(ev.data.counters).slice(0, 40)) {
            await env.DB.prepare(`
              INSERT INTO feature_counters (day, feature_key, ok_count, fail_count)
              VALUES (?, ?, ?, ?)
              ON CONFLICT(day, feature_key) DO UPDATE SET
                ok_count = feature_counters.ok_count + excluded.ok_count,
                fail_count = feature_counters.fail_count + excluded.fail_count
            `).bind(day, String(k).slice(0, 64), Number(v?.ok || 0), Number(v?.fail || 0)).run();
          }
        }

        if (ISSUE_TYPES.has(ev.type) && fp) {
          const existing = await env.DB.prepare('SELECT * FROM issue_groups WHERE fingerprint = ?').bind(fp).first();
          const title = `[${ev.type}] ${summary}`;
          if (!existing) {
            await env.DB.prepare(`
              INSERT INTO issue_groups (fingerprint, type, title, first_seen, last_seen, last_version, occurrences, affected_instances_json, versions_json, status, sample_json)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            `).bind(fp, ev.type, title, now, now, appVersion, occ, JSON.stringify([instanceId]), JSON.stringify([appVersion]), JSON.stringify(ev.data || {}).slice(0, 4096)).run();
            alerts.push({ fingerprint: fp, type: ev.type, title, appVersion });
          } else {
            const insts = JSON.parse(existing.affected_instances_json || '[]');
            if (!insts.includes(instanceId) && insts.length < 5000) insts.push(instanceId);
            const vers = JSON.parse(existing.versions_json || '[]');
            const isNewVer = !vers.includes(appVersion);
            if (isNewVer && vers.length < 100) vers.push(appVersion);
            const nextStatus = existing.status === 'resolved' && isNewVer ? 'open' : existing.status;
            await env.DB.prepare(`
              UPDATE issue_groups SET last_seen = ?, last_version = ?, occurrences = ?, affected_instances_json = ?, versions_json = ?, status = ?, sample_json = ?
              WHERE fingerprint = ?
            `).bind(now, appVersion, Number(existing.occurrences || 0) + occ, JSON.stringify(insts), JSON.stringify(vers), nextStatus, JSON.stringify(ev.data || {}).slice(0, 4096), fp).run();
            if (existing.status === 'resolved' && isNewVer) {
              alerts.push({ fingerprint: fp, type: ev.type, title: `[REGRESIÓN] ${title}`, appVersion });
            }
          }
        }
      }

      for (const a of alerts) ctx.waitUntil(sendAlert(env, a));
      return json({ accepted: events.length, alertsQueued: alerts.length }, 202);
    }

    if (pathname.startsWith('/admin/api/')) {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      if (!env.ADMIN_TOKEN || !constantTimeEqual(token, env.ADMIN_TOKEN)) {
        return json({ error: 'No autorizado' }, 401);
      }
      if (request.method === 'GET' && pathname === '/admin/api/summary') {
        const ago24h = new Date(Date.now() - 86400_000).toISOString();
        const ago7d = new Date(Date.now() - 7 * 86400_000).toISOString();
        const a24 = await env.DB.prepare('SELECT COUNT(*) AS c FROM instances WHERE last_seen >= ?').bind(ago24h).first();
        const a7 = await env.DB.prepare('SELECT COUNT(*) AS c FROM instances WHERE last_seen >= ?').bind(ago7d).first();
        const openIssues = await env.DB.prepare("SELECT COUNT(*) AS c FROM issue_groups WHERE status = 'open'").first();
        return json({ generatedAt: new Date().toISOString(), kpis: { active24h: a24?.c || 0, active7d: a7?.c || 0, openIssues: openIssues?.c || 0 } });
      }
      if (request.method === 'GET' && pathname === '/admin/api/issues') {
        const rows = await env.DB.prepare('SELECT * FROM issue_groups ORDER BY last_seen DESC LIMIT 100').all();
        return json({ issues: rows.results || [] });
      }
    }

    return json({ error: 'No encontrado' }, 404);
  },
};
