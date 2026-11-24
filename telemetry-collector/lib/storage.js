'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { DatabaseSync } = require('node:sqlite');
const { ISSUE_EVENT_TYPES } = require('./schema');

/**
 * Almacenamiento en SQLite nativo (`node:sqlite`, modo WAL) + archivo diario NDJSON comprimido con gzip.
 * Cero dependencias npm externas y cero almacenamiento de direcciones IP reales.
 */
class TelemetryStorage {
  /** @param {{ dbPath: string, archiveDir: string, retentionDays?: number, alertSpikeThreshold?: number }} opts */
  constructor(opts) {
    this.dbPath = opts.dbPath;
    this.archiveDir = opts.archiveDir;
    this.retentionDays = opts.retentionDays || 90;
    this.alertSpikeThreshold = opts.alertSpikeThreshold || 25;

    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    fs.mkdirSync(this.archiveDir, { recursive: true });

    this.db = new DatabaseSync(this.dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this._initSchema();
  }

  _initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS instances (
        instance_id TEXT PRIMARY KEY,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        app_version TEXT NOT NULL DEFAULT 'unknown',
        node_version TEXT,
        platform TEXT,
        arch TEXT,
        ram_bucket TEXT,
        install_method TEXT,
        docker_available INTEGER,
        caddy_available INTEGER,
        projects_bucket TEXT,
        databases_bucket TEXT,
        features_json TEXT,
        event_count INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        type TEXT NOT NULL,
        fingerprint TEXT,
        app_version TEXT NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 1,
        ts TEXT NOT NULL,
        received_at TEXT NOT NULL,
        summary TEXT,
        payload_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at DESC);
      CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, received_at DESC);
      CREATE INDEX IF NOT EXISTS idx_events_fp ON events(fingerprint, received_at DESC);

      CREATE TABLE IF NOT EXISTS issue_groups (
        fingerprint TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        last_version TEXT NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 1,
        affected_instances_json TEXT NOT NULL DEFAULT '[]',
        versions_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'open',
        sample_json TEXT NOT NULL,
        alert_sent_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_issues_status ON issue_groups(status, last_seen DESC);

      CREATE TABLE IF NOT EXISTS feature_counters (
        day TEXT NOT NULL,
        feature_key TEXT NOT NULL,
        ok_count INTEGER NOT NULL DEFAULT 0,
        fail_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (day, feature_key)
      );
    `);
  }

  /**
   * Ingiere un sobre validado y devuelve la lista de triggers de alerta (`new_issue`, `regression`, `spike`).
   * @param {{ instanceId: string, appVersion: string, receivedAt: string, events: any[] }} envelope
   */
  ingestEnvelope(envelope) {
    const { instanceId, appVersion, receivedAt, events } = envelope;
    const day = receivedAt.slice(0, 10);
    /** @type {Array<{ trigger: 'new_issue' | 'regression' | 'spike', fingerprint: string, type: string, title: string, appVersion: string, occurrences: number, affectedInstances: number, sample: any }>} */
    const alertCandidates = [];

    const upsertInstance = this.db.prepare(`
      INSERT INTO instances (instance_id, first_seen, last_seen, app_version, event_count)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(instance_id) DO UPDATE SET
        last_seen = excluded.last_seen,
        app_version = excluded.app_version,
        event_count = instances.event_count + excluded.event_count
    `);

    const updateInstanceHeartbeat = this.db.prepare(`
      UPDATE instances SET
        node_version = ?,
        platform = ?,
        arch = ?,
        ram_bucket = ?,
        install_method = ?,
        docker_available = ?,
        caddy_available = ?,
        projects_bucket = ?,
        databases_bucket = ?,
        features_json = ?
      WHERE instance_id = ?
    `);

    const insertEvent = this.db.prepare(`
      INSERT INTO events (event_id, instance_id, type, fingerprint, app_version, occurrences, ts, received_at, summary, payload_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const selectIssue = this.db.prepare(`SELECT * FROM issue_groups WHERE fingerprint = ?`);
    const insertIssue = this.db.prepare(`
      INSERT INTO issue_groups (
        fingerprint, type, title, first_seen, last_seen, last_version,
        occurrences, affected_instances_json, versions_json, status, sample_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    `);
    const updateIssue = this.db.prepare(`
      UPDATE issue_groups SET
        title = ?,
        last_seen = ?,
        last_version = ?,
        occurrences = ?,
        affected_instances_json = ?,
        versions_json = ?,
        status = ?,
        sample_json = ?
      WHERE fingerprint = ?
    `);

    const upsertFeature = this.db.prepare(`
      INSERT INTO feature_counters (day, feature_key, ok_count, fail_count)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(day, feature_key) DO UPDATE SET
        ok_count = feature_counters.ok_count + excluded.ok_count,
        fail_count = feature_counters.fail_count + excluded.fail_count
    `);

    const countRecentHourOccurrences = this.db.prepare(`
      SELECT COALESCE(SUM(occurrences), 0) AS total
      FROM events
      WHERE fingerprint = ? AND received_at >= ?
    `);

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    this.db.exec('BEGIN');
    try {
      upsertInstance.run(instanceId, receivedAt, receivedAt, appVersion, events.length);

      for (const ev of events) {
        insertEvent.run(
          ev.eventId,
          instanceId,
          ev.type,
          ev.fingerprint,
          appVersion,
          ev.occurrences,
          ev.ts,
          receivedAt,
          ev.title,
          JSON.stringify(ev.data)
        );

        if (ev.type === 'instance_heartbeat' && ev.data && typeof ev.data === 'object') {
          const d = ev.data;
          const osInfo = d.os && typeof d.os === 'object' ? d.os : {};
          const caps = d.capabilities && typeof d.capabilities === 'object' ? d.capabilities : {};
          const counts = d.counts && typeof d.counts === 'object' ? d.counts : {};
          updateInstanceHeartbeat.run(
            d.nodeVersion || null,
            osInfo.platform || null,
            osInfo.arch || null,
            d.ramBucket || null,
            d.installMethod || null,
            caps.dockerAvailable === true ? 1 : caps.dockerAvailable === false ? 0 : null,
            caps.caddyAvailable === true ? 1 : caps.caddyAvailable === false ? 0 : null,
            counts.projects || null,
            counts.databases || null,
            JSON.stringify(d.features || {}),
            instanceId
          );
        }

        if (ev.type === 'feature_usage' && ev.data && ev.data.counters && typeof ev.data.counters === 'object') {
          for (const [k, rawVal] of Object.entries(ev.data.counters).slice(0, 60)) {
            const ok = Math.max(0, Math.min(100000, Math.floor(Number(rawVal?.ok || 0))));
            const fail = Math.max(0, Math.min(100000, Math.floor(Number(rawVal?.fail || 0))));
            if (ok > 0 || fail > 0) {
              upsertFeature.run(day, String(k).slice(0, 64), ok, fail);
            }
          }
        }

        if (ISSUE_EVENT_TYPES.has(ev.type) && ev.fingerprint) {
          const existing = /** @type {any} */ (selectIssue.get(ev.fingerprint));
          if (!existing) {
            const affected = [instanceId];
            const versions = [appVersion];
            insertIssue.run(
              ev.fingerprint,
              ev.type,
              ev.title,
              receivedAt,
              receivedAt,
              appVersion,
              ev.occurrences,
              JSON.stringify(affected),
              JSON.stringify(versions),
              JSON.stringify(ev.data)
            );
            alertCandidates.push({
              trigger: 'new_issue',
              fingerprint: ev.fingerprint,
              type: ev.type,
              title: ev.title,
              appVersion,
              occurrences: ev.occurrences,
              affectedInstances: 1,
              sample: ev.data,
            });
          } else {
            const affected = safeJsonArray(existing.affected_instances_json);
            if (!affected.includes(instanceId) && affected.length < 5000) affected.push(instanceId);
            const versions = safeJsonArray(existing.versions_json);
            const isNewVersion = !versions.includes(appVersion);
            if (isNewVersion && versions.length < 100) versions.push(appVersion);

            let nextStatus = existing.status;
            let trigger = null;
            if (existing.status === 'resolved' && isNewVersion) {
              nextStatus = 'open';
              trigger = 'regression';
            }

            const totalOccurrences = Number(existing.occurrences || 0) + ev.occurrences;
            updateIssue.run(
              ev.title,
              receivedAt,
              appVersion,
              totalOccurrences,
              JSON.stringify(affected),
              JSON.stringify(versions),
              nextStatus,
              JSON.stringify(ev.data),
              ev.fingerprint
            );

            if (!trigger && nextStatus === 'open') {
              const hourRow = /** @type {any} */ (countRecentHourOccurrences.get(ev.fingerprint, oneHourAgo));
              if (hourRow && Number(hourRow.total) >= this.alertSpikeThreshold) {
                trigger = 'spike';
              }
            }

            if (trigger) {
              alertCandidates.push({
                trigger: /** @type {'regression' | 'spike'} */ (trigger),
                fingerprint: ev.fingerprint,
                type: ev.type,
                title: ev.title,
                appVersion,
                occurrences: totalOccurrences,
                affectedInstances: affected.length,
                sample: ev.data,
              });
            }
          }
        }
      }

      this.db.exec('COMMIT');
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    }

    this._appendNdjsonArchive(day, envelope);
    return { accepted: events.length, alertCandidates };
  }

  /** @param {string} day @param {any} envelope */
  _appendNdjsonArchive(day, envelope) {
    try {
      const ndjsonFile = path.join(this.archiveDir, `${day}.ndjson`);
      fs.appendFileSync(ndjsonFile, `${JSON.stringify(envelope)}\n`, { encoding: 'utf8', mode: 0o600 });
      this.archiveOldDays(day);
    } catch {
      // el archivo NDJSON es complementario; nunca debe tumbar la ingesta SQLite
    }
  }

  /** Comprime con gzip todos los archivos NDJSON de días anteriores al día actual. */
  archiveOldDays(currentDay = new Date().toISOString().slice(0, 10)) {
    try {
      const files = fs.readdirSync(this.archiveDir);
      for (const file of files) {
        if (!file.endsWith('.ndjson')) continue;
        const fileDay = file.slice(0, -'.ndjson'.length);
        if (fileDay >= currentDay) continue;
        const src = path.join(this.archiveDir, file);
        const dst = `${src}.gz`;
        const raw = fs.readFileSync(src);
        const gz = zlib.gzipSync(raw, { level: 6 });
        fs.writeFileSync(dst, gz, { mode: 0o600 });
        fs.unlinkSync(src);
      }
    } catch {
      // silencioso
    }
  }

  /** @param {string} fingerprint */
  markAlertSent(fingerprint) {
    try {
      this.db.prepare('UPDATE issue_groups SET alert_sent_at = ? WHERE fingerprint = ?')
        .run(new Date().toISOString(), fingerprint);
    } catch {
      // ignorar
    }
  }

  /** @param {number} [days] */
  pruneRetention(days = this.retentionDays) {
    const cutoff = new Date(Date.now() - Math.max(1, days) * 24 * 60 * 60 * 1000).toISOString();
    const res = this.db.prepare('DELETE FROM events WHERE received_at < ?').run(cutoff);
    return { deletedEvents: Number(res.changes || 0), cutoff };
  }

  getSummary() {
    const now = Date.now();
    const ago24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const ago7d = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    const ago30d = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();

    const active24h = Number(/** @type {any} */ (this.db.prepare('SELECT COUNT(*) AS c FROM instances WHERE last_seen >= ?').get(ago24h))?.c || 0);
    const active7d = Number(/** @type {any} */ (this.db.prepare('SELECT COUNT(*) AS c FROM instances WHERE last_seen >= ?').get(ago7d))?.c || 0);
    const active30d = Number(/** @type {any} */ (this.db.prepare('SELECT COUNT(*) AS c FROM instances WHERE last_seen >= ?').get(ago30d))?.c || 0);
    const totalInstances = Number(/** @type {any} */ (this.db.prepare('SELECT COUNT(*) AS c FROM instances').get())?.c || 0);
    const totalEvents = Number(/** @type {any} */ (this.db.prepare('SELECT COUNT(*) AS c FROM events').get())?.c || 0);
    const openIssues = Number(/** @type {any} */ (this.db.prepare("SELECT COUNT(*) AS c FROM issue_groups WHERE status = 'open'").get())?.c || 0);
    const openCrashes = Number(/** @type {any} */ (this.db.prepare("SELECT COUNT(*) AS c FROM issue_groups WHERE status = 'open' AND type = 'server_crash'").get())?.c || 0);
    const failures7d = Number(/** @type {any} */ (this.db.prepare("SELECT COALESCE(SUM(occurrences), 0) AS c FROM events WHERE type IN ('server_crash','api_error_5xx','operation_failure','client_error') AND received_at >= ?").get(ago7d))?.c || 0);

    const versions = this.db.prepare(`
      SELECT app_version AS version, COUNT(*) AS count
      FROM instances
      WHERE last_seen >= ?
      GROUP BY app_version
      ORDER BY count DESC
      LIMIT 12
    `).all(ago30d);

    const platforms = this.db.prepare(`
      SELECT COALESCE(platform, 'unknown') AS platform, COALESCE(arch, 'unknown') AS arch, COUNT(*) AS count
      FROM instances
      WHERE last_seen >= ?
      GROUP BY platform, arch
      ORDER BY count DESC
      LIMIT 12
    `).all(ago30d);

    const capabilities = /** @type {any} */ (this.db.prepare(`
      SELECT
        SUM(CASE WHEN docker_available = 1 THEN 1 ELSE 0 END) AS dockerYes,
        SUM(CASE WHEN docker_available = 0 THEN 1 ELSE 0 END) AS dockerNo,
        SUM(CASE WHEN caddy_available = 1 THEN 1 ELSE 0 END) AS caddyYes,
        SUM(CASE WHEN caddy_available = 0 THEN 1 ELSE 0 END) AS caddyNo
      FROM instances
      WHERE last_seen >= ?
    `).get(ago30d)) || {};

    const topFeatures = this.db.prepare(`
      SELECT feature_key AS feature, SUM(ok_count) AS okCount, SUM(fail_count) AS failCount
      FROM feature_counters
      WHERE day >= ?
      GROUP BY feature_key
      ORDER BY (SUM(ok_count) + SUM(fail_count)) DESC
      LIMIT 25
    `).all(ago30d.slice(0, 10));

    return {
      generatedAt: new Date().toISOString(),
      kpis: {
        active24h,
        active7d,
        active30d,
        totalInstances,
        totalEvents,
        openIssues,
        openCrashes,
        failures7d,
      },
      versions,
      platforms,
      capabilities: {
        dockerYes: Number(capabilities.dockerYes || 0),
        dockerNo: Number(capabilities.dockerNo || 0),
        caddyYes: Number(capabilities.caddyYes || 0),
        caddyNo: Number(capabilities.caddyNo || 0),
      },
      topFeatures,
    };
  }

  /** @param {{ status?: string, type?: string, limit?: number }} [opts] */
  listIssues({ status = 'all', type = 'all', limit = 100 } = {}) {
    const clauses = [];
    const params = [];
    if (status && status !== 'all' && ['open', 'resolved', 'ignored'].includes(status)) {
      clauses.push('status = ?');
      params.push(status);
    }
    if (type && type !== 'all' && ISSUE_EVENT_TYPES.has(type)) {
      clauses.push('type = ?');
      params.push(type);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    const rows = /** @type {any[]} */ (this.db.prepare(`
      SELECT * FROM issue_groups
      ${where}
      ORDER BY last_seen DESC
      LIMIT ?
    `).all(...params, safeLimit));

    return rows.map((r) => ({
      fingerprint: r.fingerprint,
      type: r.type,
      title: r.title,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      lastVersion: r.last_version,
      occurrences: Number(r.occurrences || 0),
      affectedInstances: safeJsonArray(r.affected_instances_json).length,
      versions: safeJsonArray(r.versions_json),
      status: r.status,
      sample: safeJsonObj(r.sample_json),
      alertSentAt: r.alert_sent_at || null,
    }));
  }

  /** @param {string} fingerprint @param {string} status */
  updateIssueStatus(fingerprint, status) {
    if (!['open', 'resolved', 'ignored'].includes(status)) {
      throw new Error('Estado inválido (usa open, resolved o ignored)');
    }
    const res = this.db.prepare('UPDATE issue_groups SET status = ? WHERE fingerprint = ?').run(status, fingerprint);
    if (!res.changes) return null;
    const row = /** @type {any} */ (this.db.prepare('SELECT * FROM issue_groups WHERE fingerprint = ?').get(fingerprint));
    return row ? {
      fingerprint: row.fingerprint,
      status: row.status,
      title: row.title,
      occurrences: Number(row.occurrences || 0),
    } : null;
  }

  /** @param {{ type?: string, fingerprint?: string, limit?: number }} [opts] */
  listEvents({ type = 'all', fingerprint = '', limit = 100 } = {}) {
    const clauses = [];
    const params = [];
    if (type && type !== 'all') {
      clauses.push('type = ?');
      params.push(type);
    }
    if (fingerprint) {
      clauses.push('fingerprint = ?');
      params.push(fingerprint);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    const rows = /** @type {any[]} */ (this.db.prepare(`
      SELECT id, event_id, instance_id, type, fingerprint, app_version, occurrences, ts, received_at, summary, payload_json
      FROM events
      ${where}
      ORDER BY id DESC
      LIMIT ?
    `).all(...params, safeLimit));

    return rows.map((r) => ({
      id: r.id,
      eventId: r.event_id,
      instanceId: r.instance_id,
      type: r.type,
      fingerprint: r.fingerprint,
      appVersion: r.app_version,
      occurrences: Number(r.occurrences || 1),
      ts: r.ts,
      receivedAt: r.received_at,
      summary: r.summary,
      data: safeJsonObj(r.payload_json),
    }));
  }

  /** @param {'json' | 'csv'} format */
  exportIssues(format = 'json') {
    const issues = this.listIssues({ status: 'all', limit: 500 });
    if (format === 'csv') {
      const header = ['fingerprint', 'type', 'status', 'occurrences', 'affected_instances', 'last_version', 'first_seen', 'last_seen', 'title'];
      const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
      const lines = [header.join(',')];
      for (const it of issues) {
        lines.push([
          it.fingerprint, it.type, it.status, it.occurrences, it.affectedInstances,
          it.lastVersion, it.firstSeen, it.lastSeen, it.title,
        ].map(esc).join(','));
      }
      return lines.join('\n');
    }
    return JSON.stringify({ exportedAt: new Date().toISOString(), summary: this.getSummary(), issues }, null, 2);
  }

  close() {
    try { this.db.close(); } catch { /* ignore */ }
  }
}

/** @param {string} raw */
function safeJsonArray(raw) {
  try {
    const p = JSON.parse(raw);
    return Array.isArray(p) ? p : [];
  } catch {
    return [];
  }
}

/** @param {string} raw */
function safeJsonObj(raw) {
  try {
    const p = JSON.parse(raw);
    return p && typeof p === 'object' ? p : {};
  } catch {
    return {};
  }
}

module.exports = { TelemetryStorage };
