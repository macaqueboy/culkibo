-- Esquema Cloudflare D1 para el recolector edge de Culkibo (capa gratuita: 100k req/día)

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

CREATE INDEX IF NOT EXISTS idx_d1_events_received ON events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_d1_events_fp ON events(fingerprint, received_at DESC);

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
  sample_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feature_counters (
  day TEXT NOT NULL,
  feature_key TEXT NOT NULL,
  ok_count INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, feature_key)
);
