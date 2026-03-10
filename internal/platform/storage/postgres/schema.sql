-- PostgreSQL schema blueprint for production persistence.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL,
  type TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  address TEXT UNIQUE NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id),
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  error TEXT NOT NULL DEFAULT '',
  normalized_target TEXT NOT NULL DEFAULT '',
  target_type TEXT NOT NULL DEFAULT '',
  profile TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  platform TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
  port INT NOT NULL,
  protocol TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  banner TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
  base_url TEXT NOT NULL,
  app_type TEXT NOT NULL DEFAULT '',
  framework TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
  application_id TEXT REFERENCES applications(id) ON DELETE SET NULL,
  service_id TEXT REFERENCES services(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  cvss DOUBLE PRECISION NOT NULL DEFAULT 0,
  vector TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS graph_nodes (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  label TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  from_id TEXT NOT NULL,
  to_id TEXT NOT NULL,
  type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_chains (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  steps TEXT NOT NULL,
  summary TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS step_results (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  category TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target_mode_status ON scans(normalized_target, mode, status);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_target_sev ON vulnerabilities(target_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_apps_scan_id ON applications(scan_id);
CREATE INDEX IF NOT EXISTS idx_steps_scan_id ON step_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_scan_id ON graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_scan_id ON graph_edges(scan_id);
