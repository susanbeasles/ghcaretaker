/* D1 ghcaretaker-observatory: workflow metrics (infra-root ADR-0001 section 3). Written only by src/metrics.mjs. Timestamps are ISO-8601 UTC as produced by Date.prototype.toISOString, so text order is time order. Provenance: event columns are measured (GitHub event timestamps); billable_* is reported (GitHub API, verbatim units) and marked by billable_kind; telemetry is measured (runner /proc samples) and marked by telemetry_kind. Estimates are never stored. */
CREATE TABLE runs (
  repo_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  attempt INTEGER NOT NULL,
  workflow_id INTEGER,
  workflow_name TEXT,
  path TEXT,
  event TEXT,
  head_branch TEXT,
  head_sha TEXT,
  actor_id INTEGER,
  status TEXT NOT NULL,
  conclusion TEXT,
  created_at TEXT NOT NULL,
  run_started_at TEXT,
  updated_at TEXT NOT NULL,
  billable_ms INTEGER,
  billable_json TEXT,
  billable_kind TEXT CHECK (billable_kind IS NULL OR billable_kind = 'reported'),
  CHECK ((billable_ms IS NULL) = (billable_kind IS NULL) AND (billable_json IS NULL) = (billable_kind IS NULL)),
  PRIMARY KEY (repo_id, run_id, attempt)
);
CREATE INDEX runs_created ON runs (created_at);
CREATE INDEX runs_repo_created ON runs (repo_id, created_at);
CREATE TABLE jobs (
  job_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  attempt INTEGER NOT NULL,
  repo_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  workflow_name TEXT,
  status TEXT NOT NULL,
  runner_name TEXT,
  labels TEXT NOT NULL,
  runner_group TEXT,
  queued_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  conclusion TEXT,
  telemetry TEXT,
  telemetry_kind TEXT CHECK (telemetry_kind IS NULL OR telemetry_kind = 'measured'),
  CHECK ((telemetry IS NULL) = (telemetry_kind IS NULL))
);
CREATE INDEX jobs_queued ON jobs (queued_at);
CREATE INDEX jobs_repo_queued ON jobs (repo_id, queued_at);
CREATE INDEX jobs_run ON jobs (repo_id, run_id, attempt);
CREATE TABLE steps (
  job_id INTEGER NOT NULL,
  number INTEGER NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  conclusion TEXT,
  started_at TEXT,
  completed_at TEXT,
  PRIMARY KEY (job_id, number)
);
CREATE TABLE deliveries_seen (
  delivery_id TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);
