-- Job logs are untrusted reports: shape validation never authenticates a runner measurement.
-- Preserve existing values while correcting their provenance, including historical measured rows.
CREATE TABLE jobs_reported (
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
  telemetry_kind TEXT CHECK (telemetry_kind IS NULL OR telemetry_kind = 'reported'),
  CHECK ((telemetry IS NULL) = (telemetry_kind IS NULL))
);
INSERT INTO jobs_reported (job_id, run_id, attempt, repo_id, name, workflow_name, status, runner_name, labels, runner_group, queued_at, started_at, completed_at, conclusion, telemetry, telemetry_kind)
SELECT job_id, run_id, attempt, repo_id, name, workflow_name, status, runner_name, labels, runner_group, queued_at, started_at, completed_at, conclusion, telemetry, CASE WHEN telemetry IS NOT NULL THEN 'reported' ELSE NULL END FROM jobs;
DROP TABLE jobs;
ALTER TABLE jobs_reported RENAME TO jobs;
CREATE INDEX jobs_queued ON jobs (queued_at);
CREATE INDEX jobs_repo_queued ON jobs (repo_id, queued_at);
CREATE INDEX jobs_run ON jobs (repo_id, run_id, attempt);
