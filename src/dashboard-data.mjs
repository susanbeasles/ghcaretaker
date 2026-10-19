// Data for the caretaker dashboard. Every function returns plain JSON (the /api twins return it as is; the HTML
// pages render it escaped). Reads are bounded: page limits 1..100, fixed date windows, LIMITed D1 queries over
// indexed columns, fan-out over at most MAX_REPOS repositories. Text that came from GitHub payloads (repository
// names, workflow, job, step and runner names, branches, author names) is untrusted and only ever escaped on output.
import { CodedError } from './bytes.mjs';
import { commitLedger, commitLedgerFor, findings, knownRepos, ledgerHead, recentEvents, verifyCommitLedger, verifyLedger } from './observatory-read.mjs';
import { promotionTagPrefix, MAIN, ZERO } from './integrity.mjs';
import { log, errorCode } from './log.mjs';

export const VERIFY_WINDOW = 1000;
export const MAX_REPOS = 100;
export const MAX_RUN_ROWS = 10_000;
export const MAX_JOB_ROWS = 20_000;
const DAY = 86_400_000;
const FAILED = new Set(['failure', 'timed_out', 'startup_failure']);
const DECIDED = new Set([...FAILED, 'success']);

// ---------- statistics ----------
/** Nearest-rank percentile of finite numbers; null for an empty set. */
export function percentile(values, p) {
  const v = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!v.length) return null;
  return v[Math.min(v.length - 1, Math.max(0, Math.ceil((p / 100) * v.length) - 1))];
}
const mean = values => { const v = values.filter(Number.isFinite); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
const span = (from, to) => { const a = Date.parse(from ?? ''), b = Date.parse(to ?? ''); return Number.isFinite(a) && Number.isFinite(b) && b >= a ? b - a : null; };

export const runDuration = r => (r.status === 'completed' ? span(r.run_started_at ?? r.created_at, r.updated_at) : null);
export const jobQueue = j => (j.started_at && j.conclusion !== 'skipped' ? span(j.queued_at, j.started_at) : null);
export const jobDuration = j => (j.status === 'completed' && j.conclusion !== 'skipped' ? span(j.started_at, j.completed_at) : null);

// Provenance of every figure (never mixed within one figure):
//   measured  - GitHub event timestamps and conclusions (and statistics over them)
//   reported  - GitHub API billing values in the API's unit; untrusted job-log telemetry claims
//   estimated - derived stand-ins for something not observed; computed at read time, never stored
// A figure is {value, kind, unit, n?}; value null means missing (no data), which is never shown as zero.
export const fig = (value, kind, unit, extra = {}) => ({ value: value === undefined || (typeof value === 'number' && !Number.isFinite(value)) ? null : value, kind, unit, ...extra });
export const HOSTED_RUNNER_GROUP = 'GitHub Actions';
export const ESTIMATE_BASIS = 'sum over completed jobs on GitHub-hosted runners of the job duration rounded up to whole minutes; only runs with no reported billing; no runner-type multiplier';

export const PROVENANCE = Object.freeze({
  measured: 'GitHub event timestamps and conclusions',
  reported: 'GitHub API billing values (milliseconds shown as minutes); untrusted job-log telemetry claims, not authenticated runner measurements',
  estimated: 'derived when nothing was reported; never stored, never summed with reported values',
});

const runKey = x => x.repo_id + ':' + x.run_id + ':' + x.attempt;

/** Summary over runs and the jobs that belong to them (rows already restricted to the window). */
export function summarize(runs, jobs) {
  const completed = runs.filter(r => r.status === 'completed');
  const decided = completed.filter(r => DECIDED.has(r.conclusion)), failures = decided.filter(r => FAILED.has(r.conclusion)).length;
  const billed = runs.filter(r => r.billable_kind === 'reported' && Number.isSafeInteger(r.billable_ms));
  const durations = runs.map(runDuration).filter(v => v !== null);
  const jobDurations = jobs.map(jobDuration).filter(v => v !== null);
  const queues = jobs.map(jobQueue).filter(v => v !== null);
  // Older databases labelled these same unauthenticated job-log claims measured.
  // Downgrade those rows at read time too, even before the provenance migration runs.
  const tele = jobs.filter(j => j.telemetry_kind === 'reported' || j.telemetry_kind === 'measured');
  const cpuMeans = tele.map(j => j.cpu_mean).filter(Number.isFinite), cpuP95s = tele.map(j => j.cpu_p95).filter(Number.isFinite), memPeaks = tele.map(j => j.mem_peak).filter(Number.isFinite);
  const jobsDecided = jobs.filter(j => j.status === 'completed' && DECIDED.has(j.conclusion)), jobFailures = jobsDecided.filter(j => FAILED.has(j.conclusion)).length;
  // Estimate: only for completed runs without reported billing, from their hosted-runner jobs present in `jobs`.
  const jobsByRun = new Map();
  for (const j of jobs) { const k = runKey(j); if (!jobsByRun.has(k)) jobsByRun.set(k, []); jobsByRun.get(k).push(j); }
  let estimate = 0, estimatedRuns = 0;
  for (const r of completed) {
    if (r.billable_kind === 'reported') continue;
    const hosted = (jobsByRun.get(runKey(r)) ?? []).filter(j => j.runner_group === HOSTED_RUNNER_GROUP).map(jobDuration).filter(v => v !== null);
    if (!hosted.length) continue;
    estimate += hosted.reduce((a, ms) => a + Math.ceil(ms / 60_000), 0); estimatedRuns++;
  }
  return {
    runs: fig(runs.length, 'measured', 'count'), jobs: fig(jobs.length, 'measured', 'count'), completed: fig(completed.length, 'measured', 'count'), failures: fig(failures, 'measured', 'count'),
    failure_rate: fig(decided.length ? failures / decided.length : null, 'measured', 'ratio', { n: decided.length }),
    job_failure_rate: fig(jobsDecided.length ? jobFailures / jobsDecided.length : null, 'measured', 'ratio', { n: jobsDecided.length }),
    run_duration_p50: fig(percentile(durations, 50), 'measured', 'ms', { n: durations.length }), run_duration_p95: fig(percentile(durations, 95), 'measured', 'ms', { n: durations.length }),
    job_duration_p50: fig(percentile(jobDurations, 50), 'measured', 'ms', { n: jobDurations.length }), job_duration_p95: fig(percentile(jobDurations, 95), 'measured', 'ms', { n: jobDurations.length }),
    queue_p95: fig(percentile(queues, 95), 'measured', 'ms', { n: queues.length }),
    billable_minutes: fig(billed.length ? billed.reduce((a, r) => a + r.billable_ms, 0) / 60_000 : null, 'reported', 'min', { n: billed.length, source: 'GET /repos/{r}/actions/runs/{id}/timing (billable total_ms)' }),
    estimated_minutes: fig(estimatedRuns ? estimate : null, 'estimated', 'min', { n: estimatedRuns, basis: ESTIMATE_BASIS }),
    telemetry_jobs: fig(tele.length, 'reported', 'count'),
    cpu_mean: fig(cpuMeans.length ? mean(cpuMeans) : null, 'reported', 'fraction', { n: cpuMeans.length }),
    cpu_p95: fig(percentile(cpuP95s, 95), 'reported', 'fraction', { n: cpuP95s.length }),
    memory_peak: fig(memPeaks.length ? Math.max(...memPeaks) : null, 'reported', 'bytes', { n: memPeaks.length }),
  };
}

// ---------- D1 reads ----------
async function runsSince(db, since) {
  const { results } = await db.prepare(`SELECT repo_id, run_id, attempt, workflow_name, status, conclusion, created_at, run_started_at, updated_at, billable_ms, billable_kind
    FROM runs WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?`).bind(since, MAX_RUN_ROWS + 1).all();
  return { rows: results.slice(0, MAX_RUN_ROWS), truncated: results.length > MAX_RUN_ROWS };
}

async function jobsSince(db, since) {
  const { results } = await db.prepare(`SELECT repo_id, run_id, attempt, job_id, name, workflow_name, status, conclusion, runner_group, queued_at, started_at, completed_at, telemetry_kind,
    json_extract(telemetry, '$.cpu_mean') AS cpu_mean, json_extract(telemetry, '$.cpu_p95') AS cpu_p95, json_extract(telemetry, '$.memory_used_max_bytes') AS mem_peak
    FROM jobs WHERE queued_at >= ? ORDER BY queued_at DESC LIMIT ?`).bind(since, MAX_JOB_ROWS + 1).all();
  return { rows: results.slice(0, MAX_JOB_ROWS), truncated: results.length > MAX_JOB_ROWS };
}

async function repoNames(env) {
  try { return new Map((await knownRepos(env)).slice(0, 10_000).map(r => [r.repo_id, r.full_name ?? null])); }
  catch (e) { log('warning', 'dashboard_repos_unavailable', { error: errorCode(e) }); return new Map(); }
}

// ---------- backup ----------
/** BackupStatus.summary() over the BACKUP_STATUS service binding; absent or failing is reported, never fatal. */
export async function backupSummary(env, timeoutMs = 5_000) {
  const binding = env.BACKUP_STATUS;
  if (!binding || typeof binding.summary !== 'function') return { available: false, reason: 'unbound' };
  let timer;
  try {
    const value = await Promise.race([binding.summary(), new Promise((_, reject) => { timer = setTimeout(() => reject(new CodedError('backup_status_timeout')), timeoutMs); })]);
    const text = JSON.stringify(value ?? null);
    if (text.length > 64 * 1024) return { available: false, reason: 'too_large' };
    return { available: true, summary: JSON.parse(text) };
  } catch (e) {
    log('warning', 'backup_status_unavailable', { error: errorCode(e) });
    return { available: false, reason: 'unavailable' };
  } finally { clearTimeout(timer); }
}

// ---------- pages ----------
export async function overviewData(env, { now = Date.now } = {}) {
  const t = now(), since24 = new Date(t - DAY).toISOString();
  const head = await ledgerHead(env);
  const chain = head.seq > 0 ? await verifyLedger(env, Math.max(1, head.seq - VERIFY_WINDOW + 1), head.seq) : { ok: true, checked: 0, first_break: null, from: 0, to: 0, head_seq: 0 };
  const [allFindings, names, backup] = await Promise.all([
    findings(env).catch(e => { log('warning', 'dashboard_findings_unavailable', { error: errorCode(e) }); return null; }), repoNames(env), backupSummary(env)]);
  let runs24 = null;
  if (env.METRICS_DB) {
    const [runs, jobs] = await Promise.all([runsSince(env.METRICS_DB, since24), jobsSince(env.METRICS_DB, since24)]);
    runs24 = { ...summarize(runs.rows, jobs.rows), truncated: runs.truncated || jobs.truncated };
  }
  const weekAgo = new Date(t - 7 * DAY).toISOString(), byKind = {};
  for (const f of allFindings ?? []) byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
  return {
    generated_at: new Date(t).toISOString(),
    ledger: { head, chain },
    findings: allFindings === null ? null : { total: allFindings.length, last_7d: allFindings.filter(f => f.detected_at >= weekAgo).length, by_kind: byKind, latest: allFindings.slice(0, 10) },
    runs_24h: runs24, provenance: PROVENANCE,
    backup,
    repos: [...names].map(([repo_id, full_name]) => ({ repo_id, full_name })).slice(0, MAX_REPOS),
  };
}

export async function eventsData(env, { limit = 50, cursor = null } = {}) {
  const [page, names] = await Promise.all([recentEvents(env, limit, cursor), repoNames(env)]);
  return { items: page.items.map(e => ({ ...e, repo: e.repo_id === null ? null : names.get(e.repo_id) ?? null })), next_cursor: page.next_cursor, limit };
}

export async function commitsData(env, repoId, { limit = 50, cursor = null } = {}) {
  const [page, repoFindings] = await Promise.all([commitLedger(env, repoId, limit, cursor), findings(env, repoId)]);
  return { repo_id: repoId, head: page.head, items: page.items, next_cursor: page.next_cursor, findings: repoFindings, limit };
}

/** verifyCommitLedger over the last VERIFY_WINDOW entries. */
export async function verifyData(env, repoId) {
  const head = await commitLedgerFor(env, repoId).head();
  const result = head.seq > 0 ? await verifyCommitLedger(env, repoId, Math.max(1, head.seq - VERIFY_WINDOW + 1), head.seq) : { ok: true, checked: 0, first_break: null, from: 0, to: 0, head_seq: 0 };
  return { repo_id: repoId, full_name: head.full_name ?? null, head: { seq: head.seq, entry_hash: head.entry_hash }, result };
}

const SHADOW = /^refs\/heads\/shadow\/pr-([1-9]\d{0,9})$/;
const PROMOTE_TAG = /^refs\/tags\/(promote\/pr-([1-9]\d{0,9})-[0-9a-f]{12})$/;

/**
 * Promotions derived from one repository's commit ledger entries (newest first): every non-deleting update of main,
 * with the promote/* tag whose 12-hex suffix matches the new tip, and the time from the candidate's shadow/pr-<n> push
 * to main when both are in the window. The PR head itself is not linked to the candidate in the ledger, so a
 * "PR head to main" time is not derivable and is not reported.
 */
export function derivePromotions(entries, repoFindings = []) {
  const tags = new Map(), shadows = new Map(), out = [];
  const missing = new Set(repoFindings.filter(f => f.kind === 'main_commit_missing_promotion_tag').map(f => f.sha));
  for (const e of entries) {
    if (e.kind !== 'ref_update' || e.data?.deleted) continue;
    const tag = PROMOTE_TAG.exec(e.data.ref ?? ''), shadow = SHADOW.exec(e.data.ref ?? '');
    if (tag) { const prefix = promotionTagPrefix(tag[1]); if (prefix && !tags.has(prefix)) tags.set(prefix, { tag: tag[1], pr: Number(tag[2]), recorded_at: e.recorded_at }); }
    if (shadow && typeof e.data.after === 'string') {
      const prev = shadows.get(e.data.after);
      if (!prev || e.recorded_at < prev.recorded_at) shadows.set(e.data.after, { pr: Number(shadow[1]), recorded_at: e.recorded_at });
    }
  }
  for (const e of entries) {
    if (e.kind !== 'ref_update' || e.data?.ref !== MAIN || e.data.deleted || typeof e.data.after !== 'string' || ZERO.test(e.data.after)) continue;
    const sha = e.data.after, tag = tags.get(sha.slice(0, 12)) ?? null, shadow = shadows.get(sha) ?? null;
    const row = { sha, seq: e.seq, reached_main_at: e.recorded_at, forced: e.data.forced === true, tag: tag?.tag ?? null, pr: tag?.pr ?? shadow?.pr ?? null,
      tag_recorded_at: tag?.recorded_at ?? null, missing_tag_finding: missing.has(sha) };
    const lag = shadow ? span(shadow.recorded_at, e.recorded_at) : null;
    if (lag !== null) row.shadow_to_main_s = Math.round(lag / 1000);
    out.push(row);
  }
  return out;
}

export async function promotionsData(env, { repoId = null, pages = 2 } = {}) {
  const names = await repoNames(env);
  const ids = repoId !== null ? [repoId] : [...names.keys()].slice(0, MAX_REPOS);
  const items = [];
  for (let i = 0; i < ids.length; i += 10) {
    const batch = await Promise.all(ids.slice(i, i + 10).map(async id => {
      const stub = commitLedgerFor(env, id), entries = [];
      let cursor = null;
      for (let p = 0; p < pages; p++) {
        const page = await stub.entries(100, cursor);
        entries.push(...page.items);
        if (!page.next_cursor) break;
        cursor = page.next_cursor;
      }
      const repoFindings = (await stub.findings(100)).items;
      return derivePromotions(entries, repoFindings).map(r => ({ repo_id: id, repo: names.get(id) ?? null, ...r }));
    }));
    items.push(...batch.flat());
  }
  items.sort((a, b) => (b.reached_main_at ?? '').localeCompare(a.reached_main_at ?? ''));
  return { items: items.slice(0, 200), window_entries_per_repo: pages * 100 };
}

function groupBy(rows, keyOf) {
  const m = new Map();
  for (const r of rows) { const k = keyOf(r); if (!m.has(k)) m.set(k, []); m.get(k).push(r); }
  return m;
}

export async function actionsData(env, { days = 7, now = Date.now } = {}) {
  if (days !== 7 && days !== 30) throw new CodedError('bad_days');
  if (!env.METRICS_DB) throw new CodedError('metrics_db_unbound');
  const t = now(), since = new Date(t - days * DAY).toISOString();
  const [runs, jobs, names] = await Promise.all([runsSince(env.METRICS_DB, since), jobsSince(env.METRICS_DB, since), repoNames(env)]);
  const name = id => names.get(id) ?? null;
  const SEP = '\u0000';
  const runGroups = { repo: groupBy(runs.rows, r => String(r.repo_id)), workflow: groupBy(runs.rows, r => r.repo_id + SEP + (r.workflow_name ?? '')) };
  const jobGroups = { repo: groupBy(jobs.rows, j => String(j.repo_id)), workflow: groupBy(jobs.rows, j => j.repo_id + SEP + (j.workflow_name ?? '')),
    job: groupBy(jobs.rows, j => j.repo_id + SEP + (j.workflow_name ?? '') + SEP + j.name) };
  const rows = (level, keys) => [...keys].map(k => {
    const [repo, workflow, job] = k.split(SEP), repoIdN = Number(repo);
    const s = summarize(level === 'job' ? [] : runGroups[level].get(k) ?? [], jobGroups[level].get(k) ?? []);
    return { repo_id: repoIdN, repo: name(repoIdN), ...(level !== 'repo' ? { workflow: workflow || null } : {}), ...(level === 'job' ? { job } : {}), ...s };
  }).sort((a, b) => (b.runs.value - a.runs.value) || (b.jobs.value - a.jobs.value)).slice(0, 200);
  const keys = level => new Set([...(runGroups[level]?.keys() ?? []), ...jobGroups[level].keys()]);
  return {
    days, since, generated_at: new Date(t).toISOString(), truncated: runs.truncated || jobs.truncated, provenance: PROVENANCE,
    total: summarize(runs.rows, jobs.rows),
    by_repository: rows('repo', keys('repo')), by_workflow: rows('workflow', keys('workflow')), by_job: rows('job', keys('job')),
  };
}
