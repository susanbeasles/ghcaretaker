// Workflow metrics collector (infra-root ADR-0001 section 3). Called by the event ledger outbox through
// metricsSinkFor(env).record(observation) for every workflow_run / workflow_job delivery of an owned repository.
//
// - Reads the captured payload from R2 (digest-checked) and upserts D1 `ghcaretaker-observatory` (binding METRICS_DB).
//   Upserts converge whatever the delivery order: a higher status rank (completed > in_progress > anything else)
//   always wins, an equal rank wins only when it is not older, and a terminal (completed) row never moves back.
// - On a completed run: GET /repos/{r}/actions/runs/{id}/timing for billable milliseconds (null on 404/410).
// - On a completed job: the job log (one redirect, allowlisted hosts only, Authorization never forwarded, at most
//   LOG_TAIL_BYTES read from the end) and the last `##[runner-telemetry]` line, validated strictly.
// - Idempotent per delivery_id (deliveries_seen, written in the same D1 batch as the enrichment). Throws to be
//   retried on transient failures; permanent "nothing to learn" outcomes store null and acknowledge.
// Never logs or stores tokens, log text or payload bodies: the log tail lives only in memory while it is parsed and
// only the validated telemetry object (numbers plus os/arch/cpu count) is written.
import { BodyTooLarge, CodedError, RedirectRefused, fetchNoRedirect, isPlainObject, readBounded } from './bytes.mjs';
import { readDelivery } from './observatory-read.mjs';
import { GitHubError, SHA, githubRequest, mintActionsToken, repoPath } from './github-app.mjs';
import { telemetryFromLog } from './telemetry.mjs';
import { log } from './log.mjs';

const API = 'https://api.github.com';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const WORD = /^[a-z_]{1,32}$/;
export const LOG_TAIL_BYTES = 2 * 1024 * 1024;
export const LOG_STREAM_CAP = 64 * 1024 * 1024; // when the storage host ignores Range: give up past this
export const LOG_NOT_READY_GRACE_MS = 10 * 60_000; // logs can lag job completion; 404 inside this window is retried
const MAX_STEPS = 500, MAX_LABELS = 32;

// Hosts GitHub redirects job-log downloads to (signed, short-lived URLs). Suffix match on a dot boundary, https,
// default port, no credentials. VERIFY against https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run
// and the hosted-runner network allowlist (https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
export const LOG_REDIRECT_HOST_SUFFIXES = Object.freeze(['.blob.core.windows.net', '.actions.githubusercontent.com']);

export function allowedLogRedirect(location, base = API) {
  let url;
  try { url = new URL(location, base); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null;
  const host = url.hostname.toLowerCase();
  const ok = LOG_REDIRECT_HOST_SUFFIXES.some(s => host.endsWith(s) && host.length > s.length && /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/.test(host.slice(0, -s.length)));
  return ok ? url : null;
}

// ---------- payload extraction (payload is GitHub-signed but still bounded and typed field by field) ----------
const text = (v, max) => (typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null);
const id = v => (Number.isSafeInteger(v) && v > 0 ? v : null);
const iso = v => { if (typeof v !== 'string' || v.length > 40) return null; const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const word = v => (typeof v === 'string' && WORD.test(v) ? v : null);

export function runOf(payload, repoId) {
  const r = payload?.workflow_run;
  if (!isPlainObject(r)) return null;
  const run = {
    repo_id: repoId, run_id: id(r.id), attempt: id(r.run_attempt ?? 1), workflow_id: id(r.workflow_id),
    workflow_name: text(r.name, 200), path: text(r.path, 300), event: word(r.event), head_branch: text(r.head_branch, 255),
    head_sha: typeof r.head_sha === 'string' && SHA.test(r.head_sha) ? r.head_sha : null,
    actor_id: id(r.actor?.id ?? r.triggering_actor?.id), status: word(r.status), conclusion: word(r.conclusion),
    created_at: iso(r.created_at), run_started_at: iso(r.run_started_at), updated_at: iso(r.updated_at),
  };
  return run.run_id && run.attempt && run.status && run.created_at && run.updated_at ? run : null;
}

export function jobOf(payload, repoId) {
  const j = payload?.workflow_job;
  if (!isPlainObject(j)) return null;
  const labels = Array.isArray(j.labels) ? j.labels.filter(l => typeof l === 'string').slice(0, MAX_LABELS).map(l => l.slice(0, 100)) : [];
  const steps = (Array.isArray(j.steps) ? j.steps : []).slice(0, MAX_STEPS).map(s => isPlainObject(s) ? {
    number: Number.isSafeInteger(s.number) && s.number >= 0 ? s.number : null, name: text(s.name, 300), status: word(s.status),
    conclusion: word(s.conclusion), started_at: iso(s.started_at), completed_at: iso(s.completed_at),
  } : null).filter(s => s && s.number !== null && s.name && s.status);
  const job = {
    job_id: id(j.id), run_id: id(j.run_id), attempt: id(j.run_attempt ?? 1), repo_id: repoId, name: text(j.name, 300),
    workflow_name: text(j.workflow_name, 200), status: word(j.status), runner_name: text(j.runner_name, 200),
    labels: JSON.stringify(labels), runner_group: text(j.runner_group_name, 200), queued_at: iso(j.created_at),
    started_at: iso(j.started_at), completed_at: iso(j.completed_at), conclusion: word(j.conclusion), steps,
  };
  return job.job_id && job.run_id && job.attempt && job.name && job.status && job.queued_at ? job : null;
}

// ---------- SQL (D1 is SQLite; ON CONFLICT ... DO UPDATE ... WHERE is an upsert guard) ----------
const rank = col => `(CASE ${col} WHEN 'completed' THEN 3 WHEN 'in_progress' THEN 2 ELSE 1 END)`;
const newer = (table, stamp) => `${rank('excluded.status')} > ${rank(table + '.status')} OR (${rank('excluded.status')} = ${rank(table + '.status')} AND ${stamp('excluded')} >= ${stamp(table)})`;
const keep = (table, cols) => cols.map(c => `${c} = COALESCE(excluded.${c}, ${table}.${c})`).join(', ');

const RUN_COLS = ['repo_id', 'run_id', 'attempt', 'workflow_id', 'workflow_name', 'path', 'event', 'head_branch', 'head_sha', 'actor_id', 'status', 'conclusion', 'created_at', 'run_started_at', 'updated_at'];
export const UPSERT_RUN = `INSERT INTO runs (${RUN_COLS.join(', ')}) VALUES (${RUN_COLS.map(() => '?').join(', ')})
  ON CONFLICT (repo_id, run_id, attempt) DO UPDATE SET status = excluded.status, conclusion = excluded.conclusion, updated_at = excluded.updated_at,
  ${keep('runs', ['workflow_id', 'workflow_name', 'path', 'event', 'head_branch', 'head_sha', 'actor_id', 'run_started_at'])}
  WHERE ${newer('runs', t => t + '.updated_at')}`;

const JOB_COLS = ['job_id', 'run_id', 'attempt', 'repo_id', 'name', 'workflow_name', 'status', 'runner_name', 'labels', 'runner_group', 'queued_at', 'started_at', 'completed_at', 'conclusion'];
const jobStamp = t => `COALESCE(${t}.completed_at, ${t}.started_at, ${t}.queued_at)`;
export const UPSERT_JOB = `INSERT INTO jobs (${JOB_COLS.join(', ')}) VALUES (${JOB_COLS.map(() => '?').join(', ')})
  ON CONFLICT (job_id) DO UPDATE SET status = excluded.status, conclusion = excluded.conclusion, labels = excluded.labels,
  ${keep('jobs', ['name', 'workflow_name', 'runner_name', 'runner_group', 'started_at', 'completed_at'])}
  WHERE ${newer('jobs', jobStamp)}`;

const STEP_COLS = ['job_id', 'number', 'name', 'status', 'conclusion', 'started_at', 'completed_at'];
const stepStamp = t => `COALESCE(${t}.completed_at, ${t}.started_at, '')`;
export const UPSERT_STEP = `INSERT INTO steps (${STEP_COLS.join(', ')}) VALUES (${STEP_COLS.map(() => '?').join(', ')})
  ON CONFLICT (job_id, number) DO UPDATE SET name = excluded.name, status = excluded.status, conclusion = excluded.conclusion,
  ${keep('steps', ['started_at', 'completed_at'])}
  WHERE ${newer('steps', stepStamp)}`;

const SEEN = 'INSERT INTO deliveries_seen (delivery_id, seen_at) VALUES (?, ?) ON CONFLICT (delivery_id) DO NOTHING';

// ---------- the collector ----------
const tokenCache = new Map(); // `${installation}:${repo}` -> {token, expires_at}; memory only, bounded

function validObservation(o) {
  return isPlainObject(o) && UUID.test(o.delivery_id ?? '') && (o.event === 'workflow_run' || o.event === 'workflow_job')
    && Number.isSafeInteger(o.repo_id) && o.repo_id > 0 && typeof o.object_key === 'string' && /^[0-9a-f]{64}$/.test(o.body_sha256 ?? '');
}

export function metricsCollector(env, deps = {}) {
  const fetcher = deps.fetcher ?? fetch, now = deps.now ?? Date.now, mint = deps.mintToken ?? mintActionsToken;

  async function token(installationId, repoId) {
    const key = installationId + ':' + repoId, cached = tokenCache.get(key);
    if (cached && cached.expires_at - now() > 300_000) return cached.token;
    const fresh = await mint(env, installationId, repoId, fetcher);
    if (tokenCache.size >= 64) tokenCache.delete(tokenCache.keys().next().value);
    tokenCache.set(key, fresh);
    return fresh.token;
  }

  // null when the App cannot be used for this repository yet (not configured): nothing to learn, do not retry forever.
  async function tokenOrNull(payload, repoId, ctx) {
    const installation = id(payload.installation?.id);
    if (!installation) { log('warning', 'metrics_no_installation', ctx); return null; }
    try { return await token(installation, repoId); }
    catch (e) { if (e.code === 'app_unconfigured') { log('warning', 'metrics_app_unconfigured', ctx); return null; } throw e; }
  }

  // VERIFY: GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing is still served
  // (https://docs.github.com/en/rest/actions/workflow-runs#get-workflow-run-usage). 404/410 store null.
  async function billable(fullName, tok, run) {
    let data;
    try { ({ data } = await githubRequest('/repos/' + repoPath(fullName) + '/actions/runs/' + run.run_id + '/timing', { token: tok, fetcher, limit: 256 * 1024 })); }
    catch (e) { if (e.status === 404 || e.status === 410) return null; throw e; }
    if (!isPlainObject(data?.billable)) return null;
    const entries = Object.entries(data.billable);
    if (entries.length > 8) return null;
    // Stored in the API's own structure and units (milliseconds); only fields that validate are kept.
    const out = {}; let total = 0;
    for (const [os, v] of entries) {
      if (!/^[A-Z_0-9]{1,24}$/.test(os) || !isPlainObject(v) || !Number.isSafeInteger(v.total_ms) || v.total_ms < 0) return null;
      out[os] = { total_ms: v.total_ms };
      if (Number.isSafeInteger(v.jobs) && v.jobs >= 0) out[os].jobs = v.jobs;
      const runsOk = Array.isArray(v.job_runs) && v.job_runs.length <= 1000 && v.job_runs.every(j => isPlainObject(j) && id(j.job_id) && Number.isSafeInteger(j.duration_ms) && j.duration_ms >= 0);
      if (runsOk) out[os].job_runs = v.job_runs.map(j => ({ job_id: j.job_id, duration_ms: j.duration_ms }));
      total += v.total_ms;
    }
    if (!Number.isSafeInteger(total)) return null;
    const runDuration = Number.isSafeInteger(data.run_duration_ms) && data.run_duration_ms >= 0 ? data.run_duration_ms : null;
    return { ms: total, json: JSON.stringify(runDuration === null ? { billable: out } : { billable: out, run_duration_ms: runDuration }) };
  }

  // Reads the end of a body: a 206 to a suffix Range is at most LOG_TAIL_BYTES; a 200 is streamed through a sliding
  // window of LOG_TAIL_BYTES and abandoned past LOG_STREAM_CAP. Returns {bytes, truncated} or null when too large.
  async function tail(response) {
    if (response.status === 206) {
      // Content-Range "bytes <first>-<last>/<size>": the tail starts mid-log unless it starts at byte 0.
      const range = /^bytes (\d+)-\d+\/(?:\d+|\*)$/.exec(response.headers.get('content-range') ?? '');
      return { bytes: await readBounded(response.body, LOG_TAIL_BYTES), truncated: !range || range[1] !== '0' };
    }
    const reader = response.body?.getReader();
    if (!reader) return { bytes: new Uint8Array(0), truncated: false };
    const window = new Uint8Array(LOG_TAIL_BYTES * 2);
    let used = 0, seen = 0, truncated = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      seen += value.byteLength;
      if (seen > LOG_STREAM_CAP) { await reader.cancel().catch(() => {}); return null; }
      let chunk = value;
      if (chunk.byteLength > LOG_TAIL_BYTES) { chunk = chunk.subarray(chunk.byteLength - LOG_TAIL_BYTES); truncated = true; used = 0; }
      if (used + chunk.byteLength > window.length) {
        const keepFrom = used + chunk.byteLength - LOG_TAIL_BYTES;
        window.copyWithin(0, keepFrom, used); used -= keepFrom; truncated = true;
      }
      window.set(chunk, used); used += chunk.byteLength;
    }
    const start = Math.max(0, used - LOG_TAIL_BYTES);
    return { bytes: window.slice(start, used), truncated: truncated || start > 0 };
  }

  async function fetchTail(url) {
    // Exactly one redirect overall: the storage host's own 3xx is refused (fetchNoRedirect), never followed.
    const get = range => fetchNoRedirect(fetcher, url.href, { method: 'GET', signal: AbortSignal.timeout(30_000),
      headers: { 'User-Agent': 'ghcaretaker-observatory', ...(range ? { Range: 'bytes=-' + LOG_TAIL_BYTES } : {}) } });
    let response;
    const attempt = async range => { try { return await get(range); } catch (e) { if (e instanceof RedirectRefused) return null; throw new CodedError('job_log_storage_network'); } };
    response = await attempt(true);
    if (response?.status === 416) { await response.body?.cancel().catch(() => {}); response = await attempt(false); }
    if (response === null) return { redirected: true };
    if (response.status !== 200 && response.status !== 206) { await response.body?.cancel().catch(() => {}); throw new CodedError('job_log_storage_http_' + response.status, response.status); }
    try { return await tail(response); } catch (e) { if (e instanceof BodyTooLarge) return null; throw new CodedError('job_log_storage_read'); }
  }

  // Returns {telemetry, reason}. Throws only for transient failures worth retrying.
  async function jobTelemetry(fullName, tok, job, ctx) {
    let response;
    try {
      response = await fetcher(API + '/repos/' + repoPath(fullName) + '/actions/jobs/' + job.job_id + '/logs', {
        method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(15_000),
        headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'ghcaretaker-observatory' },
      });
    } catch { throw new GitHubError('github_network'); }
    const status = response.status;
    await response.body?.cancel().catch(() => {});
    if (status === 404 || status === 410) {
      const completed = Date.parse(job.completed_at ?? '');
      if (status === 404 && Number.isFinite(completed) && now() - completed < LOG_NOT_READY_GRACE_MS) throw new GitHubError('job_log_not_ready', 404);
      return { telemetry: null, reason: 'log_unavailable_' + status };
    }
    if (![301, 302, 303, 307, 308].includes(status)) throw new GitHubError('github_http_' + status, status);
    const target = allowedLogRedirect(response.headers.get('location') ?? '');
    if (!target) {
      // Permanent until the allowlist is reviewed: no telemetry rather than an endless retry. Host only, never the URL.
      let host = 'invalid';
      try { host = new URL(response.headers.get('location') ?? '', API).hostname.slice(0, 100); } catch {}
      log('error', 'job_log_redirect_refused', { ...ctx, host });
      return { telemetry: null, reason: 'redirect_refused' };
    }
    const body = await fetchTail(target);
    if (body?.redirected) { log('error', 'job_log_second_redirect_refused', ctx); return { telemetry: null, reason: 'redirect_refused' }; }
    if (!body) { log('warning', 'job_log_too_large', ctx); return { telemetry: null, reason: 'log_too_large' }; }
    let bytes = body.bytes;
    // A tail can start mid-line (or mid-character): drop everything up to the first newline.
    if (body.truncated) { const nl = bytes.indexOf(0x0a); bytes = nl < 0 ? new Uint8Array(0) : bytes.subarray(nl + 1); }
    return telemetryFromLog(bytes);
  }

  async function seenAlready(db, deliveryId) {
    return (await db.prepare('SELECT 1 AS seen FROM deliveries_seen WHERE delivery_id = ?').bind(deliveryId).first()) !== null;
  }

  return {
    async record(observation) {
      if (!validObservation(observation)) throw new CodedError('bad_observation');
      const db = env.METRICS_DB;
      if (!db) throw new CodedError('metrics_db_unbound');
      const { delivery_id: deliveryId, event, repo_id: repoId } = observation;
      if (await seenAlready(db, deliveryId)) return;
      const ctx = { delivery_id: deliveryId, github_event: event, repo_id: repoId };
      const markSeen = () => db.prepare(SEEN).bind(deliveryId, new Date(now()).toISOString());
      const { payload } = await (deps.readDelivery ?? readDelivery)(env, observation.object_key, observation.body_sha256);
      const repo = payload?.repository;
      if (!isPlainObject(repo) || repo.id !== repoId || String(repo.owner?.id) !== String(env.GITHUB_OWNER_ID) || !/^\d+$/.test(String(env.GITHUB_OWNER_ID ?? ''))) {
        log('warning', 'metrics_not_owned', ctx);
        await markSeen().run();
        return;
      }
      const fullName = typeof repo.full_name === 'string' ? repo.full_name : null;

      if (event === 'workflow_run') {
        const run = runOf(payload, repoId);
        if (!run) { log('error', 'metrics_payload_unusable', ctx); await markSeen().run(); return; }
        await db.batch([db.prepare(UPSERT_RUN).bind(...RUN_COLS.map(c => run[c]))]);
        const tail = [];
        if (run.status === 'completed' && fullName) {
          const tok = await tokenOrNull(payload, repoId, ctx);
          const b = tok ? await billable(fullName, tok, run) : null;
          if (b) tail.push(db.prepare("UPDATE runs SET billable_ms = ?, billable_json = ?, billable_kind = 'reported' WHERE repo_id = ? AND run_id = ? AND attempt = ?").bind(b.ms, b.json, repoId, run.run_id, run.attempt));
        }
        await db.batch([...tail, markSeen()]);
        return;
      }

      const job = jobOf(payload, repoId);
      if (!job) { log('error', 'metrics_payload_unusable', ctx); await markSeen().run(); return; }
      await db.batch([db.prepare(UPSERT_JOB).bind(...JOB_COLS.map(c => job[c])), ...job.steps.map(s => db.prepare(UPSERT_STEP).bind(job.job_id, s.number, s.name, s.status, s.conclusion, s.started_at, s.completed_at))]);
      const tail = [];
      if (job.status === 'completed' && fullName) {
        const tok = await tokenOrNull(payload, repoId, ctx);
        if (tok) {
          const { telemetry, reason } = await jobTelemetry(fullName, tok, job, { ...ctx, job_id: job.job_id });
          if (telemetry) tail.push(db.prepare("UPDATE jobs SET telemetry = ?, telemetry_kind = 'reported' WHERE job_id = ? AND telemetry IS NULL").bind(JSON.stringify(telemetry), job.job_id));
          // No line is the normal case for a job that does not use the action: complete, not an error.
          else if (reason === 'invalid_line') log('warning', 'runner_telemetry_rejected', { ...ctx, job_id: job.job_id });
        }
      }
      await db.batch([...tail, markSeen()]);
    },
  };
}

export const _resetTokenCache = () => tokenCache.clear();
