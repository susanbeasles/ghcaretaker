// Workflow metrics collector: D1 upserts, convergence, idempotency, run timing, job-log telemetry and the
// redirect rules for log downloads. D1 is node:sqlite with the real migration; GitHub is a fake fetcher.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { metricsCollector, allowedLogRedirect, _resetTokenCache, LOG_TAIL_BYTES, LOG_NOT_READY_GRACE_MS } from '../src/metrics.mjs';
import { metricsSinkFor } from '../src/metrics-sink.mjs';
import { mintActionsToken } from '../src/github-app.mjs';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { handleWebhook } from '../src/webhook.mjs';
import { d1Database, memoryR2, secret, randomSecret, sign, sqlStorage, clock, pkcs8Pem, sha } from './fakes.mjs';

const OWNER = 215839550;
const MIGRATION = ['0001_metrics.sql', '0002_reported_telemetry.sql'].map(name => readFileSync(new URL('../migrations-observatory/' + name, import.meta.url), 'utf8')).join('\n');
const REPO = { id: 42, full_name: 'susanbeasles/demo', owner: { id: OWNER } };
const BLOB = 'https://productionresultssa1.blob.core.windows.net/actions-results/abc/logs/job.txt?sig=signed';

export const telemetry = (over = {}) => ({
  schema: 'runner-telemetry/v1', os: 'linux', arch: 'x64', cpu_count: 4, memory_total_bytes: 16_000_000_000, samples: 25, duration_s: 120.5, interval_s: 5,
  cpu_mean: 0.42, cpu_p95: 0.91, cpu_max: 0.97, memory_used_max_bytes: 6_000_000_000, memory_used_mean_bytes: 4_000_000_000,
  disk_read_bytes: 1_000_000, disk_write_bytes: 2_000_000, net_rx_bytes: 300_000_000, net_tx_bytes: 4_000_000, load1_max: 3.5, disk_free_min_bytes: 20_000_000_000, ...over,
});

beforeEach(() => _resetTokenCache());

function setup({ fetcher, now = clock(), mintToken } = {}) {
  const METRICS_DB = d1Database(MIGRATION), EVENTS = memoryR2();
  const env = { GITHUB_OWNER_ID: String(OWNER), METRICS_DB, EVENTS };
  const calls = [];
  const wrapped = async (url, init = {}) => { calls.push({ url: String(url), init }); return fetcher ? fetcher(String(url), init) : new Response(null, { status: 404 }); };
  const minted = [];
  const collector = metricsCollector(env, { fetcher: wrapped, now, mintToken: mintToken ?? (async (_e, installation, repo) => { minted.push([installation, repo]); return { token: 'test-token-' + randomSecret(), expires_at: now() + 3_600_000 }; }) });
  return { env, METRICS_DB, EVENTS, collector, calls, minted, now };
}

async function observe(EVENTS, event, payload, receivedAt = '2026-10-15T12:00:00.000Z') {
  const delivery_id = crypto.randomUUID(), body = JSON.stringify(payload);
  const { createHash } = await import('node:crypto');
  const body_sha256 = createHash('sha256').update(body).digest('hex');
  const object_key = `deliveries/2026/10/15/${delivery_id}.json`;
  await EVENTS.put(object_key, JSON.stringify({ v: 1, delivery_id, event, hook_id: null, installation_target_id: null, received_at: receivedAt, body_sha256, body }));
  return { delivery_id, event, action: payload.action ?? null, repo_id: payload.repository?.id ?? null, received_at: receivedAt, object_key, body_sha256 };
}

const runPayload = (over = {}, action = 'completed') => ({ action, installation: { id: 7 }, repository: REPO, workflow_run: {
  id: 9001, run_attempt: 1, workflow_id: 55, name: 'pipeline', path: '.github/workflows/pipeline.yml', event: 'push', head_branch: 'main', head_sha: sha(1),
  actor: { id: OWNER }, status: 'completed', conclusion: 'success', created_at: '2026-10-15T11:50:00Z', run_started_at: '2026-10-15T11:50:05Z', updated_at: '2026-10-15T11:58:00Z', ...over } });

const jobPayload = (over = {}, action = 'completed') => ({ action, installation: { id: 7 }, repository: REPO, workflow_job: {
  id: 777, run_id: 9001, run_attempt: 1, name: 'build', workflow_name: 'pipeline', status: 'completed', conclusion: 'success', runner_name: 'GitHub Actions 12',
  labels: ['ubuntu-24.04'], runner_group_name: 'GitHub Actions', created_at: '2026-10-15T11:50:06Z', started_at: '2026-10-15T11:50:20Z', completed_at: '2026-10-15T11:57:50Z',
  steps: [{ number: 1, name: 'Set up job', status: 'completed', conclusion: 'success', started_at: '2026-10-15T11:50:20Z', completed_at: '2026-10-15T11:50:22Z' },
    { number: 2, name: 'Run actions/runner-telemetry', status: 'completed', conclusion: 'success', started_at: '2026-10-15T11:50:22Z', completed_at: '2026-10-15T11:50:23Z' }], ...over } });

const row = (db, sql, ...args) => db.db.prepare(sql).get(...args);
const logText = lines => lines.map(l => '2026-10-15T11:57:49.1234567Z ' + l).join('\n') + '\n';

function githubFake({ timing = { status: 200, body: { billable: { UBUNTU: { total_ms: 480000, jobs: 2, job_runs: [] }, MACOS: { total_ms: 60000, jobs: 1 } }, run_duration_ms: 475000 } },
  logs = { status: 302, location: BLOB }, blob = { status: 206, text: logText(['##[group]Run x', '##[runner-telemetry]' + JSON.stringify(telemetry())]) } } = {}) {
  return async (url, init) => {
    if (url.endsWith('/actions/runs/9001/timing')) return timing.status === 200 ? Response.json(timing.body) : new Response(null, { status: timing.status });
    if (url.endsWith('/actions/jobs/777/logs')) return new Response(null, { status: logs.status, headers: logs.location ? { location: logs.location } : {} });
    if (url.startsWith('https://productionresultssa1.blob.core.windows.net/')) {
      if (typeof blob === 'function') return blob(url, init);
      const bytes = new TextEncoder().encode(blob.text);
      return new Response(bytes, { status: blob.status, headers: blob.status === 206 ? { 'content-range': `bytes 0-${bytes.length - 1}/${bytes.length}` } : {} });
    }
    return new Response(null, { status: 599 });
  };
}

test('completed run: upserted, billable ms from /timing summed across runner OSes, delivery marked seen', async () => {
  const { METRICS_DB, EVENTS, collector, calls, minted } = setup({ fetcher: githubFake() });
  const o = await observe(EVENTS, 'workflow_run', runPayload());
  await collector.record(o);
  const r = row(METRICS_DB, 'SELECT * FROM runs');
  assert.equal(r.repo_id, 42); assert.equal(r.run_id, 9001); assert.equal(r.attempt, 1); assert.equal(r.workflow_name, 'pipeline');
  assert.equal(r.status, 'completed'); assert.equal(r.conclusion, 'success'); assert.equal(r.created_at, '2026-10-15T11:50:00.000Z');
  assert.equal(r.billable_ms, 540000); assert.equal(r.billable_kind, 'reported');
  assert.deepEqual(JSON.parse(r.billable_json), { billable: { UBUNTU: { total_ms: 480000, jobs: 2, job_runs: [] }, MACOS: { total_ms: 60000, jobs: 1 } }, run_duration_ms: 475000 }, 'API structure and units kept');
  assert.deepEqual(minted, [[7, 42]], 'one actions:read token for the installation and repository');
  assert.equal(calls.length, 1); assert.equal(calls[0].url, 'https://api.github.com/repos/susanbeasles/demo/actions/runs/9001/timing');
  assert.equal(calls[0].init.redirect, 'manual');
  assert.ok(row(METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id));
});

test('duplicate delivery is idempotent: no second API call, no second write', async () => {
  const { METRICS_DB, EVENTS, collector, calls } = setup({ fetcher: githubFake() });
  const o = await observe(EVENTS, 'workflow_run', runPayload());
  await collector.record(o);
  const batches = METRICS_DB.batches, apiCalls = calls.length;
  await collector.record(o);
  await collector.record({ ...o });
  assert.equal(METRICS_DB.batches, batches); assert.equal(calls.length, apiCalls);
  assert.equal(row(METRICS_DB, 'SELECT COUNT(*) AS n FROM runs').n, 1);
});

test('out-of-order run events converge: completed never regresses, older equal-rank updates lose', async () => {
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake() });
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload()));
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload({ status: 'in_progress', conclusion: null, updated_at: '2026-10-15T11:59:59Z' }, 'in_progress')));
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload({ status: 'requested', conclusion: null, updated_at: '2026-10-15T11:50:00Z' }, 'requested')));
  let r = row(METRICS_DB, 'SELECT status, conclusion, updated_at, billable_ms FROM runs');
  assert.deepEqual({ ...r }, { status: 'completed', conclusion: 'success', updated_at: '2026-10-15T11:58:00.000Z', billable_ms: 540000 }, 'a later-arriving in_progress (even with a newer timestamp) never moves completed back');
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload({ conclusion: 'failure', updated_at: '2026-10-15T11:57:00Z' })));
  assert.equal(row(METRICS_DB, 'SELECT conclusion FROM runs').conclusion, 'success', 'an older completed event does not overwrite a newer one');
  // A different attempt is a different row.
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload({ run_attempt: 2, status: 'in_progress', conclusion: null, updated_at: '2026-10-15T12:10:00Z' }, 'in_progress')));
  assert.equal(row(METRICS_DB, 'SELECT COUNT(*) AS n FROM runs').n, 2);
  // In order: queued -> in_progress -> completed progresses.
  const s2 = setup({ fetcher: githubFake({ timing: { status: 404 } }) });
  await s2.collector.record(await observe(s2.EVENTS, 'workflow_run', runPayload({ status: 'requested', conclusion: null, run_started_at: null, updated_at: '2026-10-15T11:50:00Z' }, 'requested')));
  await s2.collector.record(await observe(s2.EVENTS, 'workflow_run', runPayload({ status: 'in_progress', conclusion: null, updated_at: '2026-10-15T11:51:00Z' }, 'in_progress')));
  r = row(s2.METRICS_DB, 'SELECT status, run_started_at FROM runs');
  assert.equal(r.status, 'in_progress'); assert.equal(r.run_started_at, '2026-10-15T11:50:05.000Z');
  await s2.collector.record(await observe(s2.EVENTS, 'workflow_run', runPayload()));
  assert.equal(row(s2.METRICS_DB, 'SELECT status FROM runs').status, 'completed');
});

test('timing 404/410 store null billable (never invented); 5xx throws and is retried; the base row lands first', async () => {
  for (const status of [404, 410]) {
    const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ timing: { status } }) });
    const o = await observe(EVENTS, 'workflow_run', runPayload());
    await collector.record(o);
    const r = row(METRICS_DB, 'SELECT billable_ms, billable_json, billable_kind FROM runs');
    assert.equal(r.billable_ms, null); assert.equal(r.billable_json, null); assert.equal(r.billable_kind, null);
    assert.ok(row(METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id));
  }
  let status = 502;
  const s = setup({ fetcher: async (url, init) => githubFake({ timing: status === 200 ? undefined : { status } })(url, init) });
  const o = await observe(s.EVENTS, 'workflow_run', runPayload());
  await assert.rejects(s.collector.record(o), /github_http_502/);
  assert.equal(row(s.METRICS_DB, 'SELECT status FROM runs').status, 'completed', 'the run itself is stored before enrichment');
  assert.equal(row(s.METRICS_DB, 'SELECT COUNT(*) AS n FROM deliveries_seen').n, 0, 'not marked seen, so the outbox retries');
  status = 200;
  await s.collector.record(o);
  assert.equal(row(s.METRICS_DB, 'SELECT billable_ms FROM runs').billable_ms, 540000);
  // A malformed timing body is not trusted.
  const bad = setup({ fetcher: githubFake({ timing: { status: 200, body: { billable: { UBUNTU: { total_ms: -5 } } } } }) });
  await bad.collector.record(await observe(bad.EVENTS, 'workflow_run', runPayload()));
  assert.equal(row(bad.METRICS_DB, 'SELECT billable_ms FROM runs').billable_ms, null);
});

test('repositories not owned by 215839550 are ignored (acknowledged, nothing stored, no API call)', async () => {
  const { METRICS_DB, EVENTS, collector, calls } = setup({ fetcher: githubFake() });
  const foreign = { ...runPayload(), repository: { id: 42, full_name: 'someone/demo', owner: { id: 1 } } };
  const o = await observe(EVENTS, 'workflow_run', foreign);
  await collector.record(o);
  assert.equal(row(METRICS_DB, 'SELECT COUNT(*) AS n FROM runs').n, 0); assert.equal(calls.length, 0);
  assert.ok(row(METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id));
  // The observation's repo id must match the payload.
  const mismatch = await observe(EVENTS, 'workflow_run', runPayload());
  await collector.record({ ...mismatch, repo_id: 43 });
  assert.equal(row(METRICS_DB, 'SELECT COUNT(*) AS n FROM runs').n, 0);
});

test('completed job: one redirect to an allowlisted host, Authorization not forwarded, tail range, telemetry stored', async () => {
  const { METRICS_DB, EVENTS, collector, calls } = setup({ fetcher: githubFake() });
  await collector.record(await observe(EVENTS, 'workflow_job', jobPayload()));
  const j = row(METRICS_DB, 'SELECT * FROM jobs');
  assert.equal(j.job_id, 777); assert.equal(j.run_id, 9001); assert.equal(j.name, 'build'); assert.equal(j.status, 'completed');
  assert.equal(j.queued_at, '2026-10-15T11:50:06.000Z'); assert.deepEqual(JSON.parse(j.labels), ['ubuntu-24.04']); assert.equal(j.runner_group, 'GitHub Actions');
  assert.deepEqual(JSON.parse(j.telemetry), telemetry()); assert.equal(j.telemetry_kind, 'reported');
  assert.equal(row(METRICS_DB, 'SELECT COUNT(*) AS n FROM steps WHERE job_id = 777').n, 2);
  const [api, blob] = calls;
  assert.equal(api.url, 'https://api.github.com/repos/susanbeasles/demo/actions/jobs/777/logs');
  assert.equal(api.init.redirect, 'manual'); assert.match(api.init.headers.Authorization, /^Bearer test-token-/);
  assert.equal(blob.url, BLOB); assert.equal(blob.init.redirect, 'manual', 'exactly one redirect: the storage request follows none');
  const headerNames = Object.keys(blob.init.headers).map(h => h.toLowerCase());
  assert.ok(!headerNames.includes('authorization'), 'the GitHub token never reaches the storage host');
  assert.equal(blob.init.headers.Range, 'bytes=-' + LOG_TAIL_BYTES);
  assert.equal(calls.length, 2);
});

test('log redirect to an unlisted host is refused: no request to it, no telemetry, no token leaked', async () => {
  for (const location of ['https://evil.example.com/logs.txt', 'https://blob.core.windows.net.evil.example/x', 'http://x.blob.core.windows.net/x',
    'https://user:pw@x.blob.core.windows.net/x', 'https://x.blob.core.windows.net:8443/x', 'https://blob.core.windows.net/x', '//evil.example/x', 'javascript:alert(1)']) {
    const { METRICS_DB, EVENTS, collector, calls } = setup({ fetcher: githubFake({ logs: { status: 302, location } }) });
    const o = await observe(EVENTS, 'workflow_job', jobPayload());
    await collector.record(o);
    assert.equal(calls.length, 1, 'only the API call was made for ' + location);
    assert.equal(row(METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
    assert.ok(row(METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id), 'acknowledged, not retried forever');
  }
  assert.ok(allowedLogRedirect('https://pipelines.actions.githubusercontent.com/x/y'));
  assert.ok(allowedLogRedirect('https://results-receiver.actions.githubusercontent.com/x'));
  assert.equal(allowedLogRedirect('https://actions.githubusercontent.com.evil.example/x'), null);
  assert.equal(allowedLogRedirect('https://evilactions.githubusercontent.com/x'), null);
});

test('telemetry: malformed, out-of-range, unknown-key or echoed lines are rejected; the last line decides', async () => {
  const cases = [
    ['##[runner-telemetry]{not json', null],
    ['##[runner-telemetry]' + JSON.stringify(telemetry({ cpu_mean: 1.5 })), null],
    ['##[runner-telemetry]' + JSON.stringify(telemetry({ extra: 1 })), null],
    ['##[runner-telemetry]' + JSON.stringify({ ...telemetry(), schema: 'runner-telemetry/v2' }), null],
    ['##[runner-telemetry]' + JSON.stringify(telemetry({ samples: -1 })), null],
    ['##[runner-telemetry]' + JSON.stringify(telemetry({ disk_read_bytes: 1.5 })), null],
    ['echo ##[runner-telemetry]' + JSON.stringify(telemetry()), null],
    ['##[runner-telemetry]' + JSON.stringify(telemetry({ cpu_mean: null, cpu_p95: null, cpu_max: null })), telemetry({ cpu_mean: null, cpu_p95: null, cpu_max: null })],
  ];
  for (const [line, expected] of cases) {
    const lines = ['##[runner-telemetry]' + JSON.stringify(telemetry({ cpu_mean: 0.01 })), 'other output', line];
    const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ blob: { status: 206, text: logText(lines) } }) });
    await collector.record(await observe(EVENTS, 'workflow_job', jobPayload()));
    const stored = row(METRICS_DB, 'SELECT telemetry FROM jobs').telemetry;
    assert.deepEqual(stored === null ? null : JSON.parse(stored), expected, line.slice(0, 60));
  }
  // No line: no telemetry.
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ blob: { status: 206, text: logText(['just a build']) } }) });
  await collector.record(await observe(EVENTS, 'workflow_job', jobPayload()));
  assert.equal(row(METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
});

test('job log 404 shortly after completion is retried; later it is final (null); 5xx retried', async () => {
  const done = Date.parse('2026-10-15T11:57:50Z');
  let status = 404;
  const now = clock(done + 60_000);
  const s = setup({ now, fetcher: async (url, init) => githubFake({ logs: status === 302 ? undefined : { status } })(url, init) });
  const o = await observe(s.EVENTS, 'workflow_job', jobPayload());
  await assert.rejects(s.collector.record(o), /job_log_not_ready/);
  assert.equal(row(s.METRICS_DB, 'SELECT status FROM jobs').status, 'completed');
  now.advance(LOG_NOT_READY_GRACE_MS);
  status = 503;
  await assert.rejects(s.collector.record(o), /github_http_503/);
  status = 404;
  await s.collector.record(o);
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
  assert.equal(row(s.METRICS_DB, 'SELECT COUNT(*) AS n FROM deliveries_seen').n, 1);
});

test('storage ignoring Range: the body is streamed through a bounded tail window; an oversize log yields nothing', async () => {
  const filler = 'x'.repeat(1023) + '\n', line = '2026-10-15T11:57:49Z ##[runner-telemetry]' + JSON.stringify(telemetry()) + '\n';
  const chunk = new TextEncoder().encode(filler.repeat(512)); // 512 KiB
  const streamOf = (chunks, tailText) => new ReadableStream({ pull(c) { if (chunks-- > 0) c.enqueue(chunk); else { c.enqueue(new TextEncoder().encode(tailText)); c.close(); } } });
  let s = setup({ fetcher: githubFake({ blob: () => new Response(streamOf(12, line), { status: 200 }) }) }); // 6 MiB then the line
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload()));
  assert.deepEqual(JSON.parse(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry), telemetry());
  s = setup({ fetcher: githubFake({ blob: () => new Response(streamOf(140, line), { status: 200 }) }) }); // 70 MiB: over the cap
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload()));
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
  // 416 to the suffix range: refetch once without Range.
  const seen = [];
  s = setup({ fetcher: githubFake({ blob: (url, init) => { seen.push(init.headers.Range ?? null); return init.headers.Range ? new Response(null, { status: 416 }) : new Response(line, { status: 200 }); } }) });
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload()));
  assert.deepEqual(seen, ['bytes=-' + LOG_TAIL_BYTES, null]);
  assert.ok(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry);
  // A 206 tail that starts mid-log drops its first (partial) line.
  s = setup({ fetcher: githubFake({ blob: () => new Response(line + 'after\n', { status: 206, headers: { 'content-range': 'bytes 100-500/501' } }) }) });
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload()));
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null, 'the partial first line is not trusted');
});

test('job and step events converge out of order; a completed job never regresses; telemetry is written once', async () => {
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake() });
  await collector.record(await observe(EVENTS, 'workflow_job', jobPayload()));
  await collector.record(await observe(EVENTS, 'workflow_job', jobPayload({ status: 'in_progress', conclusion: null, completed_at: null, runner_name: 'other',
    steps: [{ number: 2, name: 'Run actions/runner-telemetry', status: 'in_progress', conclusion: null, started_at: '2026-10-15T11:50:22Z', completed_at: null }] }, 'in_progress')));
  await collector.record(await observe(EVENTS, 'workflow_job', jobPayload({ status: 'queued', conclusion: null, started_at: null, completed_at: null, runner_name: null, steps: [] }, 'queued')));
  const j = row(METRICS_DB, 'SELECT status, conclusion, runner_name, completed_at FROM jobs');
  assert.deepEqual({ ...j }, { status: 'completed', conclusion: 'success', runner_name: 'GitHub Actions 12', completed_at: '2026-10-15T11:57:50.000Z' });
  assert.equal(row(METRICS_DB, 'SELECT status FROM steps WHERE job_id = 777 AND number = 2').status, 'completed');
  // queued then in_progress in order: progresses, keeps earlier fields.
  const s = setup({ fetcher: githubFake() });
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload({ status: 'queued', conclusion: null, started_at: null, completed_at: null, runner_name: null, steps: [] }, 'queued')));
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload({ status: 'in_progress', conclusion: null, completed_at: null }, 'in_progress')));
  assert.equal(row(s.METRICS_DB, 'SELECT status FROM jobs').status, 'in_progress');
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null, 'telemetry only on completion');
});

test('App not configured: rows stored, enrichment skipped (null), acknowledged; D1 failure is retried', async () => {
  const s = setup({ fetcher: githubFake(), mintToken: async () => { const e = new Error('app_unconfigured'); e.code = 'app_unconfigured'; throw e; } });
  const o = await observe(s.EVENTS, 'workflow_job', jobPayload());
  await s.collector.record(o);
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null); assert.equal(s.calls.length, 0);
  assert.ok(row(s.METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id));
  const t = setup({ fetcher: githubFake() });
  const o2 = await observe(t.EVENTS, 'workflow_run', runPayload());
  t.METRICS_DB.failNextBatch = true;
  await assert.rejects(t.collector.record(o2), /d1 unavailable/);
  assert.equal(row(t.METRICS_DB, 'SELECT COUNT(*) AS n FROM deliveries_seen').n, 0);
  await t.collector.record(o2);
  assert.equal(row(t.METRICS_DB, 'SELECT COUNT(*) AS n FROM runs').n, 1);
});

test('bad observations and a missing METRICS_DB binding throw (retried by the outbox, never dropped)', async () => {
  const { collector, EVENTS } = setup();
  await assert.rejects(collector.record({ delivery_id: 'x' }), /bad_observation/);
  await assert.rejects(metricsSinkFor({}).record(await observe(EVENTS, 'workflow_run', runPayload())), /metrics_db_unbound/);
  // Digest-checked read: a tampered capture is refused.
  const s = setup({ fetcher: githubFake() });
  const o = await observe(s.EVENTS, 'workflow_run', runPayload());
  await assert.rejects(s.collector.record({ ...o, body_sha256: 'f'.repeat(64) }), /delivery_digest_mismatch/);
});

test('secret-looking log text next to the telemetry line: only the parsed numbers are stored, nothing else', async () => {
  const secrets = ['ghp_' + 'A'.repeat(36), 'AKIA' + 'B'.repeat(16), 'Bearer eyJhbGciOi.secretpayload.sig', 'password=hunter2-' + randomSecret(), '/home/runner/work/demo/demo/.env'];
  const lines = ['##[group]Run env', ...secrets.map(x => 'TOKEN=' + x), 'runner-host-abc123.internal', '##[runner-telemetry]' + JSON.stringify(telemetry()), ...secrets];
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ blob: { status: 206, text: logText(lines) } }) });
  const o = await observe(EVENTS, 'workflow_job', jobPayload());
  await collector.record(o);
  assert.deepEqual(JSON.parse(row(METRICS_DB, 'SELECT telemetry FROM jobs').telemetry), telemetry());
  const dump = JSON.stringify(['runs', 'jobs', 'steps', 'deliveries_seen'].map(t => METRICS_DB.db.prepare('SELECT * FROM ' + t).all()));
  for (const x of [...secrets, 'runner-host-abc123', 'TOKEN=', '##[']) assert.ok(!dump.includes(x), 'not stored: ' + x);
  // A telemetry object smuggling text in an extra field, or a line with text before the marker, is refused outright.
  for (const line of ['##[runner-telemetry]' + JSON.stringify({ ...telemetry(), env: { GITHUB_TOKEN: secrets[0] } }), secrets[0] + ' ##[runner-telemetry]' + JSON.stringify(telemetry()),
    '##[runner-telemetry]' + JSON.stringify(telemetry({ arch: secrets[0] }))]) {
    const s = setup({ fetcher: githubFake({ blob: { status: 206, text: logText([line]) } }) });
    await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload()));
    assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
  }
});

test('a completed job without telemetry is complete, not an error: acknowledged, telemetry missing (null)', async () => {
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ blob: { status: 206, text: logText(['build ok']) } }) });
  const o = await observe(EVENTS, 'workflow_job', jobPayload());
  await collector.record(o);
  const j = row(METRICS_DB, 'SELECT status, telemetry, telemetry_kind FROM jobs');
  assert.deepEqual({ ...j }, { status: 'completed', telemetry: null, telemetry_kind: null });
  assert.ok(row(METRICS_DB, 'SELECT 1 AS x FROM deliveries_seen WHERE delivery_id = ?', o.delivery_id));
});

test('hostile payload text is stored bounded and verbatim (escaping is the renderer\'s job)', async () => {
  const { METRICS_DB, EVENTS, collector } = setup({ fetcher: githubFake({ timing: { status: 404 } }) });
  await collector.record(await observe(EVENTS, 'workflow_run', runPayload({ name: '<script>alert(1)</script>'.repeat(50), event: 'push"><img', head_sha: 'not-a-sha' })));
  const r = row(METRICS_DB, 'SELECT workflow_name, event, head_sha FROM runs');
  assert.equal(r.workflow_name.length, 200); assert.equal(r.event, null); assert.equal(r.head_sha, null);
});

test('actions:read token: requests exactly actions:read for one repository and refuses a broader grant', async () => {
  const { pem } = await pkcs8Pem(), env = { OBSERVATORY_APP_ID: '123456', OBSERVATORY_APP_KEY: secret(pem) };
  const bodies = [];
  const ok = await mintActionsToken(env, 7, 42, async (url, init) => { bodies.push(JSON.parse(init.body)); return Response.json({ token: 'short-lived', expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: { actions: 'read', metadata: 'read' } }, { status: 201 }); });
  assert.equal(ok.token, 'short-lived');
  assert.deepEqual(bodies[0], { repository_ids: [42], permissions: { actions: 'read' } });
  const seen = [];
  await assert.rejects(mintActionsToken(env, 7, 42, async (url, init) => {
    seen.push(init.method);
    if (url.endsWith('/access_tokens')) return Response.json({ token: 'too-broad', expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: { actions: 'read', contents: 'read' } }, { status: 201 });
    return new Response(null, { status: 204 });
  }), /token_too_broad/);
  assert.deepEqual(seen, ['POST', 'DELETE']);
});

test('wired end to end: a signed workflow_job webhook reaches D1 through the event ledger outbox', async () => {
  const current = randomSecret(), now = clock(), storage = sqlStorage(), EVENTS = memoryR2(), METRICS_DB = d1Database(MIGRATION);
  const env = { GITHUB_OWNER_ID: String(OWNER), EVENTS, METRICS_DB, OBSERVATORY_WEBHOOK_SECRET: secret(current), ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook'), OBSERVATORY_APP_ID: '' };
  const core = new EventLedgerCore(storage, env, { now });
  env.EVENT_LEDGER = { idFromName: n => n, get: () => core };
  const text = JSON.stringify(jobPayload({ status: 'queued', conclusion: null, started_at: null, completed_at: null }, 'queued'));
  const r = await handleWebhook(new Request('https://hooks.vespoli.me/github', { method: 'POST', body: text, headers: { 'x-github-event': 'workflow_job', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': await sign(current, text) } }), env);
  assert.equal(r.status, 202);
  await core.alarm();
  assert.equal(row(METRICS_DB, 'SELECT status FROM jobs WHERE job_id = 777').status, 'queued');
  assert.deepEqual(Object.keys(core.head().outbox), [], 'the metrics row was acknowledged');
});

test('no redirect is ever followed: GitHub API 3xx, a storage host 3xx (second hop) and an alert webhook 3xx all fail', async () => {
  const { githubRequest } = await import('../src/github-app.mjs');
  const { deliverAlert } = await import('../src/alerts.mjs');
  const hop = async (url, init) => { assert.equal(init.redirect, 'manual'); return new Response(null, { status: 302, headers: { location: 'https://evil.example/' } }); };
  await assert.rejects(githubRequest('/repos/a/b', { token: 't', fetcher: hop }), /github_redirect_refused/);
  await assert.rejects(deliverAlert({ ALERT_WEBHOOK_URL: secret('https://alerts.invalid/x') }, { schema: 'x' }, hop), /alert_redirect_refused/);
  const visited = [];
  const s = setup({ fetcher: githubFake({ blob: (url, init) => { visited.push(url); assert.equal(init.redirect, 'manual'); return new Response(null, { status: 307, headers: { location: 'https://evil.example/second' } }); } }) });
  const o = await observe(s.EVENTS, 'workflow_job', jobPayload());
  await s.collector.record(o);
  assert.deepEqual(visited, [BLOB], 'the second hop is not taken');
  assert.ok(!s.calls.some(c => c.url.startsWith('https://evil.example')));
  assert.equal(row(s.METRICS_DB, 'SELECT telemetry FROM jobs').telemetry, null);
});

test('a valid marker forged by an ordinary step is reported, never measured', async () => {
  const forged = telemetry({ cpu_mean: 0.99, cpu_p95: 0.99, cpu_max: 0.99 });
  const s = setup({ fetcher: githubFake({ blob: { status: 206, text: logText(['##[runner-telemetry]' + JSON.stringify(forged)]) } }) });
  await s.collector.record(await observe(s.EVENTS, 'workflow_job', jobPayload({ steps: [] })));
  const stored = row(s.METRICS_DB, 'SELECT telemetry, telemetry_kind FROM jobs');
  assert.deepEqual(JSON.parse(stored.telemetry), forged);
  assert.equal(stored.telemetry_kind, 'reported');
});

test('telemetry migration preserves historical rows and indexes while downgrading measured claims', () => {
  const db = d1Database(readFileSync(new URL('../migrations-observatory/0001_metrics.sql', import.meta.url), 'utf8'));
  db.db.prepare(`INSERT INTO jobs (job_id, run_id, attempt, repo_id, name, status, labels, queued_at, telemetry, telemetry_kind)
    VALUES (?, 1, 1, 42, 'build', 'completed', '[]', '2026-10-15T11:00:00Z', ?, ?)`).run(1, JSON.stringify(telemetry()), 'measured');
  db.db.prepare(`INSERT INTO jobs (job_id, run_id, attempt, repo_id, name, status, labels, queued_at)
    VALUES (2, 1, 1, 42, 'missing', 'completed', '[]', '2026-10-15T11:00:00Z')`).run();
  const before = db.db.prepare('SELECT * FROM jobs ORDER BY job_id').all();
  db.db.exec(readFileSync(new URL('../migrations-observatory/0002_reported_telemetry.sql', import.meta.url), 'utf8'));
  const after = db.db.prepare('SELECT * FROM jobs ORDER BY job_id').all();
  assert.deepEqual(after.map(j => ({ ...j })), before.map(j => ({ ...j, telemetry_kind: j.telemetry ? 'reported' : null })));
  assert.deepEqual(db.db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'jobs' ORDER BY name").all().map(x => x.name), ['jobs_queued', 'jobs_repo_queued', 'jobs_run']);
  assert.throws(() => db.db.prepare("UPDATE jobs SET telemetry_kind = 'measured' WHERE job_id = 1").run(), /CHECK constraint/);
});
