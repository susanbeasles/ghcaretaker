// Dashboard data and routing with a valid Access assertion: statistics, promotion derivation, bounded D1 reads,
// backup status tolerance, JSON twins carrying provenance, parameter validation. (Gate: access.test.mjs;
// presentation: dashboard-render.test.mjs.)
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { percentile, summarize, derivePromotions, backupSummary, actionsData } from '../src/dashboard-data.mjs';
import { handleDashboard, CSP } from '../src/dashboard.mjs';
import { _resetAccessCache } from '../src/access.mjs';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { CommitLedgerCore } from '../src/commit-ledger-core.mjs';
import { metricsCollector } from '../src/metrics.mjs';
import { accessKit, d1Database, sqlStorage, memoryR2, clock, namespace, secret, sha } from './fakes.mjs';

const MIGRATION = ['0001_metrics.sql', '0002_reported_telemetry.sql'].map(name => readFileSync(new URL('../migrations-observatory/' + name, import.meta.url), 'utf8')).join('\n');
beforeEach(() => _resetAccessCache());

test('nearest-rank percentiles; empty is null', () => {
  assert.equal(percentile([], 95), null);
  assert.equal(percentile([5], 50), 5);
  const v = Array.from({ length: 100 }, (_, i) => i + 1);
  assert.equal(percentile(v, 50), 50); assert.equal(percentile(v, 95), 95); assert.equal(percentile([3, 1, 2], 95), 3);
});

test('summarize: failure rate excludes cancelled and skipped; durations and queue from event timestamps', () => {
  const r = (id, conclusion, start, end) => ({ repo_id: 1, run_id: id, attempt: 1, status: 'completed', conclusion, created_at: start, run_started_at: start, updated_at: end, billable_ms: null, billable_kind: null });
  const s = summarize([r(1, 'success', '2026-10-15T10:00:00Z', '2026-10-15T10:01:00Z'), r(2, 'failure', '2026-10-15T10:00:00Z', '2026-10-15T10:03:00Z'), r(3, 'cancelled', '2026-10-15T10:00:00Z', '2026-10-15T10:00:30Z'),
    { ...r(4, null, '2026-10-15T10:00:00Z', '2026-10-15T10:00:30Z'), status: 'in_progress' }],
  [{ repo_id: 1, run_id: 1, attempt: 1, status: 'completed', conclusion: 'success', queued_at: '2026-10-15T10:00:00Z', started_at: '2026-10-15T10:00:42Z', completed_at: '2026-10-15T10:01:00Z', runner_group: 'self-hosted' }]);
  assert.equal(s.failure_rate.value, 0.5); assert.equal(s.failure_rate.n, 2); assert.equal(s.failure_rate.kind, 'measured');
  assert.equal(s.run_duration_p95.value, 180_000); assert.equal(s.queue_p95.value, 42_000);
  assert.equal(s.billable_minutes.value, null, 'nothing reported: missing, not zero');
  assert.equal(s.estimated_minutes.value, null, 'self-hosted jobs are not estimated as billable');
});

test('promotions are derived from main updates, promote/* tags and shadow pushes in the ledger', () => {
  const S = sha(10), T = sha(11);
  const ru = (seq, ref, after, at, extra = {}) => ({ seq, kind: 'ref_update', recorded_at: at, data: { ref, before: '0'.repeat(40), after, created: false, deleted: false, forced: false, ...extra } });
  const entries = [
    ru(6, 'refs/tags/promote/pr-7-' + S.slice(0, 12), sha(99), '2026-10-15T10:21:00.000Z', { created: true }),
    ru(5, 'refs/heads/main', S, '2026-10-15T10:20:00.000Z'),
    ru(4, 'refs/heads/main', T, '2026-10-15T10:10:00.000Z', { forced: true }),
    ru(3, 'refs/heads/shadow/pr-7', S, '2026-10-15T10:05:00.000Z'),
    ru(2, 'refs/heads/main', '0'.repeat(40), '2026-10-15T10:00:00.000Z', { deleted: true }),
  ];
  const out = derivePromotions(entries, [{ kind: 'main_commit_missing_promotion_tag', sha: T }]);
  assert.equal(out.length, 2);
  assert.deepEqual(out[0], { sha: S, seq: 5, reached_main_at: '2026-10-15T10:20:00.000Z', forced: false, tag: 'promote/pr-7-' + S.slice(0, 12), pr: 7, tag_recorded_at: '2026-10-15T10:21:00.000Z', missing_tag_finding: false, shadow_to_main_s: 900 });
  assert.equal(out[1].tag, null); assert.equal(out[1].missing_tag_finding, true); assert.equal(out[1].forced, true);
  assert.equal('shadow_to_main_s' in out[1], false, 'not derivable: omitted');
});

test('backup status: unbound, failing and slow bindings are reported, never fatal', async () => {
  assert.deepEqual(await backupSummary({}), { available: false, reason: 'unbound' });
  assert.deepEqual(await backupSummary({ BACKUP_STATUS: { summary: async () => { throw new Error('down'); } } }), { available: false, reason: 'unavailable' });
  assert.deepEqual(await backupSummary({ BACKUP_STATUS: { summary: () => new Promise(() => {}) } }, 20), { available: false, reason: 'unavailable' });
  assert.deepEqual(await backupSummary({ BACKUP_STATUS: { summary: async () => ({ ok: true }) } }), { available: true, summary: { ok: true } });
  assert.deepEqual(await backupSummary({ BACKUP_STATUS: { summary: async () => ({ blob: 'x'.repeat(70_000) }) } }), { available: false, reason: 'too_large' });
});

test('actions data only accepts 7 or 30 days and requires the metrics binding', async () => {
  await assert.rejects(actionsData({ METRICS_DB: d1Database(MIGRATION) }, { days: 14 }), /bad_days/);
  await assert.rejects(actionsData({}, { days: 7 }), /metrics_db_unbound/);
});

async function world() {
  const now = clock(Date.parse('2026-10-15T12:00:00Z')), kit = await accessKit();
  const env = { ...kit.env, GITHUB_OWNER_ID: '215839550', EVENTS: memoryR2(), METRICS_DB: d1Database(MIGRATION), ALERT_WEBHOOK_URL: secret('https://alerts.invalid/x'),
    BACKUP_STATUS: { summary: async () => ({ last_success_at: '2026-10-15T03:20:00Z', repositories: 3 }) } };
  const events = new EventLedgerCore(sqlStorage(), env, { now });
  env.EVENT_LEDGER = { idFromName: n => n, get: () => events };
  env.COMMIT_LEDGER = namespace(() => new CommitLedgerCore(sqlStorage(), env, { now }));
  const db = env.METRICS_DB.db;
  db.prepare(`INSERT INTO runs (repo_id, run_id, attempt, workflow_name, status, conclusion, created_at, run_started_at, updated_at, billable_ms, billable_json, billable_kind)
    VALUES (42, 1, 1, '<b>wf</b>', 'completed', 'success', '2026-10-15T11:00:00.000Z', '2026-10-15T11:00:00.000Z', '2026-10-15T11:04:00.000Z', 240000, '{}', 'reported')`).run();
  db.prepare(`INSERT INTO jobs (job_id, run_id, attempt, repo_id, name, workflow_name, status, labels, runner_group, queued_at, started_at, completed_at, conclusion, telemetry, telemetry_kind)
    VALUES (9, 1, 1, 42, 'build', '<b>wf</b>', 'completed', '[]', 'GitHub Actions', '2026-10-15T11:00:01.000Z', '2026-10-15T11:00:11.000Z', '2026-10-15T11:03:50.000Z', 'success', ?, 'reported')`)
    .run(JSON.stringify({ cpu_mean: 0.4, cpu_p95: 0.9, memory_used_max_bytes: 5_000_000_000 }));
  // One event so the ledger head is non-empty (begin/commit are the ingress path).
  const delivery_id = crypto.randomUUID(), body_sha256 = 'a'.repeat(64), r = events.begin({ delivery_id, body_sha256 });
  await events.commit({ delivery_id, token: r.token, event: 'workflow_run', action: 'completed', repo_id: 42, repo_full_name: 'susanbeasles/<i>demo</i>', body_sha256 });
  const get = async (path, method = 'GET') => handleDashboard(new Request('https://caretaker.vespoli.me' + path, { method, headers: { 'cf-access-jwt-assertion': await kit.sign(kit.claims({ exp: Math.floor(now() / 1000) + 600, iat: Math.floor(now() / 1000), nbf: Math.floor(now() / 1000) })) } }), env, { fetcher: kit.fetcher, now });
  return { env, get, now };
}

test('routes with a valid assertion: HTML pages, JSON twins with provenance, security headers, HEAD without body', async () => {
  const { get } = await world();
  for (const path of ['/', '/events', '/repos/42/commits', '/repos/42/verify', '/promotions', '/actions', '/actions?days=30']) {
    const r = await get(path);
    assert.equal(r.status, 200, path);
    assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff'); assert.equal(r.headers.get('cache-control'), 'no-store');
    const text = await r.text();
    assert.ok(!text.includes('<b>wf</b>') && !text.includes('<i>demo</i>'), path + ' escapes payload text');
  }
  assert.match(CSP, /default-src 'none'; style-src 'self'/); assert.match(CSP, /frame-ancestors 'none'/);
  const overview = await (await get('/api/overview')).json();
  assert.equal(overview.ledger.head.seq, 1); assert.equal(overview.ledger.chain.ok, true);
  assert.equal(overview.runs_24h.billable_minutes.kind, 'reported'); assert.equal(overview.runs_24h.billable_minutes.value, 4);
  assert.equal(overview.runs_24h.estimated_minutes.value, null, 'reported runs are never estimated');
  assert.equal(overview.backup.summary.repositories, 3); assert.ok(overview.provenance.estimated);
  const actions = await (await get('/api/actions?days=7')).json();
  assert.equal(actions.by_job[0].cpu_mean.kind, 'reported'); assert.equal(actions.by_job[0].cpu_mean.value, 0.4);
  assert.equal(actions.by_job[0].memory_peak.value, 5_000_000_000); assert.equal(actions.by_workflow[0].workflow, '<b>wf</b>', 'JSON keeps the raw value (served as application/json, nosniff)');
  assert.equal(actions.total.queue_p95.value, 10_000);
  const events = await (await get('/api/events?limit=1')).json();
  assert.equal(events.items[0].repo, 'susanbeasles/<i>demo</i>');
  const verify = await (await get('/api/repos/42/verify')).json();
  assert.equal(verify.result.ok, true);
  const head = await get('/actions', 'HEAD');
  assert.equal(head.status, 200); assert.equal(await head.text(), '');
  const css = await get('/style.css');
  assert.equal(css.headers.get('content-type'), 'text/css; charset=utf-8');
});

test('bad parameters are 400, unknown paths 404, never a redirect', async () => {
  const { get } = await world();
  for (const path of ['/events?limit=0', '/events?limit=101', '/events?cursor=-1', '/events?cursor=abc', '/actions?days=14', '/repos/0/commits', '/repos/abc/commits', '/repos/99999999999999999/commits', '/api/actions?days=1', '/promotions?repo=x']) {
    const r = await get(path);
    assert.equal(r.status, 400, path); await r.arrayBuffer();
  }
  for (const path of ['/overview', '/api', '/api/', '/repos/42', '/repos/42/commits/', '/events/', '/api/style.css']) {
    const r = await get(path);
    assert.equal(r.status, 404, path); await r.arrayBuffer();
  }
});

test('collector output feeds the dashboard: telemetry figures are reported, an absent timing is missing', async () => {
  const { env, get } = await world();
  env.METRICS_DB.db.exec('DELETE FROM runs; DELETE FROM jobs');
  const collector = metricsCollector(env, { readDelivery: async (_e, _k, _s) => current, mintToken: async () => { const e = new Error('x'); e.code = 'app_unconfigured'; throw e; } });
  let current;
  const deliver = async payload => { current = { payload }; await collector.record({ delivery_id: crypto.randomUUID(), event: payload.workflow_run ? 'workflow_run' : 'workflow_job', action: payload.action, repo_id: 42, received_at: '', object_key: 'k', body_sha256: 'a'.repeat(64) }); };
  const repository = { id: 42, full_name: 'susanbeasles/demo', owner: { id: 215839550 } };
  await deliver({ action: 'completed', repository, installation: { id: 1 }, workflow_run: { id: 5, run_attempt: 1, name: 'ci', status: 'completed', conclusion: 'success', created_at: '2026-10-15T11:00:00Z', run_started_at: '2026-10-15T11:00:00Z', updated_at: '2026-10-15T11:02:00Z' } });
  const t = await (await get('/api/actions')).json();
  assert.equal(t.total.runs.value, 1); assert.equal(t.total.billable_minutes.value, null); assert.equal(t.total.cpu_mean.value, null);
});

test('new and legacy job-log claims have only reported provenance in dashboard aggregates', () => {
  for (const telemetry_kind of ['reported', 'measured']) {
    const summary = summarize([], [{ telemetry_kind, cpu_mean: 0.99, cpu_p95: 1, mem_peak: 100 }]);
    for (const key of ['telemetry_jobs', 'cpu_mean', 'cpu_p95', 'memory_peak']) assert.equal(summary[key].kind, 'reported', key);
    assert.equal(summary.telemetry_jobs.value, 1);
    assert.equal(summary.cpu_mean.value, 0.99);
  }
});
