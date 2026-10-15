// Presentation only: the render functions called directly with fixture data. Escaping of hostile payload text,
// missing data shown as missing (never zero), estimate labels, and markup that works under the strict CSP.
// Authorization is tested separately in access.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { overviewPage, eventsPage, commitsPage, verifyPage, promotionsPage, actionsPage, figure, escapeHtml, html, CSS } from '../src/dashboard-html.mjs';
import { summarize, fig, PROVENANCE } from '../src/dashboard-data.mjs';

const HOSTILE = `<script>alert("x")</script><img src=x onerror=alert(1)>'"&`;
const ESCAPED = '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;&#39;&quot;&amp;';

function assertSafe(page, label) {
  assert.ok(!page.includes('<script'), label + ': no script element');
  assert.ok(!/<img\b/i.test(page), label + ': no injected element');
  assert.ok(!/\sstyle=/i.test(page), label + ': no inline style attributes (CSP style-src self)');
  assert.ok(!/\son[a-z]+=/i.test(page.replace(/&lt;[^]*?&gt;/g, '')), label + ': no event handler attributes');
  assert.ok(!/(?:src|href)="(?:https?:)?\/\//i.test(page), label + ': no external resources or links');
  assert.match(page, /<link rel="stylesheet" href="\/style.css">/);
}

const emptySummary = summarize([], []);
const overview = (over = {}) => ({
  generated_at: '2026-10-15T12:00:00.000Z',
  ledger: { head: { seq: 12, entry_hash: 'e'.repeat(64), last_checkpoint: null, outbox: { metrics: { pending: 2, max_attempts: 1 } } }, chain: { ok: true, checked: 12, first_break: null, from: 1, to: 12, head_seq: 12 } },
  findings: { total: 1, last_7d: 1, by_kind: { main_forced_update: 1 }, latest: [{ kind: 'main_forced_update', repo_id: 42, ref: HOSTILE, sha: 'a'.repeat(40), detected_at: '2026-10-15T11:00:00.000Z' }] },
  runs_24h: { ...emptySummary, truncated: false }, provenance: PROVENANCE,
  backup: { available: true, summary: { last_capture: '2026-10-15T03:17:00Z', note: HOSTILE, nested: { x: HOSTILE } } },
  repos: [{ repo_id: 42, full_name: HOSTILE }], ...over,
});

test('figure(): missing is "missing" never 0, estimates carry ≈ and an est. badge with the basis, others are plain', () => {
  assert.equal(String(figure(fig(null, 'measured', 'ms'))), '<span class="missing">missing</span>');
  assert.equal(String(figure(undefined)), '<span class="missing">missing</span>');
  assert.equal(String(figure(fig(0, 'measured', 'count'))), '0', 'a real zero is zero');
  assert.equal(String(figure(fig(90_000, 'measured', 'ms'))), '1m 30s');
  assert.equal(String(figure(fig(12.5, 'reported', 'min'))), '12.5');
  const est = String(figure(fig(7, 'estimated', 'min', { basis: 'rounded <b>' })));
  assert.match(est, /^<span class="est">≈ 7\.0<\/span> <abbr class="badge est" title="estimated: rounded &lt;b&gt;">est\.<\/abbr>$/);
  assert.equal(escapeHtml(HOSTILE), ESCAPED);
  assert.equal(String(html`<p>${HOSTILE}</p>`), '<p>' + ESCAPED + '</p>');
  assert.equal(String(html`<p>${[HOSTILE, html`<b>ok</b>`]}</p>`), '<p>' + ESCAPED + '<b>ok</b></p>', 'only html`` fragments pass unescaped');
});

test('overview: hostile repository names, refs and backup text are escaped; empty metrics read as missing', () => {
  const page = overviewPage(overview());
  assertSafe(page, 'overview');
  assert.ok(page.includes(ESCAPED));
  assert.ok(!page.includes(HOSTILE));
  assert.match(page, /duration p50/); assert.match(page, /<span class="missing">missing<\/span><\/div><div class="k">duration p50/);
  assert.match(page, /<div class="v">0<\/div><div class="k">runs/, 'zero runs is a real zero');
  assert.match(page, /billable minutes \(reported\)/); assert.match(page, /\(estimated\)/);
  const broken = overviewPage(overview({ ledger: { head: { seq: 3, entry_hash: 'e'.repeat(64), last_checkpoint: null, outbox: {} }, chain: { ok: false, checked: 1, first_break: { seq: 2, reason: 'entry_hash_mismatch' } } }, findings: null, runs_24h: null, backup: { available: false, reason: 'unbound' } }));
  assert.match(broken, /broken at 2/); assert.match(broken, /entry_hash_mismatch/); assert.match(broken, /Findings unavailable/); assert.match(broken, /Backup status unavailable \(unbound\)/);
});

test('events, commit ledger and verification pages escape every payload-derived value', () => {
  const events = eventsPage({ items: [{ seq: 5, received_at: '2026-10-15T11:00:00.000Z', event: 'workflow_job', action: 'completed', repo_id: 42, repo: HOSTILE, delivery_id: crypto.randomUUID(), entry_hash: 'f'.repeat(64) }], next_cursor: 5, limit: 50 });
  assertSafe(events, 'events'); assert.ok(events.includes(ESCAPED)); assert.match(events, /href="\/events\?cursor=5&amp;limit=50"/);
  const commits = commitsPage({ repo_id: 42, limit: 50, next_cursor: null, head: { full_name: HOSTILE, seq: 2, mirrored_through: 2, inbox: { pending: 0 }, promotions_pending: 0 },
    items: [{ seq: 2, kind: 'commit', recorded_at: '2026-10-15T11:00:00.000Z', entry_hash: 'f'.repeat(64), data: { sha: 'a'.repeat(40), verified: false, verification_reason: HOSTILE, author_name: HOSTILE, parents: ['b'.repeat(40)], ref: HOSTILE } },
      { seq: 1, kind: 'ref_update', recorded_at: '2026-10-15T11:00:00.000Z', entry_hash: 'f'.repeat(64), data: { ref: HOSTILE, before: '0'.repeat(40), after: 'a'.repeat(40), forced: true, pusher: HOSTILE } }],
    findings: [{ kind: 'tag_moved', ref: HOSTILE, sha: 'a'.repeat(40), entry_seq: 1, detected_at: '2026-10-15T11:00:00.000Z' }] });
  assertSafe(commits, 'commits'); assert.ok(!commits.includes(HOSTILE)); assert.match(commits, /href="\/repos\/42\/verify"/);
  const verify = verifyPage({ repo_id: 42, full_name: HOSTILE, head: { seq: 9, entry_hash: 'f'.repeat(64) }, result: { ok: false, checked: 3, from: 7, to: 9, head_seq: 9, first_break: { seq: 8, reason: 'prev_hash_mismatch' } } });
  assertSafe(verify, 'verify'); assert.match(verify, /First break at seq 8: prev_hash_mismatch/);
});

test('promotions: tag, missing-tag finding and shadow→main time; absent time is shown as absent', () => {
  const page = promotionsPage({ window_entries_per_repo: 200, items: [
    { repo_id: 42, repo: HOSTILE, sha: 'a'.repeat(40), reached_main_at: '2026-10-15T11:00:00.000Z', tag: 'promote/pr-7-aaaaaaaaaaaa', pr: 7, shadow_to_main_s: 754, forced: false, missing_tag_finding: false },
    { repo_id: 42, repo: HOSTILE, sha: 'b'.repeat(40), reached_main_at: '2026-10-15T10:00:00.000Z', tag: null, pr: null, forced: true, missing_tag_finding: true }] });
  assertSafe(page, 'promotions');
  assert.match(page, /promote\/pr-7-aaaaaaaaaaaa/); assert.match(page, /12m 34s/); assert.match(page, /badge bad">missing/); assert.match(page, /forced/);
});

test('actions: reported and estimated minutes in separate columns, estimates visibly marked, missing telemetry not zero', () => {
  const runs = [
    { repo_id: 42, run_id: 1, attempt: 1, workflow_name: HOSTILE, status: 'completed', conclusion: 'success', created_at: '2026-10-15T10:00:00.000Z', run_started_at: '2026-10-15T10:00:00.000Z', updated_at: '2026-10-15T10:05:00.000Z', billable_ms: 300_000, billable_kind: 'reported' },
    { repo_id: 42, run_id: 2, attempt: 1, workflow_name: HOSTILE, status: 'completed', conclusion: 'failure', created_at: '2026-10-15T11:00:00.000Z', run_started_at: '2026-10-15T11:00:00.000Z', updated_at: '2026-10-15T11:02:00.000Z', billable_ms: null, billable_kind: null },
  ];
  const jobs = [{ repo_id: 42, run_id: 2, attempt: 1, job_id: 9, name: HOSTILE, workflow_name: HOSTILE, status: 'completed', conclusion: 'failure', runner_group: 'GitHub Actions',
    queued_at: '2026-10-15T11:00:00.000Z', started_at: '2026-10-15T11:00:10.000Z', completed_at: '2026-10-15T11:01:30.000Z', telemetry_kind: null, cpu_mean: null, cpu_p95: null, mem_peak: null }];
  const s = summarize(runs, jobs);
  assert.deepEqual(s.billable_minutes, { value: 5, kind: 'reported', unit: 'min', n: 1, source: s.billable_minutes.source });
  assert.equal(s.estimated_minutes.value, 2, 'run 2 only: 80 s rounds up to 2 minutes; never added to the reported 5');
  assert.equal(s.estimated_minutes.kind, 'estimated');
  assert.equal(s.cpu_mean.value, null); assert.equal(s.telemetry_jobs.value, 0);
  const row = { repo_id: 42, repo: HOSTILE, workflow: HOSTILE, job: HOSTILE, ...s };
  const page = actionsPage({ days: 7, since: '2026-10-08T12:00:00.000Z', truncated: false, provenance: PROVENANCE, total: s, by_repository: [row], by_workflow: [row], by_job: [row] });
  assertSafe(page, 'actions');
  assert.ok(!page.includes(HOSTILE)); assert.ok(page.includes(ESCAPED));
  assert.match(page, /Billable min \(reported\)<\/th><th class="num" scope="col">Minutes \(estimated\)/);
  assert.match(page, /<span class="est">≈ 2\.0<\/span> <abbr class="badge est"/);
  assert.match(page, /<td class="num">5\.0<\/td>/, 'reported minutes are plain');
  assert.ok((page.match(/class="missing">missing/g) ?? []).length >= 4, 'CPU and memory without telemetry are missing');
  assert.ok(!/CPU mean[^]*?<td class="num">0%/.test(page), 'never a fake 0%');
  assert.match(page, /<svg class="bar" width="60" height="8" viewBox="0 0 100 10" aria-hidden="true" focusable="false">/);
});

test('stylesheet: light and dark schemes, phone-width rules, no remote fonts or imports', () => {
  assert.match(CSS, /prefers-color-scheme:dark/); assert.match(CSS, /max-width:600px/);
  assert.ok(!/@import|url\(|@font-face/.test(CSS));
});
