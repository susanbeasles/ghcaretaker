// Owner requirement 5a (missed deliveries reconciled against GitHub's hook delivery log with the App JWT) and the
// GitHub API wrappers behind requirements 4 and 5 (compare, matching refs, Link cursors). GitHub is a local fetcher;
// the App key is generated per run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { compareCommits, listMatchingRefs, nextCursor, listHookDeliveries, MAX_COMPARE_COMMITS } from '../src/github-app.mjs';
import { MAX_DELIVERY_PAGES, MAX_REDELIVERIES_PER_RUN, MAX_ATTEMPTS_PER_GUID, REDELIVERY_SPACING_MS } from '../src/hook-reconcile.mjs';
import { unb64 } from '../src/crypto.mjs';
import { sqlStorage, memoryR2, secret, clock, pkcs8Pem, sha, captureLogs } from './fakes.mjs';

const API = 'https://api.github.com';
const at = (now, minutesAgo) => new Date(now() - minutesAgo * 60_000).toISOString().replace('.000', '');

async function ledger({ appId = '123456' } = {}) {
  const now = clock(), storage = sqlStorage(), { pem } = await pkcs8Pem(), calls = [], alerts = [];
  const gh = { pages: [[]], attemptStatus: () => 202 };
  const fetcher = async (url, init) => {
    if (url.startsWith('https://alerts.invalid')) { alerts.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); }
    const u = new URL(url);
    calls.push({ method: init.method ?? 'GET', path: u.pathname + u.search, auth: init.headers.Authorization, redirect: init.redirect });
    if (u.pathname === '/app/hook/deliveries') {
      const i = u.searchParams.get('cursor') ? Number(u.searchParams.get('cursor').slice(1)) : 0;
      const link = i + 1 < gh.pages.length ? `<${API}/app/hook/deliveries?per_page=100&cursor=c${i + 1}>; rel="next"` : null;
      return Response.json(gh.pages[i], { headers: link ? { link } : {} });
    }
    const m = /^\/app\/hook\/deliveries\/(\d+)\/attempts$/.exec(u.pathname);
    if (m && init.method === 'POST') return new Response('', { status: gh.attemptStatus(Number(m[1])) });
    return new Response(null, { status: 599 });
  };
  const env = { EVENTS: memoryR2(), ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook'), OBSERVATORY_APP_ID: appId, OBSERVATORY_APP_KEY: secret(pem) };
  const core = new EventLedgerCore(storage, env, { now, fetcher });
  return { core, storage, now, calls, alerts, gh, pem };
}

async function ledgered(core) {
  const delivery_id = crypto.randomUUID(), body_sha256 = 'a'.repeat(64), r = core.begin({ delivery_id, body_sha256 });
  await core.commit({ delivery_id, token: r.token, event: 'push', body_sha256 });
  return delivery_id;
}
const item = (id, guid, status, when, o = {}) => ({ id, guid, delivered_at: when, redelivery: false, duration: 0.1, status: status === 202 ? 'OK' : 'failed', status_code: status, event: 'push', action: null, installation_id: 7, repository_id: 42, ...o });
const posts = calls => calls.filter(c => c.method === 'POST').map(c => Number(/deliveries\/(\d+)\//.exec(c.path)[1])).sort((a, b) => a - b);
const run = async core => { await core.requestCron(['deliveries']); await core.alarm(); return JSON.parse(core.meta('hooks_last_run')); };

test('hook deliveries: redeliver guids missing from the ledger or never acknowledged; App JWT only; bodies never read', async () => {
  const { core, now, calls, gh, pem } = await ledger();
  const ok = await ledgered(core), unacked = await ledgered(core), conflicted = await ledgered(core);
  core.begin({ delivery_id: conflicted, body_sha256: 'b'.repeat(64), event: 'push' }); // delivery_conflict finding
  const missingAcked = crypto.randomUUID(), missingFailed = crypto.randomUUID(), tooOld = crypto.randomUUID();
  gh.pages = [[
    item(11, ok, 202, at(now, 5)), item(12, unacked, 500, at(now, 6)), item(13, unacked, 0, at(now, 4), { redelivery: true }),
    item(14, missingAcked, 202, at(now, 7)), item(15, missingFailed, 503, at(now, 8)),
  ], [item(16, conflicted, 409, at(now, 9)), item(17, tooOld, 500, at(now, 5 * 24 * 60))]];
  const { result: last, lines } = await captureLogs(() => run(core));
  assert.deepEqual(posts(calls), [13, 14, 15], 'latest attempt of each guid; the conflicted and the too-old are left alone');
  assert.deepEqual({ ...last, at: 0 }, { at: 0, ok: true, pages: 2, invalid: 0, complete: true, resumed: false, scanned: 5, missing: 2, unacknowledged: 1,
    redelivered: 3, failed: 0, skipped_conflict: 1, skipped_exhausted: 0, skipped_spacing: 0, deferred: 0 });
  for (const c of calls) {
    assert.equal(c.redirect, 'manual');
    const [h, p] = c.auth.replace('Bearer ', '').split('.');
    assert.equal(JSON.parse(new TextDecoder().decode(unb64(h))).alg, 'RS256');
    assert.equal(JSON.parse(new TextDecoder().decode(unb64(p))).iss, '123456', 'App JWT, not an installation token');
  }
  assert.ok(calls.every(c => !c.path.includes('/request') && !c.path.includes('/attempts?')), 'never fetches a delivery body');
  const logged = lines.join('\n');
  assert.ok(!logged.includes('Bearer') && !logged.includes(pem.slice(40, 80)), 'no credentials in logs');
  const state = JSON.parse(core.meta('hooks_state'));
  assert.equal(state.watermark, Date.parse(at(now, 4))); assert.equal(state.resume_cursor, null);
  // Immediately again: spacing holds every candidate back.
  calls.length = 0;
  const again = await run(core);
  assert.deepEqual(posts(calls), []); assert.equal(again.skipped_spacing, 3);
});

test('hook deliveries: per-guid cap with an exhaustion alert, per-run bound, and GitHub refusing a redelivery', async () => {
  const { core, now, calls, gh, alerts } = await ledger();
  const stuck = crypto.randomUUID();
  gh.pages = [[item(1, stuck, 500, at(now, 1))]];
  for (let i = 0; i < MAX_ATTEMPTS_PER_GUID; i++) { await run(core); now.advance(REDELIVERY_SPACING_MS); }
  assert.equal(posts(calls).length, MAX_ATTEMPTS_PER_GUID);
  gh.pages = [[item(1, stuck, 500, at(now, 1))]];
  const exhausted = await run(core); await core.alarm();
  assert.equal(posts(calls).length, MAX_ATTEMPTS_PER_GUID, 'capped'); assert.equal(exhausted.skipped_exhausted, 1);
  assert.ok(alerts.some(a => a.code === 'redelivery_exhausted' && a.delivery_id === stuck && a.type === 'operational'));

  calls.length = 0; now.advance(REDELIVERY_SPACING_MS);
  gh.pages = [Array.from({ length: MAX_REDELIVERIES_PER_RUN + 5 }, (_, i) => item(100 + i, crypto.randomUUID(), 500, at(now, 2)))];
  gh.attemptStatus = id => (id === 100 ? 422 : 202);
  const bounded = await run(core);
  assert.equal(posts(calls).length, MAX_REDELIVERIES_PER_RUN);
  assert.equal(bounded.redelivered + bounded.failed, MAX_REDELIVERIES_PER_RUN); assert.equal(bounded.failed, 1); assert.equal(bounded.deferred, 5);
  const refused = core.storage.sql.exec('SELECT last_result FROM hook_redeliveries WHERE last_hook_delivery_id = 100').toArray()[0];
  assert.equal(refused.last_result, 'github_http_422');
});

test('hook deliveries: a run cut short by the page cap resumes from its cursor before the watermark moves', async () => {
  const { core, now, calls, gh } = await ledger();
  gh.pages = Array.from({ length: MAX_DELIVERY_PAGES + 2 }, (_, i) => [item(1000 + i, crypto.randomUUID(), 202, at(now, 10 + i))]);
  const first = await run(core);
  assert.equal(first.pages, MAX_DELIVERY_PAGES); assert.equal(first.complete, false);
  let state = JSON.parse(core.meta('hooks_state'));
  assert.equal(state.resume_cursor, 'c' + MAX_DELIVERY_PAGES); assert.equal(state.watermark, undefined); assert.equal(state.pending_watermark, Date.parse(at(now, 10)));
  assert.equal(posts(calls).length, MAX_DELIVERY_PAGES, 'acknowledged but missing from the ledger: redelivered');
  const second = await run(core);
  assert.equal(second.resumed, true); assert.equal(second.complete, true); assert.equal(second.pages, 2);
  state = JSON.parse(core.meta('hooks_state'));
  assert.equal(state.watermark, Date.parse(at(now, 10)), 'watermark = newest of the interrupted walk'); assert.equal(state.resume_cursor, null);
});

test('hook deliveries fail closed without an App id; nothing is fetched and the run is recorded as failed', async () => {
  const { core, calls } = await ledger({ appId: '' });
  const last = await run(core);
  assert.deepEqual({ ...last, at: 0 }, { at: 0, ok: false, error: 'app_unconfigured' });
  assert.equal(calls.length, 0);
});

test('Link cursors: next is parsed; a present but unusable next link is an error, never "no more pages"', async () => {
  assert.equal(nextCursor(`<${API}/app/hook/deliveries?per_page=100&cursor=v1_abc%3D>; rel="next", <${API}/x>; rel="last"`), 'v1_abc=');
  assert.equal(nextCursor(null), null); assert.equal(nextCursor(`<${API}/x?page=1>; rel="prev"`), null);
  for (const bad of ['<https://evil.invalid/?cursor=a>; rel="next"', `<${API}/x>; rel="next"`, `<${API}/x?cursor=a%20b>; rel="next"`]) assert.throws(() => nextCursor(bad), /github_bad_link/);
  const page = await listHookDeliveries('jwt', null, async () => Response.json([{ id: 1, guid: 'NOT-A-GUID', delivered_at: 'x', status_code: 200 }, item(2, crypto.randomUUID().toUpperCase(), 202, '2026-10-15T11:00:00Z')]));
  assert.equal(page.invalid, 1); assert.equal(page.items.length, 1); assert.match(page.items[0].guid, /^[0-9a-f-]{36}$/);
});

function compareApi({ total, pageSizes, files = 0, status = 'ahead' }) {
  const urls = [];
  let n = 0;
  const fetcher = async (url, init) => {
    urls.push(url); assert.equal(init.redirect, 'manual');
    const page = Number(new URL(url).searchParams.get('page')), size = pageSizes[page - 1] ?? 0;
    const commits = Array.from({ length: size }, () => { n++; return { sha: sha(n), parents: [{ sha: sha(n - 1) }], commit: { tree: { sha: sha(9000 + n) }, message: 'secret message ' + n, author: { name: 'A', date: 'd' }, committer: { name: 'C', date: 'd' }, verification: { verified: true, reason: 'valid' } } }; });
    return Response.json({ status, total_commits: total, merge_base_commit: { sha: sha(0) }, commits, files: page === 1 ? Array.from({ length: files }, () => ({ patch: 'x'.repeat(1000) })) : undefined });
  };
  return { fetcher, urls };
}

test('compare: every page, oldest first, bounded by commits and bytes; short results and budget exhaustion are explicit', async () => {
  const ok = compareApi({ total: 150, pageSizes: [100, 50] });
  const r = await compareCommits('susanbeasles/demo', 'feature/x', sha(500), 'tok', ok.fetcher);
  assert.deepEqual(ok.urls, [1, 2].map(p => `${API}/repos/susanbeasles/demo/compare/feature%2Fx...${sha(500)}?per_page=100&page=${p}`));
  assert.equal(r.commits.length, 150); assert.equal(r.commits[0].sha, sha(1)); assert.equal(r.status, 'ahead'); assert.equal(r.merge_base, sha(0));
  assert.ok(!JSON.stringify(r).includes('secret message'), 'messages reduced to sha256');
  await assert.rejects(compareCommits('susanbeasles/demo', sha(1), sha(2), 'tok', compareApi({ total: MAX_COMPARE_COMMITS + 1, pageSizes: [100] }).fetcher), /compare_too_many_commits/);
  await assert.rejects(compareCommits('susanbeasles/demo', sha(1), sha(2), 'tok', compareApi({ total: 300, pageSizes: [100, 100, 50] }).fetcher), /compare_incomplete/, 'GitHub stopped short of total_commits');
  await assert.rejects(compareCommits('susanbeasles/demo', sha(1), sha(2), 'tok', compareApi({ total: 1, pageSizes: [1], files: 50 }).fetcher, null, { maxBytes: 20_000 }), /compare_too_large/);
  const budget = { api: 1 };
  await assert.rejects(compareCommits('susanbeasles/demo', sha(1), sha(2), 'tok', compareApi({ total: 150, pageSizes: [100, 50] }).fetcher, budget), /deferred/);
  await assert.rejects(compareCommits('susanbeasles/demo', sha(1), sha(2), 'tok', async () => new Response(null, { status: 302, headers: { location: 'https://evil.invalid' } })), /github_redirect_refused/);
  for (const [b, h] of [['..', sha(2)], [sha(1), 'main'], ['a//b', sha(2)]]) await assert.rejects(compareCommits('susanbeasles/demo', b, h, 'tok', ok.fetcher), /bad_compare_range/);
});

test('matching refs: paginated, tolerant of ignored pagination, and incomplete when the page cap is hit', async () => {
  const refsApi = (pages, { ignorePaging = false } = {}) => async url => {
    const p = ignorePaging ? 1 : Number(new URL(url).searchParams.get('page'));
    return Response.json(pages[p - 1] ?? []);
  };
  const page = (from, n, ns = 'heads') => Array.from({ length: n }, (_, i) => ({ ref: `refs/${ns}/b${from + i}`, object: { sha: sha(from + i), type: 'commit' } }));
  let r = await listMatchingRefs('susanbeasles/demo', 'heads', 'tok', refsApi([page(0, 100), page(100, 3)]));
  assert.equal(r.refs.size, 103); assert.equal(r.complete, true);
  r = await listMatchingRefs('susanbeasles/demo', 'heads', 'tok', refsApi([page(0, 100)], { ignorePaging: true }));
  assert.equal(r.refs.size, 100); assert.equal(r.complete, true);
  r = await listMatchingRefs('susanbeasles/demo', 'heads', 'tok', refsApi([page(0, 100), page(100, 100), page(200, 100)]), null, 2);
  assert.equal(r.refs.size, 200); assert.equal(r.complete, false);
  r = await listMatchingRefs('susanbeasles/demo', 'tags', 'tok', refsApi([[...page(0, 2, 'tags'), { ref: 'refs/heads/x', object: { sha: sha(1) } }, { ref: 'refs/tags/bad', object: { sha: 'zz' } }]]));
  assert.deepEqual([...r.refs.keys()], ['refs/tags/b0', 'refs/tags/b1']);
  await assert.rejects(listMatchingRefs('susanbeasles/demo', 'pulls', 'tok', refsApi([])), /bad_ref_namespace/);
});
