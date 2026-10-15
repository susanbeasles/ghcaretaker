// Owner requirements 3, 4 and 5b: per-ref head tracking with gap findings (never a silent rewrite), truncated pushes
// completed through compare with every commit's source recorded, created/deleted/forced pushes, incomplete ranges
// retried through the outbox, and ref reconciliation against GitHub's branches and tags. GitHub is modelled by a small
// commit graph: compare(base, head) returns the commits reachable from head and not from base, oldest first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CommitLedgerCore, REF_GRACE_MS, COMPARE_INLINE_ATTEMPTS } from '../src/commit-ledger-core.mjs';
import { pushSubset, PUSH_PAYLOAD_COMMIT_CAP } from '../src/routing.mjs';
import { GitHubError } from '../src/github-app.mjs';
import { sqlStorage, memoryR2, secret, clock, sha } from './fakes.mjs';

const ZERO = '0'.repeat(40), REPO = 42, MAIN = 'refs/heads/main';

function github() {
  const parents = new Map(), number = new Map(), refs = new Map(), unverified = new Set();
  const m = {
    refs, unverified, compares: [], listings: 0, failCompare: null, complete: true,
    commit(n, ps = n > 1 ? [n - 1] : []) { parents.set(sha(n), ps.map(sha)); number.set(sha(n), n); return sha(n); },
    chain(from, to) { for (let n = from; n <= to; n++) m.commit(n); },
    ancestors(s) { const out = new Set(), stack = [s]; while (stack.length) { const x = stack.pop(); if (out.has(x) || !parents.has(x)) continue; out.add(x); stack.push(...parents.get(x)); } return out; },
    details: s => ({ sha: s, tree: sha(5000 + number.get(s)), parents: parents.get(s), author_name: 'A', author_date: '2026-10-15T10:00:00Z', committer_name: 'GitHub',
      committer_date: '2026-10-15T10:00:00Z', message_sha256: 'c'.repeat(64), verified: !unverified.has(s), verification_reason: unverified.has(s) ? 'unsigned' : 'valid' }),
    async compare(_full, base, head, _token, _fetcher, budget) {
      m.compares.push([base, head]);
      if (budget) { if (budget.api <= 0) throw Object.assign(new Error('deferred'), { code: 'deferred' }); budget.api--; }
      if (m.failCompare) throw m.failCompare;
      const b = refs.get('refs/heads/' + base) ?? base;
      if (!parents.has(b) || !parents.has(head)) throw new GitHubError('github_http_404', 404);
      const A = m.ancestors(head), B = m.ancestors(b);
      const commits = [...A].filter(x => !B.has(x)).sort((x, y) => number.get(x) - number.get(y)).map(m.details);
      const common = [...A].filter(x => B.has(x)).sort((x, y) => number.get(y) - number.get(x));
      const status = b === head ? 'identical' : A.has(b) ? 'ahead' : B.has(head) ? 'behind' : 'diverged';
      return { status, total_commits: commits.length, merge_base: common[0] ?? null, commits };
    },
    async listRefs(_full, ns) { m.listings++; return { refs: new Map([...refs].filter(([r]) => r.startsWith('refs/' + ns + '/'))), complete: m.complete }; },
  };
  return m;
}

function setup(gh = github()) {
  const now = clock(), storage = sqlStorage(), alerts = [], lookups = [];
  const env = { EVENTS: memoryR2(), ALERT_WEBHOOK_URL: secret('https://alerts.invalid/caretaker') };
  const core = new CommitLedgerCore(storage, env, {
    now, fetcher: async (url, init) => { alerts.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); },
    mintToken: async () => ({ token: 'token-for-tests', expires_at: now() + 3_600_000 }),
    commitDetails: async (_f, s) => { lookups.push(s); return gh.details(s); },
    hasPromotionTag: async () => true, compareCommits: gh.compare, listRefs: gh.listRefs,
  });
  return { core, storage, now, alerts, lookups, gh };
}

const push = (o = {}) => ({ type: 'push', repo_id: REPO, full_name: 'susanbeasles/demo', installation_id: 7, delivery_id: crypto.randomUUID(), ref: MAIN,
  before: sha(1), after: sha(2), created: false, deleted: false, forced: false, pusher: 'susanbeasles', commits: [sha(2)], commits_truncated: false,
  size: null, distinct_size: null, default_branch: 'main', truncated: false, ...o });
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => sha(a + i));
const entries = core => core.entries(100).items.reverse();
const kinds = core => core.findings().items.map(f => f.kind).sort();
const commitSet = core => new Set(core.storage.sql.exec('SELECT sha FROM commits').toArray().map(r => r.sha));
const refTable = core => Object.fromEntries(core.storage.sql.exec('SELECT ref, sha, deleted FROM refs ORDER BY ref').toArray().map(r => [r.ref, [r.sha, r.deleted]]));
const outbox = (core, kind) => core.storage.sql.exec('SELECT * FROM outbox WHERE kind = ?', kind).toArray();

test('push subset: a list of 20 or more, or fewer listed than size, is possibly truncated; deletions are not', () => {
  const repo = { id: REPO, full_name: 'susanbeasles/demo', owner: { id: 1 }, default_branch: 'main' };
  const p = o => pushSubset({ ref: MAIN, before: sha(1), after: sha(30), repository: repo, commits: [], ...o }, crypto.randomUUID());
  const list = n => range(2, n + 1).map(id => ({ id }));
  assert.equal(PUSH_PAYLOAD_COMMIT_CAP, 20);
  assert.equal(p({ commits: list(19) }).truncated, false);
  assert.equal(p({ commits: list(20) }).truncated, true);
  assert.equal(p({ commits: list(3), size: 7 }).truncated, true);
  assert.equal(p({ commits: list(3), size: 3 }).truncated, false);
  assert.equal(p({ commits: [], deleted: true, after: ZERO, size: 5 }).truncated, false);
  assert.deepEqual([p({}).default_branch, p({ repository: { ...repo, default_branch: '../x' } }).default_branch], ['main', null]);
  assert.equal(p({ size: -1 }).size, null);
});

test('truncated push: the full range comes from compare; every commit records webhook or api_compare; main rules see all', async () => {
  const gh = github(); gh.chain(1, 30); gh.unverified.add(sha(5));
  const { core, lookups } = setup(gh);
  await core.ingest(push({ before: sha(1), after: sha(30), commits: range(11, 30), size: 29, truncated: true }));
  await core.alarm();
  assert.deepEqual(gh.compares, [[sha(1), sha(30)]]);
  const all = entries(core), update = all[0].data, commits = all.slice(1);
  assert.equal(all[0].kind, 'ref_update');
  assert.deepEqual({ listed: update.listed, size: update.size, truncated: update.truncated, complete: update.complete, gap: update.gap }, { listed: 20, size: 29, truncated: true, complete: true, gap: false });
  assert.deepEqual(commits.map(e => e.data.sha), range(2, 30), 'oldest first, every commit of the range');
  assert.deepEqual(commits.map(e => e.data.source), [...Array(9).fill('api_compare'), ...Array(20).fill('webhook')]);
  assert.deepEqual(lookups, [], 'compare carried the details: no per-commit lookups');
  assert.deepEqual(kinds(core), ['main_commit_unverified'], 'a commit known only from compare is still judged on main');
  assert.equal(core.findings().items[0].sha, sha(5));
  assert.equal((await core.verify()).ok, true);
});

test('created branch with a truncated list compares against the default branch; deletions need no compare', async () => {
  const gh = github(); gh.chain(1, 10); gh.refs.set(MAIN, sha(10)); gh.commit(11, [10]); for (let n = 12; n <= 35; n++) gh.commit(n);
  const { core } = setup(gh);
  await core.ingest(push({ ref: 'refs/heads/feature', created: true, before: ZERO, after: sha(35), commits: range(16, 35), truncated: true }));
  await core.ingest(push({ ref: 'refs/heads/feature', deleted: true, before: sha(35), after: ZERO, commits: [] }));
  await core.alarm();
  assert.deepEqual(gh.compares, [['main', sha(35)]]);
  const all = entries(core);
  assert.deepEqual(all.filter(e => e.kind === 'commit').map(e => e.data.sha), range(11, 35));
  assert.equal(all.filter(e => e.kind === 'ref_update')[1].data.deleted, true);
  assert.deepEqual(refTable(core), { 'refs/heads/feature': [sha(35), 1] });
  assert.deepEqual(kinds(core), []);
});

test('forced push: force_push finding with old and new heads; commits the new head no longer contains stay in the ledger', async () => {
  const gh = github(); gh.chain(1, 5); gh.commit(51, [3]); gh.commit(52, [51]);
  const { core } = setup(gh), ref = 'refs/heads/feature';
  await core.ingest(push({ ref, before: sha(1), after: sha(5), commits: range(2, 5) }));
  await core.ingest(push({ ref, forced: true, before: sha(5), after: sha(52), commits: [sha(51), sha(52)] }));
  await core.alarm();
  const f = core.findings().items;
  assert.deepEqual(f.map(x => x.kind), ['force_push']);
  assert.deepEqual(f[0].detail, { before: sha(5), after: sha(52) }); assert.equal(f[0].ref, ref);
  for (const s of [sha(4), sha(5), sha(51), sha(52)]) assert.ok(commitSet(core).has(s), 'kept: ' + s);
  assert.deepEqual(refTable(core)[ref], [sha(52), 0]);
});

test('compare failing: retried in place, then recorded as incomplete_push and retried through the outbox until complete', async () => {
  const gh = github(); gh.chain(1, 30); gh.failCompare = new GitHubError('github_http_502', 502);
  const { core, now } = setup(gh);
  const item = push({ ref: 'refs/heads/feature', before: sha(1), after: sha(30), commits: range(11, 30), truncated: true });
  await core.ingest(item);
  for (let i = 1; i < COMPARE_INLINE_ATTEMPTS; i++) { await core.alarm(); assert.equal(core.head().seq, 0, 'inbox head waits, attempt ' + i); now.advance(3_600_000); }
  await core.alarm();
  const update = entries(core)[0].data;
  assert.equal(update.complete, false, 'never claimed complete');
  assert.deepEqual(entries(core).filter(e => e.kind === 'commit').map(e => e.data.sha), range(11, 30), 'what the payload listed is recorded');
  const [incomplete] = core.findings().items;
  assert.equal(incomplete.kind, 'incomplete_push');
  assert.deepEqual(incomplete.detail, { reason: 'github_http_502', before: sha(1), after: sha(30), listed: 20, size: null, retrying: true });
  for (let i = 0; i < 3; i++) { now.advance(3_600_000); await core.alarm(); }
  const [row] = outbox(core, 'backfill');
  assert.equal(row.done_at, null); assert.ok(row.attempts >= 3, 'still retrying'); assert.equal(row.last_error, 'github_http_502');
  assert.equal(entries(core).filter(e => e.kind === 'reconcile').length, 0);
  gh.failCompare = null; now.advance(3_600_000); await core.alarm();
  const done = entries(core).filter(e => e.kind === 'reconcile');
  assert.equal(done.length, 1);
  assert.deepEqual({ ...done[0].data, delivery_id: 0 }, { ref: 'refs/heads/feature', reason: 'push_backfill', from: sha(1), to: sha(30), deleted: false, compare_status: 'ahead', commits: 9, complete: true, delivery_id: 0 });
  assert.equal(done[0].data.delivery_id, item.delivery_id);
  assert.deepEqual(entries(core).filter(e => e.kind === 'commit' && e.data.source === 'api_compare').map(e => e.data.sha), range(2, 10));
  assert.ok(outbox(core, 'backfill')[0].done_at);
  assert.equal((await core.verify()).ok, true);
});

test('a range beyond the bounds is incomplete at once and keeps retrying; nothing ever claims it complete', async () => {
  const gh = github(); gh.chain(1, 30); gh.failCompare = new GitHubError('compare_too_many_commits');
  const { core, now } = setup(gh);
  await core.ingest(push({ before: sha(1), after: sha(30), commits: range(11, 30), truncated: true }));
  await core.alarm();
  assert.equal(entries(core)[0].data.complete, false);
  assert.ok(kinds(core).includes('incomplete_push'));
  for (let i = 0; i < 4; i++) { now.advance(3_600_000); await core.alarm(); }
  assert.ok(outbox(core, 'backfill')[0].attempts >= 4);
  assert.ok(!entries(core).some(e => e.kind === 'reconcile'));
});

test('ref gap: recorded and reconciled, never a silent rewrite; the missed range is backfilled', async () => {
  const gh = github(); gh.chain(1, 4); gh.refs.set(MAIN, sha(4));
  const { core, now } = setup(gh);
  await core.ingest(push({ before: sha(1), after: sha(2), commits: [sha(2)] }));
  await core.ingest(push({ before: sha(3), after: sha(4), commits: [sha(4)] })); // the 2 -> 3 delivery never arrived
  await core.alarm();
  const gap = core.findings().items.find(f => f.kind === 'ref_gap');
  assert.deepEqual(gap.detail, { recorded_head: sha(2), recorded_deleted: false, before: sha(3), after: sha(4) });
  assert.equal(entries(core).filter(e => e.kind === 'ref_update')[1].data.gap, true);
  assert.equal(Number(core.meta('refs_reconcile_due_at')), now() + REF_GRACE_MS);
  await core.alarm();
  assert.ok(commitSet(core).has(sha(3)), 'missed commit backfilled from compare');
  assert.equal(entries(core).find(e => e.data.sha === sha(3)).data.source, 'api_compare');
  now.advance(REF_GRACE_MS + 1000); await core.alarm();
  assert.equal(gh.listings, 2, 'reconciled against GitHub refs');
  assert.deepEqual(refTable(core)[MAIN], [sha(4), 0]);
  assert.ok(!kinds(core).includes('ref_drift'), 'explained by the backfill');
});

test('out-of-order deliveries converge to the same refs and commits as in-order ones', async () => {
  const run = async order => {
    const gh = github(); gh.chain(1, 3); gh.refs.set(MAIN, sha(1));
    const ctx = setup(gh);
    await ctx.core.ingest(push({ before: sha(1), after: sha(1), commits: [] })); // records main at 1
    ctx.now.advance(REF_GRACE_MS + 1000); await ctx.core.alarm();
    gh.refs.set(MAIN, sha(3));
    const p1 = push({ before: sha(1), after: sha(2), commits: [sha(2)] }), p2 = push({ before: sha(2), after: sha(3), commits: [sha(3)] });
    for (const p of order === 'in' ? [p1, p2] : [p2, p1]) await ctx.core.ingest(p);
    await ctx.core.alarm(); await ctx.core.alarm();
    await ctx.core.requestCron(['refs']); ctx.now.advance(REF_GRACE_MS + 1000); await ctx.core.alarm(); await ctx.core.alarm();
    return { refs: refTable(ctx.core), commits: [...commitSet(ctx.core)].sort(), kinds: kinds(ctx.core) };
  };
  const inOrder = await run('in'), outOfOrder = await run('out');
  assert.deepEqual(outOfOrder.refs, inOrder.refs);
  assert.deepEqual(inOrder.refs[MAIN], [sha(3), 0]);
  assert.deepEqual(outOfOrder.commits, inOrder.commits);
  assert.deepEqual(inOrder.kinds, []);
  assert.ok(outOfOrder.kinds.length > 0 && outOfOrder.kinds.every(k => k === 'ref_gap'), 'only gap findings: ' + outOfOrder.kinds);
});

test('ref reconciliation: baseline, missed fast-forward, unobserved deletion, tag move and history rewrite', async () => {
  const gh = github(); gh.chain(1, 4); gh.unverified.add(sha(3));
  gh.refs.set(MAIN, sha(1)); gh.refs.set('refs/heads/dev', sha(3)); gh.refs.set('refs/tags/v1', sha(1)); gh.refs.set('refs/heads/old', sha(1));
  const { core, now } = setup(gh);
  await core.ingest(push({ ref: 'refs/heads/scratch', before: sha(1), after: sha(1), commits: [] }));
  await core.alarm(); now.advance(REF_GRACE_MS + 1000);
  gh.refs.delete('refs/heads/scratch');
  await core.requestCron(['refs']); await core.alarm();
  const base = entries(core).filter(e => e.kind === 'reconcile');
  assert.deepEqual(base.filter(e => e.data.reason === 'baseline').map(e => [e.data.ref, e.data.complete]).sort(),
    [['refs/heads/dev', false], [MAIN, false], ['refs/heads/old', false], ['refs/tags/v1', false]].sort());
  assert.deepEqual(kinds(core), ['ref_drift'], 'the one ref the ledger saw and GitHub no longer has');
  assert.equal(core.findings().items[0].detail.reason, 'deleted_unobserved');
  assert.equal(core.meta('refs_baselined'), '1');

  // Changes on GitHub that no delivery told the ledger about.
  gh.refs.set(MAIN, sha(4));                                         // fast-forward 1 -> 4 (3 is unsigned)
  gh.commit(62, [2]); gh.refs.set('refs/heads/dev', sha(62));       // 3 -> 62 (parent 2): history rewritten
  gh.refs.set('refs/tags/v1', sha(2));                               // tag moved
  gh.refs.delete('refs/heads/old');                                  // deleted
  gh.refs.set('refs/heads/new', sha(2));                             // created
  now.advance(REF_GRACE_MS + 1000); await core.requestCron(['refs']); await core.alarm();
  const f = core.findings().items, by = k => f.filter(x => x.kind === k);
  assert.deepEqual(by('ref_drift').map(x => [x.ref, x.detail.reason]).sort(), [
    ['refs/heads/dev', 'history_rewritten'], ['refs/heads/new', 'created_unobserved'], ['refs/heads/old', 'deleted_unobserved'],
    ['refs/heads/scratch', 'deleted_unobserved'], ['refs/tags/v1', 'tag_target_changed']].sort());
  assert.deepEqual(by('tag_moved')[0].detail, { from: sha(1), to: sha(2) });
  assert.deepEqual(by('force_push').map(x => x.ref), ['refs/heads/dev']);
  assert.ok(!by('ref_drift').some(x => x.ref === MAIN), 'a fast-forward is explained by compare');
  assert.deepEqual(by('main_commit_unverified').map(x => x.sha), [sha(3)], 'backfilled main commits are judged');
  assert.deepEqual(refTable(core), { 'refs/heads/dev': [sha(62), 0], [MAIN]: [sha(4), 0], 'refs/heads/new': [sha(2), 0], 'refs/heads/old': [sha(1), 1], 'refs/heads/scratch': [sha(1), 1], 'refs/tags/v1': [sha(2), 0] });
  const last = JSON.parse(core.meta('refs_last_run'));
  assert.equal(last.ok, true); assert.equal(last.backfilled, 1);
  assert.equal((await core.verify()).ok, true);
  // Settled: the next run finds nothing to do and raises nothing new.
  const before = f.length; now.advance(REF_GRACE_MS + 1000); await core.requestCron(['refs']); await core.alarm();
  assert.equal(core.findings().items.length, before); assert.equal(JSON.parse(core.meta('refs_last_run')).in_sync, 6);
});

test('ref reconciliation proves nothing from a capped listing, leaves fresh refs to their webhooks and waits for the inbox', async () => {
  const gh = github(); gh.chain(1, 3); gh.refs.set(MAIN, sha(1));
  const { core, now } = setup(gh);
  await core.ingest(push({ ref: 'refs/heads/feature', before: sha(1), after: sha(2), commits: [sha(2)] }));
  await core.alarm();
  gh.complete = false;                                   // GitHub's listing hit the page cap; feature is not in it
  now.advance(REF_GRACE_MS + 1000); await core.requestCron(['refs']); await core.alarm();
  assert.ok(!kinds(core).includes('ref_drift'), 'absent from an incomplete listing is not a deletion');
  assert.equal(core.meta('refs_baselined'), null, 'no baseline from an incomplete listing');

  // A ref a delivery just moved is left alone even if GitHub's listing still shows the old head.
  gh.complete = true; gh.refs.set('refs/heads/feature', sha(2));
  await core.ingest(push({ ref: 'refs/heads/feature', before: sha(2), after: sha(3), commits: [sha(3)] }));
  await core.requestCron(['refs']); await core.alarm();
  assert.ok(!kinds(core).includes('ref_drift'));
  assert.equal(JSON.parse(core.meta('refs_last_run')).deferred_recent, 1);
  assert.deepEqual(refTable(core)['refs/heads/feature'], [sha(3), 0]);

  // Pending deliveries may explain a difference: no reconciliation while the inbox holds one.
  const blocked = setup(gh);
  blocked.core.deps.commitDetails = async () => { throw new GitHubError('github_http_502', 502); };
  await blocked.core.ingest(push({ ref: 'refs/heads/feature', before: sha(1), after: sha(2), commits: [sha(2)] }));
  await blocked.core.requestCron(['refs']);
  const listings = gh.listings; await blocked.core.alarm();
  assert.equal(gh.listings, listings, 'not listed while the inbox is not empty');
  assert.notEqual(blocked.core.meta('refs_reconcile_due_at'), null, 'still due');
});
