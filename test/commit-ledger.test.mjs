import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CommitLedgerCore, commitMirrorKey } from '../src/commit-ledger-core.mjs';
import { refFindings, mainCommitFindings, promotionTagPrefix } from '../src/integrity.mjs';
import { canonical } from '../src/chain.mjs';
import { sqlStorage, memoryR2, secret, clock, sha } from './fakes.mjs';

const ZERO = '0'.repeat(40), REPO = 42;

function details(n, o = {}) {
  return { sha: sha(n), tree: sha(1000 + n), parents: [sha(n - 1)], author_name: 'Author', author_date: '2026-10-15T11:00:00Z', committer_name: 'GitHub',
    committer_date: '2026-10-15T11:00:00Z', message_sha256: 'c'.repeat(64), verified: true, verification_reason: 'valid', ...o };
}

function setup({ overrides = {}, alertStatus = () => 204, tagged = () => false, apiFails = () => false } = {}) {
  const now = clock(), storage = sqlStorage(), EVENTS = memoryR2(), alerts = [], lookups = [], tagChecks = [];
  const env = { PROMOTER_ACTOR_ID: '99', EVENTS, ALERT_WEBHOOK_URL: secret('https://alerts.invalid/caretaker') };
  const core = new CommitLedgerCore(storage, env, {
    now,
    fetcher: async (url, init) => { const status = alertStatus(alerts.length); alerts.push({ url, status, body: JSON.parse(init.body), init }); return new Response(null, { status }); },
    mintToken: async () => ({ token: 'token-for-tests', expires_at: now() + 3_600_000 }),
    commitDetails: async (fullName, s) => {
      lookups.push(s);
      if (apiFails(s)) throw Object.assign(Error('github down'), { code: 'github_http_502' });
      const n = Number(Object.entries(overrides).find(([, d]) => d.sha === s)?.[0] ?? [...Array(2000).keys()].find(i => sha(i) === s));
      return overrides[n] ?? details(n);
    },
    promotionTagTarget: async (_r, ref) => { const n = [...Array(2000).keys()].find(i => ref.endsWith(sha(i).slice(0, 12))); return n === undefined ? null : sha(n); },
    hasPromotionTag: async (_r, s) => { tagChecks.push(s); return tagged(s); },
  });
  return { core, storage, EVENTS, now, alerts, lookups, tagChecks };
}

const push = (o = {}) => ({ type: 'push', repo_id: REPO, full_name: 'susanbeasles/demo', installation_id: 7, delivery_id: crypto.randomUUID(),
  ref: 'refs/heads/main', before: sha(1), after: sha(2), created: false, deleted: false, forced: false, pusher: 'susanbeasles', commits: [sha(2)], commits_truncated: false, ...o });
const create = (ref, o = {}) => ({ type: 'create', repo_id: REPO, full_name: 'susanbeasles/demo', installation_id: 7, delivery_id: crypto.randomUUID(), ref, ref_type: 'tag', actor_id: 99, ...o });
const kinds = core => core.findings().items.map(f => f.kind).sort();
const promoTag = (n, pr = 7) => `promote/pr-${pr}-${sha(n).slice(0, 12)}`;

test('a promoted fast-forward of main: ref_update + commit entries, chained, mirrored, no findings', async () => {
  const { core, EVENTS, now, alerts, tagChecks } = setup();
  await core.ingest(push({ before: sha(1), after: sha(3), commits: [sha(2), sha(3)] }));
  await core.alarm();
  const page = core.entries(10).items.reverse();
  assert.deepEqual(page.map(e => [e.seq, e.kind]), [[1, 'ref_update'], [2, 'commit'], [3, 'commit']]);
  assert.deepEqual(page[0].data, { ref: 'refs/heads/main', before: sha(1), after: sha(3), created: false, deleted: false, forced: false, pusher: 'susanbeasles', delivery_id: page[0].delivery_id,
    size: null, listed: 2, truncated: false, complete: true, gap: false });
  assert.deepEqual(Object.keys(page[1].data).sort(), ['author_date', 'author_name', 'committer_date', 'committer_name', 'message_sha256', 'parents', 'ref', 'sha', 'source', 'tree', 'verification_reason', 'verified']);
  assert.deepEqual(page.slice(1).map(e => e.data.source), ['webhook', 'webhook']);
  assert.equal(page[1].data.sha, sha(2)); assert.equal(page[2].prev_hash, page[1].entry_hash);
  assert.equal((await core.verify()).ok, true);
  for (const e of page) assert.equal(new TextDecoder().decode(EVENTS.objects.get(commitMirrorKey(REPO, e.seq)).bytes), canonical(e));
  assert.equal(core.head().mirrored_through, 3);
  await core.ingest(create(promoTag(2), { ref: promoTag(2) }));
  await core.ingest(create(promoTag(3)));
  await core.alarm();
  now.advance(16 * 60_000); await core.alarm();
  assert.deepEqual(kinds(core), []); assert.deepEqual(tagChecks, [], 'cleared by create events, no API check needed');
  assert.equal(alerts.length, 0); assert.equal(core.head().promotions_pending, 0);
});

test('forced update and deletion of main are findings and alerts carry no secret content', async () => {
  const { core, alerts } = setup();
  await core.ingest(push({ forced: true, before: sha(5), after: sha(2) }));
  await core.ingest(push({ deleted: true, before: sha(2), after: ZERO, commits: [] }));
  await core.alarm();
  assert.deepEqual(kinds(core), ['force_push', 'main_deleted', 'main_forced_update']);
  const forced = alerts.find(a => a.body.code === 'main_forced_update');
  assert.equal(forced.url, 'https://alerts.invalid/caretaker'); assert.equal(forced.init.redirect, 'manual'); assert.ok(forced.init.signal);
  assert.deepEqual({ ...forced.body, finding_id: 0, detected_at: 0, delivery_id: 0 }, { schema: 'ghcaretaker-alert/v1', type: 'integrity_finding', code: 'main_forced_update', severity: 'critical',
    repo_id: REPO, repo: 'susanbeasles/demo', ref: 'refs/heads/main', sha: sha(2), delivery_id: 0, entry_seq: 1, finding_id: 0, detail: { before: sha(5), after: sha(2) }, detected_at: 0 });
  for (const a of alerts) assert.ok(!JSON.stringify(a.body).includes('token-for-tests'));
});

test('unverified main commit and merge commit on main are findings; the same on a branch is not', async () => {
  const { core } = setup({ overrides: { 2: details(2, { verified: false, verification_reason: 'unsigned' }), 3: details(3, { parents: [sha(2), sha(9)] }) } });
  await core.ingest(push({ ref: 'refs/heads/feature', commits: [sha(2), sha(3)], after: sha(3) }));
  await core.alarm();
  assert.deepEqual(kinds(core), []);
  // The same commits fast-forward main later: already in the ledger (no new commit entries) but still judged on main.
  await core.ingest(push({ before: sha(1), after: sha(3), commits: [sha(2), sha(3)] }));
  await core.alarm();
  assert.equal(core.entries(10).items.filter(e => e.kind === 'commit').length, 2, 'one entry per commit');
  const f = core.findings().items;
  assert.deepEqual(f.map(x => x.kind).sort(), ['main_commit_multiple_parents', 'main_commit_unverified']);
  assert.deepEqual(f.find(x => x.kind === 'main_commit_unverified').detail, { reason: 'unsigned' });
  assert.equal(f.find(x => x.kind === 'main_commit_unverified').entry_seq, 2);
});

test('main commits without authenticated creation evidence are flagged despite name-only API hints', async () => {
  const { core, now, tagChecks, alerts } = setup({ tagged: s => s === sha(3) });
  await core.ingest(push({ before: sha(1), after: sha(2), commits: [sha(2)] }));
  await core.ingest(push({ before: sha(2), after: sha(3), commits: [sha(3)] }));
  await core.alarm();
  now.advance(14 * 60_000); await core.alarm();
  assert.deepEqual(tagChecks, [], 'not before 15 minutes');
  now.advance(2 * 60_000); await core.alarm();
  assert.deepEqual(tagChecks, [], 'name-only API lookup cannot establish creator');
  assert.deepEqual(kinds(core), ['main_commit_missing_promotion_tag', 'main_commit_missing_promotion_tag']);
  assert.ok(core.findings().items.some(f => f.sha === sha(2)));
  assert.ok(alerts.some(a => a.body.code === 'main_commit_missing_promotion_tag'));
  // A late create event does not erase an already-raised finding.
  await core.ingest(create(promoTag(2))); await core.alarm();
  assert.deepEqual(kinds(core), ['main_commit_missing_promotion_tag', 'main_commit_missing_promotion_tag']);
});

test('a promote tag seen before the main push (out-of-order delivery) satisfies the check immediately', async () => {
  const { core, now, tagChecks } = setup();
  await core.ingest(create(promoTag(2)));
  await core.ingest(push());
  await core.alarm(); now.advance(20 * 60_000); await core.alarm();
  assert.deepEqual(kinds(core), []); assert.deepEqual(tagChecks, []);
  // A non-matching or malformed tag name does not clear anything.
  assert.equal(promotionTagPrefix('promote/pr-7-' + sha(2).slice(0, 11)), null);
  assert.equal(promotionTagPrefix('refs/tags/promote/pr-7-' + sha(2).slice(0, 12)), sha(2).slice(0, 12));
  assert.equal(promotionTagPrefix('promote/pr-0-' + sha(2).slice(0, 12)), null);
});

test('tags: forced update, in-place move, deletion and re-creation elsewhere are findings', async () => {
  const { core } = setup();
  const tag = 'refs/tags/v1.0.0';
  await core.ingest(push({ ref: tag, created: true, before: ZERO, after: sha(10), commits: [] }));
  await core.alarm();
  assert.deepEqual(kinds(core), []);
  await core.ingest(push({ ref: tag, before: sha(10), after: sha(11), forced: true, commits: [] }));
  await core.ingest(push({ ref: tag, deleted: true, before: sha(11), after: ZERO, commits: [] }));
  await core.ingest(push({ ref: tag, created: true, before: ZERO, after: sha(12), commits: [] }));
  await core.alarm();
  assert.deepEqual(kinds(core), ['force_push', 'tag_deleted', 'tag_forced_update', 'tag_moved', 'tag_moved']);
  const moved = core.findings().items.filter(f => f.kind === 'tag_moved').map(f => f.detail);
  assert.deepEqual(moved.sort((a, b) => a.to.localeCompare(b.to)), [{ from: sha(10), to: sha(11) }, { from: sha(11), to: sha(12) }].sort((a, b) => a.to.localeCompare(b.to)));
});

test('alert delivery failure is retried by alarm until delivered, never dropped', async () => {
  const { core, now, alerts, storage } = setup({ alertStatus: n => (n < 3 ? 503 : 204), tagged: () => true });
  // One finding (main_deleted), so exactly one alert row is retried; a forced push now raises two findings.
  await core.ingest(push({ deleted: true, before: sha(2), after: ZERO, commits: [] }));
  await core.alarm();
  assert.equal(alerts.length, 1);
  let row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'alert'").toArray()[0];
  assert.equal(row.done_at, null); assert.equal(row.attempts, 1); assert.equal(row.last_error, 'alert_http_503');
  assert.ok(core.storage.alarmAt >= now() + 30_000, 'retry scheduled with backoff');
  await core.alarm(); assert.equal(alerts.length, 1, 'not retried before backoff elapses');
  for (let i = 0; i < 3; i++) { now.advance(3_600_000); await core.alarm(); }
  assert.equal(alerts.length, 4);
  row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'alert'").toArray()[0];
  assert.ok(row.done_at); assert.equal(row.attempts, 3);
  assert.equal(new Set(alerts.map(a => a.body.finding_id)).size, 1, 'same alert each time');
});

test('a missing or non-https alert URL is a retried failure, not a silent drop', async () => {
  const { core, storage, alerts } = setup();
  core.env.ALERT_WEBHOOK_URL = secret('http://alerts.invalid/plain');
  await core.ingest(push({ forced: true })); await core.alarm();
  assert.equal(alerts.length, 0);
  const row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'alert'").toArray()[0];
  assert.equal(row.last_error, 'alert_url_not_https'); assert.equal(row.done_at, null);
});

test('GitHub API failure blocks the inbox head and preserves order; nothing is appended until details are known', async () => {
  let down = true;
  const { core, now } = setup({ apiFails: () => down });
  const first = push({ before: sha(1), after: sha(2), commits: [sha(2)] }), second = push({ before: sha(2), after: sha(3), commits: [sha(3)] });
  await core.ingest(first); await core.ingest(second);
  await core.alarm();
  assert.equal(core.head().seq, 0); assert.equal(core.head().inbox.pending, 2); assert.equal(core.head().inbox.max_attempts, 1);
  down = false; now.advance(60_000); await core.alarm();
  const entries = core.entries(10).items.reverse();
  assert.deepEqual(entries.map(e => e.delivery_id), [first.delivery_id, first.delivery_id, second.delivery_id, second.delivery_id]);
  assert.equal((await core.verify()).ok, true);
});

test('commit unavailable upstream is recorded fail-closed and flagged on main', async () => {
  const { core } = setup({ overrides: { 2: { ...details(2), tree: null, parents: null, verified: false, verification_reason: 'commit_unavailable_404' } } });
  await core.ingest(push()); await core.alarm();
  assert.deepEqual(core.findings().items.map(f => [f.kind, f.detail.reason]), [['main_commit_unverified', 'commit_unavailable_404']]);
});

test('ingest is idempotent per delivery and refuses a different repository', async () => {
  const { core } = setup();
  const item = push();
  assert.deepEqual(await core.ingest(item), { accepted: true });
  assert.deepEqual(await core.ingest(item), { accepted: true });
  await core.alarm();
  assert.equal(core.head().seq, 2);
  await assert.rejects(core.ingest({ ...push(), repo_id: 43 }), /repo_mismatch/);
  for (const bad of [{ ...push(), commits: ['nothex'] }, { ...push(), delivery_id: 'x' }, { ...push(), type: 'release' }, { ...push(), before: 'zz' }]) await assert.rejects(core.ingest(bad), /bad_request/);
});

test('commit ledger tamper is detected by verify; the R2 mirror is never rewritten', async () => {
  const { core, storage, EVENTS } = setup();
  await core.ingest(push({ commits: [sha(2)] })); await core.alarm();
  const mirrored = EVENTS.objects.get(commitMirrorKey(REPO, 2)).bytes;
  assert.throws(() => storage.sql.exec("UPDATE entries SET data = '{}' WHERE seq = 2"), /append only/);
  storage.db.exec('DROP TRIGGER entries_no_update');
  const row = storage.sql.exec('SELECT data FROM entries WHERE seq = 2').toArray()[0];
  storage.db.exec("UPDATE entries SET data = '" + row.data.replace('"verified":true', '"verified":false') + "' WHERE seq = 2");
  assert.deepEqual((await core.verify()).first_break, { seq: 2, reason: 'entry_hash_mismatch' });
  assert.deepEqual(EVENTS.objects.get(commitMirrorKey(REPO, 2)).bytes, mirrored);
  assert.equal(JSON.parse(new TextDecoder().decode(mirrored)).data.verified, true, 'mirror keeps the original');
});

test('pure rules match the ADR list exactly', () => {
  const u = (o) => ({ ref: 'refs/heads/main', before: sha(1), after: sha(2), created: false, deleted: false, forced: false, ...o });
  assert.deepEqual(refFindings(u({}), sha(1)), []);
  assert.deepEqual(refFindings(u({ ref: 'refs/heads/feature', forced: true }), null), [], 'forced push to a branch is not a finding');
  assert.deepEqual(refFindings(u({ ref: 'refs/heads/feature', deleted: true }), null), []);
  assert.deepEqual(refFindings(u({ ref: 'refs/tags/x', created: true, before: ZERO }), null), [], 'new tag');
  assert.deepEqual(refFindings(u({ ref: 'refs/tags/x', created: true, before: ZERO }), sha(2)), [], 'same target re-created');
  assert.deepEqual(mainCommitFindings(details(4)), []);
  assert.deepEqual(mainCommitFindings({ ...details(4), verified: undefined }).map(f => f.kind), ['main_commit_unverified']);
});

for (const beforeMain of [true, false]) test('promotion actor and full target are required, order=' + beforeMain, async () => {
  for (const scenario of ['wrong_actor', 'wrong_target', 'unconfigured', 'valid']) {
    const { core, now } = setup();
    if (scenario === 'unconfigured') delete core.env.PROMOTER_ACTOR_ID;
    core.deps.promotionTagTarget = async () => scenario === 'wrong_target' ? sha(3) : sha(2);
    const event = create(promoTag(2), { actor_id: scenario === 'wrong_actor' ? 100 : 99 });
    if (beforeMain) await core.ingest(event);
    await core.ingest(push());
    if (!beforeMain) await core.ingest(event);
    await core.alarm(); now.advance(16 * 60_000); await core.alarm();
    assert.equal(core.head().promotions_pending, 0);
    assert.equal(kinds(core).includes('main_commit_missing_promotion_tag'), scenario !== 'valid', scenario);
  }
});

test('absent promotion ref is untrusted evidence and cannot block later pushes', async()=>{
 const {core,now}=setup();core.deps.promotionTagTarget=async()=>{throw Object.assign(Error('gone'),{code:'github_http_404',status:404});};
 await core.ingest(create(promoTag(2)));await core.ingest(push());await core.alarm();
 assert.equal(core.storage.sql.exec('SELECT COUNT(*) AS n FROM inbox').toArray()[0].n,0);
 assert.ok(core.entries(10).items.some(e=>e.kind==='commit'));
 now.advance(16*60000);await core.alarm();assert.ok(kinds(core).includes('main_commit_missing_promotion_tag'));
});
test('transient promotion lookup preserves ordered retry then recovers',async()=>{
 const {core,now}=setup();let calls=0;core.deps.promotionTagTarget=async()=>{if(++calls===1)throw Object.assign(Error('down'),{code:'github_http_502',status:502});return sha(2);};
 await core.ingest(create(promoTag(2)));await core.ingest(push());await core.alarm();assert.equal(core.storage.sql.exec('SELECT COUNT(*) AS n FROM inbox').toArray()[0].n,2);
 now.advance(3600000);await core.alarm();assert.equal(core.storage.sql.exec('SELECT COUNT(*) AS n FROM inbox').toArray()[0].n,0);assert.equal(core.head().promotions_pending,0);
});

test('verified promotion lookup uses a SHA and actor index',()=>{
 const {core}=setup();
 const plan=core.sql.exec('EXPLAIN QUERY PLAN SELECT tag FROM verified_promote_tags WHERE sha = ? AND actor_id = ? LIMIT 1',sha(2),99).toArray();
 assert.ok(plan.some(r=>/USING (?:COVERING )?INDEX verified_promote_tags_sha_actor/.test(r.detail)),JSON.stringify(plan));
 const seek=core.sql.exec('EXPLAIN QUERY PLAN SELECT tag FROM verified_promote_tags WHERE sha = ? AND actor_id = ? AND tag > ? ORDER BY tag LIMIT 1',sha(2),99,'').toArray();
 assert.ok(seek.some(r=>r.detail.includes('USING COVERING INDEX verified_promote_tags_sha_actor_tag')),JSON.stringify(seek));
 assert.ok(seek.every(r=>!r.detail.includes('TEMP B-TREE')),JSON.stringify(seek));
});

test('promotion create deferral preserves ordered inbox even past terminal retry age',async()=>{
 const {core,now}=setup();let calls=0,mints=0;
 delete core.deps.promotionTagTarget;
 core.deps.mintToken=async()=>{mints++;return {token:'synthetic',expires_at:now()+3600000};};
 core.fetcher=async()=>Response.json({object:++calls%2?{type:'tag',sha:sha(500)}:{type:'commit',sha:sha(2)}});
 await core.ingest(create(promoTag(2)));await core.ingest(create('ordinary-branch',{ref_type:'branch'}));
 core.sql.exec('UPDATE inbox SET attempts = 11, queued_at = ?',now()-25*3600000);
 await core.processInbox({api:0});assert.equal(mints,0);assert.equal(calls,0);
 const budget={api:2};await core.processInbox(budget);
 assert.equal(mints,1);assert.equal(calls,1);assert.equal(budget.api,0);
 const pending=core.sql.exec('SELECT attempts, last_error FROM inbox ORDER BY id').toArray();
 assert.equal(pending.length,2);assert.equal(pending[0].attempts,11);assert.equal(pending[0].last_error,null);
 calls=0;await core.processInbox({api:2});
 assert.equal(mints,1,'cached token costs no request');assert.equal(calls,2);
 assert.equal(core.sql.exec('SELECT COUNT(*) AS n FROM inbox').one().n,0);
 assert.equal(core.sql.exec('SELECT COUNT(*) AS n FROM verified_promote_tags').one().n,1);
});

test('promotion checks share dereference budget and defer without retry penalties or false findings',async()=>{
 const {core,now}=setup();await core.ingest(push());await core.processInbox({api:40});
 core.sql.exec('INSERT INTO verified_promote_tags (tag,sha,actor_id,delivery_id) VALUES (?,?,?,?)',promoTag(2),sha(2),99,crypto.randomUUID());
 now.advance(16*60000);delete core.deps.promotionTagTarget;let calls=0;
 core.fetcher=async()=>Response.json({object:++calls%2?{type:'tag',sha:sha(500)}:{type:'commit',sha:sha(2)}});
 const budget={api:1};await core.checkPromotions(budget);
 assert.equal(calls,1);assert.equal(budget.api,0);
 const row=core.sql.exec('SELECT status,attempts,last_error FROM promotions WHERE sha = ?',sha(2)).one();
 assert.deepEqual(row,{status:'pending',attempts:0,last_error:null});assert.deepEqual(kinds(core),[]);
 calls=0;await core.checkPromotions({api:2});
 assert.equal(core.sql.exec('SELECT status FROM promotions WHERE sha = ?',sha(2)).one().status,'satisfied');
});

for (const validLast of [true,false]) test('promotion evidence resumes beyond one alarm budget; valid last='+validLast,async()=>{
 const {core,now}=setup();await core.ingest(push());await core.processInbox({api:40});
 const refs=Array.from({length:46},(_,i)=>promoTag(2,100+i));
 for(const ref of refs)core.sql.exec('INSERT INTO verified_promote_tags (tag,sha,actor_id,delivery_id) VALUES (?,?,?,?)',ref,sha(2),99,crypto.randomUUID());
 now.advance(16*60000);delete core.deps.promotionTagTarget;const seen=[];
 core.fetcher=async url=>{seen.push(url);return Response.json({object:{type:'commit',sha:validLast&&url.endsWith(refs.at(-1))?sha(2):sha(3)}});};
 await core.checkPromotions({api:40});assert.equal(seen.length,40);
 assert.equal(core.sql.exec('SELECT status FROM promotions').one().status,'pending');
 assert.equal(core.sql.exec('SELECT last_tag FROM promotion_check_progress').one().last_tag,refs[39]);
 const resumed=new CommitLedgerCore(core.storage,core.env,{...core.deps,fetcher:core.fetcher});
 await resumed.checkPromotions({api:40});
 assert.equal(core.sql.exec('SELECT status FROM promotions').one().status,validLast?'satisfied':'flagged');
 assert.equal(seen.length,46);assert.equal(new Set(seen).size,46,'completed lookups are not repeated');
 assert.equal(core.sql.exec('SELECT COUNT(*) AS n FROM promotion_check_progress').one().n,0);
 assert.equal(core.sql.exec('SELECT attempts FROM promotions').one().attempts,0);
 assert.deepEqual(kinds(core),validLast?[]:['main_commit_missing_promotion_tag']);
});

const PROMOTION_MIGRATION = 'migration:exact-promotion-evidence:v1';

test('upgrade reopens legacy satisfied provenance once without rewriting ledger history',async()=>{
 const {core,storage,now}=setup();
 await core.ingest(push({after:sha(3),commits:[sha(2),sha(3)]}));await core.processInbox({api:40});
 for(const [n,source] of [[2,'create_event:'+promoTag(2)],[3,'api']]) {
  core.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = ?, resolved_at = ?, attempts = 7, last_error = 'old', next_check_at = ? WHERE sha = ?",source,core.iso(now()),now()+86400000,sha(n));
 }
 core.sql.exec('INSERT INTO promote_tags (tag,prefix,delivery_id,seen_at) VALUES (?,?,?,?)',promoTag(2),sha(2).slice(0,12),crypto.randomUUID(),core.iso(now()));
 core.sql.exec('INSERT INTO verified_promote_tags (tag,sha,actor_id,delivery_id) VALUES (?,?,?,?)',promoTag(3),sha(3),99,crypto.randomUUID());
 core.sql.exec('INSERT INTO promotion_check_progress (sha,actor_id,last_tag) VALUES (?,?,?)',sha(3),99,'z');
 core.sql.exec('DELETE FROM meta WHERE key = ?',PROMOTION_MIGRATION);
 const entries=core.sql.exec('SELECT * FROM entries ORDER BY seq').toArray(), tags=core.sql.exec('SELECT * FROM promote_tags').toArray();
 now.advance(16*60000);
 const upgraded=new CommitLedgerCore(storage,core.env,core.deps);
 const reopened=core.sql.exec('SELECT status,resolved_by,resolved_at,attempts,last_error,next_check_at,due_at FROM promotions').toArray();
 assert.equal(reopened.length,2);
 for(const row of reopened) {
  assert.equal(row.status,'pending');assert.equal(row.resolved_by,null);assert.equal(row.resolved_at,null);
  assert.equal(row.attempts,0);assert.equal(row.last_error,null);assert.equal(row.next_check_at,now());assert.ok(row.due_at<now());
 }
 assert.equal(core.sql.exec('SELECT COUNT(*) AS n FROM promotion_check_progress').one().n,0);
 assert.deepEqual(core.sql.exec('SELECT * FROM entries ORDER BY seq').toArray(),entries);
 assert.deepEqual(core.sql.exec('SELECT * FROM promote_tags').toArray(),tags);
 await storage.deleteAlarm();await upgraded.initialize();assert.equal(storage.alarmAt,now()+1000);
 await upgraded.checkPromotions({api:40});
 assert.equal(core.sql.exec('SELECT status FROM promotions WHERE sha = ?',sha(2)).one().status,'flagged');
 assert.equal(core.sql.exec('SELECT status FROM promotions WHERE sha = ?',sha(3)).one().status,'satisfied');
 const settled=core.sql.exec('SELECT * FROM promotions ORDER BY sha').toArray();
 new CommitLedgerCore(storage,core.env,core.deps);
 assert.deepEqual(core.sql.exec('SELECT * FROM promotions ORDER BY sha').toArray(),settled);
 assert.deepEqual(core.sql.exec('SELECT * FROM entries ORDER BY seq').toArray(),entries);
});

test('fresh verified states survive reopening and migrated work respects grace and batch bounds',async()=>{
 const {core,storage,now}=setup();await core.ingest(create(promoTag(2)));await core.ingest(push());await core.processInbox({api:40});
 const verified=core.sql.exec('SELECT * FROM promotions').one();
 assert.equal(verified.status,'satisfied');new CommitLedgerCore(storage,core.env,core.deps);
 assert.deepEqual(core.sql.exec('SELECT * FROM promotions').one(),verified);
 for(let i=3;i<15;i++)core.sql.exec("INSERT INTO promotions (sha,delivery_id,due_at,next_check_at,status,resolved_by) VALUES (?,?,?,?,'satisfied','api')",sha(i),crypto.randomUUID(),now()+60000,now()+60000);
 core.sql.exec('DELETE FROM meta WHERE key = ?',PROMOTION_MIGRATION);
 const upgraded=new CommitLedgerCore(storage,core.env,core.deps);
 await upgraded.checkPromotions({api:40});assert.equal(core.sql.exec("SELECT COUNT(*) AS n FROM promotions WHERE status = 'pending'").one().n,13);
 now.advance(16*60000);await upgraded.checkPromotions({api:40});
 assert.equal(core.sql.exec("SELECT COUNT(*) AS n FROM promotions WHERE status = 'pending'").one().n,3);
 await upgraded.checkPromotions({api:40});assert.equal(core.sql.exec("SELECT COUNT(*) AS n FROM promotions WHERE status = 'pending'").one().n,0);
});

test('promotion migration marker and invalidation roll back together on failure',async()=>{
 const {core,storage}=setup();await core.ingest(push());await core.processInbox({api:40});
 core.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = 'api'");
 core.sql.exec('DELETE FROM meta WHERE key = ?',PROMOTION_MIGRATION);
 const original=storage.sql.exec;
 storage.sql.exec=(query,...args)=>{if(query.startsWith('INSERT INTO meta')&&args[0]===PROMOTION_MIGRATION)throw Error('synthetic migration write failure');return original(query,...args);};
 assert.throws(()=>new CommitLedgerCore(storage,core.env,core.deps),/synthetic migration write failure/);
 storage.sql.exec=original;
 assert.equal(core.sql.exec('SELECT status FROM promotions').one().status,'satisfied');assert.equal(core.meta(PROMOTION_MIGRATION),null);
 new CommitLedgerCore(storage,core.env,core.deps);assert.equal(core.sql.exec('SELECT status FROM promotions').one().status,'pending');
});
