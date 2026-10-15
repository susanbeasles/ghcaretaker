// Owner requirement 6: external checkpoint anchors in R2 `observatory-anchors` (write-once keys), verified on the cron
// and through a read method. Truncation is simulated by deleting tail rows in the SQLite fake (after dropping the
// append-only triggers, as an attacker with raw storage access would), rewriting by editing a middle entry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { CommitLedgerCore } from '../src/commit-ledger-core.mjs';
import { ANCHOR_EVERY, anchorKey, parseAnchor } from '../src/anchors.mjs';
import { GENESIS, canonical, entryHash } from '../src/chain.mjs';
import { sha256Hex } from '../src/bytes.mjs';
import { sqlStorage, memoryR2, secret, clock, sha } from './fakes.mjs';

function eventLedger(extraEnv = {}) {
  const now = clock(), storage = sqlStorage(), ANCHORS = memoryR2(), alerts = [];
  const env = { EVENTS: memoryR2(), ANCHORS, ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook'), ...extraEnv };
  const core = new EventLedgerCore(storage, env, { now, fetcher: async (_u, init) => { alerts.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); } });
  return { core, storage, ANCHORS, alerts, now, env };
}
async function append(core, n = 1) {
  for (let i = 0; i < n; i++) {
    const delivery_id = crypto.randomUUID(), body_sha256 = (await sha256Hex(delivery_id)), r = core.begin({ delivery_id, body_sha256 });
    await core.commit({ delivery_id, token: r.token, event: 'push', body_sha256 });
  }
}
const cron = async core => { await core.requestCron(['anchor']); await core.alarm(); };
const text = (bucket, key) => new TextDecoder().decode(bucket.objects.get(key).bytes);
const anchorKeys = (bucket, ledger = 'event') => [...bucket.objects.keys()].filter(k => k.startsWith(`anchors/${ledger}/`)).sort();
const findingKinds = core => core.findings().items.map(f => f.kind + ':' + f.detail.reason).sort();
const drop = (storage, table) => { storage.db.exec(`DROP TRIGGER IF EXISTS ${table}_no_update`); storage.db.exec(`DROP TRIGGER IF EXISTS ${table}_no_delete`); };

test('cron anchors: canonical write-once record per advanced head, chained by prev_anchor_hash, verified by the read method', async () => {
  const { core, ANCHORS, now } = eventLedger();
  await append(core, 3); await cron(core);
  const k3 = anchorKey('event', 3);
  assert.deepEqual(anchorKeys(ANCHORS), ['anchors/event/0000000000000003.json']); assert.equal(k3, 'anchors/event/0000000000000003.json');
  const t3 = text(ANCHORS, k3), a3 = parseAnchor(t3, k3);
  assert.deepEqual(a3, { ledger: 'event', seq: 3, head_hash: core.head().entry_hash, entry_count: 3, created_at: '2026-10-15T12:00:00.000Z', prev_anchor_hash: GENESIS });
  assert.equal(t3, canonical(a3)); assert.equal(ANCHORS.objects.get(k3).customMetadata.anchor_hash, await sha256Hex(t3));
  now.advance(3_600_000); await cron(core);
  assert.equal(anchorKeys(ANCHORS).length, 1, 'no new entries: no new anchor');
  await append(core, 2); now.advance(3_600_000); await cron(core);
  const a5 = parseAnchor(text(ANCHORS, anchorKey('event', 5)), anchorKey('event', 5));
  assert.equal(a5.prev_anchor_hash, await sha256Hex(t3), 'anchors chain');
  assert.equal(a5.entry_count, 5);
  const v = await core.verifyAnchor();
  assert.equal(v.ok, true); assert.equal(v.anchor.seq, 5); assert.deepEqual(v.problems, []); assert.equal(v.blocked, null);
  assert.equal(core.head().last_anchor.seq, 5);
  // The put is create-only: replaying the same write never replaces an anchor.
  const put = ANCHORS.put.bind(ANCHORS), seen = [];
  ANCHORS.put = (key, value, options) => { seen.push(options.onlyIf.get('if-none-match')); return put(key, value, options); };
  await append(core, 1); now.advance(3_600_000); await cron(core);
  assert.deepEqual(seen, ['*']);
});

test(`every ${ANCHOR_EVERY} entries an anchor is written without waiting for the cron`, async () => {
  const { core, ANCHORS } = eventLedger();
  await append(core, ANCHOR_EVERY - 1); await core.alarm();
  assert.equal(anchorKeys(ANCHORS).length, 0);
  await append(core, 1); await core.alarm();
  assert.deepEqual(anchorKeys(ANCHORS), [anchorKey('event', ANCHOR_EVERY)]);
});

test('tail truncation: deleting the newest rows is a critical tail_truncation finding and alert; anchoring stops', async () => {
  const { core, storage, ANCHORS, alerts, now } = eventLedger();
  await append(core, 5); await cron(core);
  drop(storage, 'events'); storage.db.exec('DELETE FROM events WHERE seq > 3');
  assert.equal((await core.verify()).ok, true, 'the remaining chain is internally consistent: the chain alone cannot tell');
  const read = await core.verifyAnchor();
  assert.equal(read.ok, false); assert.deepEqual(read.problems.map(p => p.code + ':' + p.reason), ['tail_truncation:head_below_anchor']);
  assert.equal(core.findings().items.length, 0, 'the read method only reports');
  now.advance(3_600_000); await cron(core); await core.alarm();
  assert.deepEqual(findingKinds(core), ['tail_truncation:head_below_anchor']);
  const alert = alerts.find(a => a.code === 'tail_truncation');
  assert.equal(alert.severity, 'critical'); assert.equal(alert.detail.anchor_seq, 5); assert.equal(alert.detail.head_seq, 3);
  assert.ok(core.head().anchor_blocked);
  // New entries refill the seq range: now the entry at the anchored seq no longer matches, and nothing is re-anchored.
  await append(core, 4); now.advance(3_600_000); await cron(core);
  assert.deepEqual(anchorKeys(ANCHORS), [anchorKey('event', 5)], 'a truncated ledger is never blessed by a new anchor');
  assert.ok(findingKinds(core).includes('anchor_mismatch:head_hash'));
  // Wiping the local anchor table as well does not hide the external anchor.
  storage.db.exec('DELETE FROM anchors'); storage.db.exec("DELETE FROM meta WHERE key LIKE 'anchor%'");
  assert.equal((await core.verifyAnchor()).ok, false);
});

test('a middle entry rewritten and the chain recomputed after it: anchor_mismatch at the anchored head', async () => {
  const { core, storage } = eventLedger();
  await append(core, 5); await cron(core);
  drop(storage, 'events');
  let prev = storage.sql.exec('SELECT entry_hash FROM events WHERE seq = 1').toArray()[0].entry_hash;
  for (let seq = 2; seq <= 5; seq++) {
    const row = storage.sql.exec('SELECT * FROM events WHERE seq = ?', seq).toArray()[0];
    const edited = { ...row, body_sha256: seq === 2 ? 'f'.repeat(64) : row.body_sha256, prev_hash: prev };
    edited.entry_hash = await entryHash(edited);
    storage.sql.exec('UPDATE events SET body_sha256 = ?, prev_hash = ?, entry_hash = ? WHERE seq = ?', edited.body_sha256, edited.prev_hash, edited.entry_hash, seq);
    prev = edited.entry_hash;
  }
  assert.equal((await core.verify()).ok, true, 'a recomputed chain verifies on its own');
  await cron(core);
  assert.deepEqual(findingKinds(core), ['anchor_mismatch:head_hash']);
});

test('a middle entry rewritten without recomputing the chain: anchor_mismatch chain_break with the first break', async () => {
  const { core, storage } = eventLedger();
  await append(core, 5); await cron(core);
  drop(storage, 'events'); storage.sql.exec("UPDATE events SET event = 'release' WHERE seq = 2");
  await cron(core);
  const [f] = core.findings().items;
  assert.equal(f.kind, 'anchor_mismatch'); assert.equal(f.detail.reason, 'chain_break'); assert.deepEqual(f.detail.first_break, { seq: 2, reason: 'entry_hash_mismatch' });
});

test('missing rows below the anchor, a removed anchor object and a replaced anchor are each detected', async () => {
  let ctx = eventLedger();
  await append(ctx.core, 5); await cron(ctx.core);
  drop(ctx.storage, 'events'); ctx.storage.db.exec('DELETE FROM events WHERE seq = 2'); await append(ctx.core, 1);
  assert.ok((await ctx.core.verifyAnchor()).problems.some(p => p.code === 'anchor_mismatch' && p.reason === 'entries_missing'));

  ctx = eventLedger();
  await append(ctx.core, 2); await cron(ctx.core);
  ctx.ANCHORS.objects.delete(anchorKey('event', 2));
  assert.deepEqual((await ctx.core.verifyAnchor()).problems.map(p => p.reason), ['anchor_missing']);

  ctx = eventLedger();
  await append(ctx.core, 2); await cron(ctx.core); await append(ctx.core, 2); ctx.now.advance(3_600_000); await cron(ctx.core);
  ctx.storage.db.exec("DELETE FROM meta WHERE key = 'anchor_chain_verified'");
  const k = anchorKey('event', 2), forged = { ...JSON.parse(text(ctx.ANCHORS, k)), created_at: '2026-10-15T12:30:00.000Z' };
  ctx.ANCHORS.objects.set(k, { bytes: new TextEncoder().encode(canonical(forged)), customMetadata: {} }); // an account admin rewrote it
  const v = await ctx.core.verifyAnchor();
  assert.deepEqual(v.problems.map(p => p.reason), ['anchor_chain']); assert.equal(v.problems[0].chain_reason, 'prev_anchor_hash_mismatch');
});

test('an existing object at the next anchor key that says something else is a conflict, never overwritten', async () => {
  const { core, ANCHORS } = eventLedger();
  await append(core, 2);
  const k = anchorKey('event', 2), squatter = canonical({ ledger: 'event', seq: 2, head_hash: 'e'.repeat(64), entry_count: 2, created_at: '2026-10-15T11:00:00.000Z', prev_anchor_hash: GENESIS });
  ANCHORS.objects.set(k, { bytes: new TextEncoder().encode(squatter), customMetadata: {} });
  await cron(core);
  assert.equal(text(ANCHORS, k), squatter);
  assert.ok(findingKinds(core).some(x => x.startsWith('anchor_mismatch:')));
});

test('commit ledgers are anchored as commit-<repo_id>; their tail truncation is a finding of that repository', async () => {
  const now = clock(), storage = sqlStorage(), ANCHORS = memoryR2(), alerts = [];
  const env = { EVENTS: memoryR2(), ANCHORS, ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook') };
  const core = new CommitLedgerCore(storage, env, { now, fetcher: async (_u, init) => { alerts.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); },
    mintToken: async () => ({ token: 't', expires_at: now() + 3_600_000 }), hasPromotionTag: async () => true,
    commitDetails: async (_f, s) => ({ sha: s, tree: sha(900), parents: [sha(1)], author_name: 'a', author_date: 'd', committer_name: 'c', committer_date: 'd', message_sha256: 'c'.repeat(64), verified: true, verification_reason: 'valid' }) });
  await core.ingest({ type: 'push', repo_id: 42, full_name: 'susanbeasles/demo', installation_id: 7, delivery_id: crypto.randomUUID(), ref: 'refs/heads/feature',
    before: sha(1), after: sha(3), created: false, deleted: false, forced: false, pusher: 'x', commits: [sha(2), sha(3)], commits_truncated: false });
  await core.alarm();
  assert.deepEqual(await core.requestCron(['anchor']), { accepted: true, tasks: ['anchor'] }); await core.alarm();
  assert.deepEqual(anchorKeys(ANCHORS, 'commit-42'), [anchorKey('commit-42', 3)]);
  assert.equal((await core.verifyAnchor()).ok, true);
  drop(storage, 'entries'); storage.db.exec('DELETE FROM entries WHERE seq = 3');
  now.advance(3_600_000); await core.requestCron(['anchor']); await core.alarm(); await core.alarm();
  const f = core.findings().items.find(x => x.kind === 'tail_truncation');
  assert.ok(f); assert.equal(f.entry_seq, 3); assert.equal(f.detail.ledger, 'commit-42');
  assert.ok(alerts.some(a => a.code === 'tail_truncation' && a.repo_id === 42 && a.severity === 'critical'));
  // An empty ledger (never ingested) has nothing to anchor.
  const empty = new CommitLedgerCore(sqlStorage(), env, { now });
  assert.deepEqual(await empty.requestCron(['anchor']), { accepted: false, reason: 'empty_ledger' });
});

test('secondary anchor seam: when BACKUP_ANCHOR is bound each anchor is sent and retried until accepted', async () => {
  const sent = [];
  let accept = false;
  const { core, storage, now } = eventLedger({ BACKUP_ANCHOR: { anchor: async r => { sent.push(r); return accept ? { ok: true } : { ok: false, code: 'b2_unavailable' }; } } });
  await append(core, 2); await cron(core); await core.alarm();
  assert.equal(sent.length, 1);
  assert.deepEqual(Object.keys(sent[0]).sort(), ['anchor_hash', 'created_at', 'entry_count', 'head_hash', 'key', 'ledger', 'prev_anchor_hash', 'seq']);
  let row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'anchor_backup'").toArray()[0];
  assert.equal(row.done_at, null); assert.equal(row.last_error, 'backup_anchor_b2_unavailable');
  accept = true; now.advance(3_600_000); await core.alarm();
  row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'anchor_backup'").toArray()[0];
  assert.ok(row.done_at);
});

test('anchor storage unavailable: retried in five minutes, no finding (an outage is not evidence)', async () => {
  const { core, ANCHORS, now } = eventLedger();
  await append(core, 2); ANCHORS.fail = true; const list = ANCHORS.list; ANCHORS.list = async () => { throw new Error('r2 down'); };
  await cron(core);
  assert.equal(core.findings().items.length, 0);
  assert.equal(Number(core.meta('cron_due:anchor')), now() + 300_000);
  ANCHORS.fail = false; ANCHORS.list = list; now.advance(300_000); await core.alarm();
  assert.deepEqual(anchorKeys(ANCHORS), [anchorKey('event', 2)]);
});
