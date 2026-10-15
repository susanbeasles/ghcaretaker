import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { CommitLedgerCore } from '../src/commit-ledger-core.mjs';
import { canonical, link, verifyEntries, GENESIS, entryHash } from '../src/chain.mjs';
import { handleWebhook } from '../src/webhook.mjs';
import { readDelivery, recentEvents, ledgerHead, findings, commitLedger } from '../src/observatory-read.mjs';
import { ESCALATE_AT } from '../src/outbox.mjs';
import { sqlStorage, memoryR2, secret, randomSecret, clock, sign, sha, namespace } from './fakes.mjs';

const OWNER = 215839550;

function ledger(deps = {}, envOverrides = {}) {
  const now = clock(), storage = sqlStorage(), EVENTS = memoryR2();
  const env = { GITHUB_OWNER_ID: String(OWNER), EVENTS, ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook'), ...envOverrides };
  const core = new EventLedgerCore(storage, env, { now, ...deps });
  env.EVENT_LEDGER = { idFromName: n => n, get: () => core };
  return { core, storage, env, now, EVENTS };
}

async function append(core, n, extra = {}) {
  const delivery_id = crypto.randomUUID(), body_sha256 = (n.toString(16)).padStart(64, '0');
  const r = core.begin({ delivery_id, body_sha256 });
  return core.commit({ delivery_id, token: r.token, event: 'push', body_sha256, repo_id: 42, ...extra });
}

test('canonical JSON is key-sorted, whitespace-free and refuses ambiguous values', () => {
  assert.equal(canonical({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: -2 } }), '{"a":[true,null,"x"],"b":1,"c":{"y":-2,"z":"é"}}');
  for (const bad of [{ a: undefined }, { a: 1.5 }, { a: 2 ** 60 }, { a: () => 1 }]) assert.throws(() => canonical(bad));
});

test('entry_hash = sha256(prev_hash || canonical(entry without entry_hash)), genesis is 64 zeros', async () => {
  const [first, second] = await link(null, [{ x: 1 }, { x: 2 }]);
  assert.equal(first.prev_hash, GENESIS); assert.equal(second.prev_hash, first.entry_hash);
  const { createHash } = await import('node:crypto');
  const expected = createHash('sha256').update(GENESIS + canonical({ x: 1, seq: 1, prev_hash: GENESIS })).digest('hex');
  assert.equal(first.entry_hash, expected); assert.equal(await entryHash(first), expected);
  assert.equal((await verifyEntries([first, second], GENESIS, 1)).ok, true);
  assert.deepEqual((await verifyEntries([first, { ...second, x: 3 }], GENESIS, 1)).first_break, { seq: 2, reason: 'entry_hash_mismatch' });
});

test('event ledger chain verifies, rejects in-place edits, and verify reports the first break after tampering', async () => {
  const { core, storage } = ledger();
  for (let i = 1; i <= 5; i++) await append(core, i);
  assert.deepEqual(await core.verify(), { ok: true, checked: 5, first_break: null, last: { seq: 5, entry_hash: core.head().entry_hash }, from: 1, to: 5, head_seq: 5 });
  assert.throws(() => storage.sql.exec("UPDATE events SET event = 'x' WHERE seq = 3"), /append only/);
  assert.throws(() => storage.sql.exec('DELETE FROM events WHERE seq = 3'), /append only/);
  // An attacker with raw storage access drops the guard and edits a row: verify locates it.
  storage.db.exec('DROP TRIGGER events_no_update');
  storage.db.exec("UPDATE events SET body_sha256 = '" + 'f'.repeat(64) + "' WHERE seq = 3");
  const broken = await core.verify();
  assert.equal(broken.ok, false); assert.deepEqual(broken.first_break, { seq: 3, reason: 'entry_hash_mismatch' });
  assert.equal((await core.verify(1, 2)).ok, true);
  assert.equal((await core.verify(4, 5)).ok, true, 'later links are internally consistent; the break is at 3');
  // Recomputing the edited row's hash still breaks the link to its successor.
  const row = storage.sql.exec('SELECT * FROM events WHERE seq = 3').toArray()[0];
  storage.db.exec("UPDATE events SET entry_hash = '" + await entryHash(row) + "' WHERE seq = 3");
  assert.deepEqual((await core.verify()).first_break, { seq: 4, reason: 'prev_hash_mismatch' });
  storage.db.exec('DROP TRIGGER events_no_delete'); storage.db.exec('DELETE FROM events WHERE seq = 2');
  assert.deepEqual((await core.verify(1, 5)).first_break, { seq: 2, reason: 'missing_entry' });
});

test('hourly checkpoint goes to checkpoints/<seq>.json once per advanced head and is never rewritten', async () => {
  const { core, now, EVENTS } = ledger();
  await append(core, 1); await append(core, 2);
  await core.alarm();
  const first = EVENTS.json('checkpoints/2.json');
  assert.deepEqual(first, { seq: 2, entry_hash: core.head().entry_hash, at: '2026-10-15T12:00:00.000Z' });
  assert.deepEqual(core.head().last_checkpoint, { seq: 2, entry_hash: first.entry_hash, at: first.at, object_key: 'checkpoints/2.json' });
  now.advance(30 * 60_000); await core.alarm(); assert.equal(EVENTS.puts, 1, 'not before the hour');
  now.advance(31 * 60_000); await core.alarm(); assert.equal(EVENTS.puts, 1, 'no new entries, no new checkpoint');
  await append(core, 3); now.advance(61 * 60_000); await core.alarm();
  assert.equal(EVENTS.json('checkpoints/3.json').seq, 3); assert.equal(EVENTS.puts, 2);
  assert.ok(core.storage.alarmAt <= now() + 3_600_000, 'next hourly alarm armed');
});

test('backup capture receives {repo_id, reason, delivery_id}; failures retry with backoff, escalate, and are never dropped', async () => {
  const calls = [], alerts = [];
  let failing = true;
  const backup = { async capture(arg) { calls.push(arg); if (failing) throw Error('backup down'); return { ok: true, job_id: 'j' }; } };
  const fetcher = async (url, init) => { alerts.push({ url, body: JSON.parse(init.body), redirect: init.redirect }); return new Response(null, { status: 204 }); };
  const { core, storage, now } = ledger({ backup, fetcher, commitLedger: () => ({ ingest: async () => ({ accepted: true }) }) });
  const r = await append(core, 1, { downstream: [{ kind: 'backup', payload: { repo_id: 42, reason: 'push', delivery_id: 'x' } }] });
  for (let i = 0; i < ESCALATE_AT; i++) { await core.alarm(); now.advance(3_600_000); }
  assert.equal(calls.length, ESCALATE_AT);
  assert.deepEqual(calls[0], { repo_id: 42, reason: 'push', delivery_id: 'x' });
  const row = storage.sql.exec("SELECT * FROM outbox WHERE kind = 'backup'").toArray()[0];
  assert.equal(row.done_at, null); assert.equal(row.attempts, ESCALATE_AT); assert.equal(row.last_error, 'Error');
  await core.alarm();
  const escalation = alerts.find(a => a.body.code === 'downstream_retrying');
  assert.ok(escalation, 'operational alert sent'); assert.equal(escalation.redirect, 'manual'); assert.equal(escalation.body.target, 'backup');
  failing = false; now.advance(3_600_000); await core.alarm();
  assert.ok(storage.sql.exec("SELECT done_at FROM outbox WHERE kind = 'backup'").toArray()[0].done_at, 'eventually delivered');
  assert.equal(r.state, 'appended');
});

test('backup refusals are never marked delivered silently: transient codes retry, permanent ones settle with an alert', async () => {
  const alerts = [];
  const fetcher = async (url, init) => { alerts.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); };
  let answer = { ok: false, code: 'enqueue_failed' };
  const backup = { async capture() { return answer; } };
  const { core, storage, now } = ledger({ backup, fetcher, commitLedger: () => ({ ingest: async () => ({ accepted: true }) }) });
  await append(core, 1, { downstream: [{ kind: 'backup', payload: { repo_id: 42, reason: 'push', delivery_id: 'x' } }] });
  const row = () => storage.sql.exec("SELECT * FROM outbox WHERE kind = 'backup'").toArray()[0];
  await core.alarm();
  assert.equal(row().done_at, null, 'enqueue_failed is retried');
  assert.equal(row().last_error, 'backup_enqueue_failed');
  answer = undefined; now.advance(3_600_000); await core.alarm();
  assert.equal(row().done_at, null, 'a malformed answer is retried, never taken as success');
  answer = { ok: false, code: 'not_in_inventory' }; now.advance(3_600_000); await core.alarm();
  assert.ok(row().done_at, 'a permanent refusal settles');
  now.advance(60_000); await core.alarm();
  const refused = alerts.find(a => a.code === 'backup_capture_refused');
  assert.ok(refused, 'and raises an operational alert');
  assert.equal(refused.refusal, 'not_in_inventory'); assert.equal(refused.severity, 'warning');
});

test('workflow events reach the metrics sink with a reference that readDelivery verifies', async () => {
  const observed = [], current = randomSecret();
  const { core, env, EVENTS } = ledger({ metricsSink: { record: async o => { observed.push(o); } } }, { OBSERVATORY_WEBHOOK_SECRET: secret(current) });
  const payload = { action: 'completed', workflow_job: { id: 1, name: 'test' }, repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: OWNER } } };
  const text = JSON.stringify(payload), id = crypto.randomUUID();
  const response = await handleWebhook(new Request('https://hooks.vespoli.me/github', { method: 'POST', body: text, headers: { 'x-github-event': 'workflow_job', 'x-github-delivery': id, 'x-hub-signature-256': await sign(current, text) } }), env);
  assert.equal(response.status, 202);
  await core.alarm();
  assert.equal(observed.length, 1);
  const o = observed[0];
  assert.deepEqual(Object.keys(o).sort(), ['action', 'body_sha256', 'delivery_id', 'event', 'object_key', 'received_at', 'repo_id']);
  assert.equal(o.event, 'workflow_job'); assert.equal(o.action, 'completed'); assert.equal(o.delivery_id, id);
  const read = await readDelivery(env, o.object_key, o.body_sha256);
  assert.deepEqual(read.payload, payload);
  await assert.rejects(readDelivery(env, o.object_key, 'f'.repeat(64)), /delivery_digest_mismatch/);
  await assert.rejects(readDelivery(env, '../audit/x.json', o.body_sha256), /bad_object_key/);
  const stored = EVENTS.objects.get(o.object_key), record = JSON.parse(new TextDecoder().decode(stored.bytes));
  stored.bytes = new TextEncoder().encode(JSON.stringify({ ...record, body: text.replace('test', 'evil') }));
  await assert.rejects(readDelivery(env, o.object_key, o.body_sha256), /delivery_digest_mismatch/);
});

test('push and create are handed to the per-repository commit ledger; read API pages and fans out findings', async () => {
  const current = randomSecret(), commitNs = namespace(name => new CommitLedgerCore(sqlStorage(), env, {
    now, commitDetails: async (_r, s) => ({ sha: s, tree: sha(900), parents: [sha(1)], author_name: 'a', author_date: 'd', committer_name: 'c', committer_date: 'd', message_sha256: 'm'.repeat(1).padEnd(64, '0'), verified: false, verification_reason: 'unsigned' }),
    mintToken: async () => ({ token: 'test-token', expires_at: Date.now() + 3_600_000 }), fetcher: async () => new Response(null, { status: 204 }),
  }));
  const { core, env, now } = ledger({}, { OBSERVATORY_WEBHOOK_SECRET: secret(current), BACKUP: { capture: async () => ({ ok: true, job_id: 'j' }) } });
  env.COMMIT_LEDGER = commitNs;
  const payload = { ref: 'refs/heads/main', before: sha(1), after: sha(2), created: false, deleted: false, forced: false, pusher: { name: 'x' }, commits: [{ id: sha(2) }], repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: OWNER } }, installation: { id: 7 } };
  const text = JSON.stringify(payload);
  await handleWebhook(new Request('https://hooks.vespoli.me/github', { method: 'POST', body: text, headers: { 'x-github-event': 'push', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': await sign(current, text) } }), env);
  await core.alarm();
  const repoLedger = commitNs.instances.get('42');
  assert.ok(repoLedger, 'idFromName(String(repo_id))');
  await repoLedger.alarm();
  assert.equal(repoLedger.head().seq, 2);
  const page = await commitLedger(env, 42, 1);
  assert.equal(page.items[0].kind, 'commit'); assert.equal(page.next_cursor, 2); assert.equal(page.head.seq, 2);
  assert.equal((await commitLedger(env, 42, 1, page.next_cursor)).items[0].kind, 'ref_update');
  const all = await findings(env);
  assert.deepEqual(all.map(f => f.kind), ['main_commit_unverified']); assert.equal(all[0].repo_id, 42);
  assert.equal((await recentEvents(env, 10)).items.length, 1); assert.equal((await ledgerHead(env)).seq, 1);
  await assert.rejects(async () => commitLedger(env, -1), /bad_repo_id/);
  assert.throws(() => core.recent(1000), /bad_limit/);
});
