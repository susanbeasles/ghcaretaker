// Owner requirements 1 and 2: a 2xx only after the raw delivery is durably stored (R2 create-only write, ledger
// reservation and commit); any failure before that is a 5xx. Duplicate delivery ids: identical content is an
// idempotent 2xx with one ledger entry (including two concurrent deliveries); different content never overwrites and
// is a delivery_conflict finding holding both digests, with an alert. Requirement 7: no bodies in findings, alerts, logs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleWebhook } from '../src/webhook.mjs';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { sha256Hex } from '../src/bytes.mjs';
import { sqlStorage, memoryR2, secret, randomSecret, clock, sign, sha, deferred, captureLogs } from './fakes.mjs';

const OWNER = 215839550, MARKER = 'body-marker-' + crypto.randomUUID();

function setup() {
  const now = clock(), storage = sqlStorage(), EVENTS = memoryR2(), current = randomSecret(), alerts = [];
  const env = { GITHUB_OWNER_ID: String(OWNER), EVENTS, OBSERVATORY_WEBHOOK_SECRET: secret(current), ALERT_WEBHOOK_URL: secret('https://alerts.invalid/hook') };
  const fetcher = async (url, init) => { alerts.push({ url, body: init.body }); return new Response(null, { status: 204 }); };
  const core = new EventLedgerCore(storage, env, { now, fetcher });
  env.EVENT_LEDGER = { idFromName: n => n, get: () => core };
  return { env, core, storage, EVENTS, current, now, alerts };
}

const payload = (o = {}) => ({ ref: 'refs/heads/main', before: sha(1), after: sha(2), created: false, deleted: false, forced: false, pusher: { name: 'x' },
  commits: [{ id: sha(2), message: MARKER }], repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: OWNER } }, installation: { id: 7 }, ...o });

async function request(key, body, id) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Request('https://hooks.vespoli.me/github', { method: 'POST', body: text, headers: {
    'content-type': 'application/json', 'x-github-event': 'push', 'x-github-delivery': id, 'x-hub-signature-256': await sign(key, text) } });
}

const settled = async p => Promise.race([p.then(() => true), new Promise(r => setTimeout(() => r(false), 30))]);
const entries = ctx => ctx.core.head().seq;
const fast = { waitMs: 2_000, stepMs: 5 };

test('a 202 is sent only after the R2 create-only write and the ledger commit have both completed', async () => {
  const ctx = setup(), id = crypto.randomUUID(), order = [], putGate = deferred(), commitGate = deferred();
  const put = ctx.EVENTS.put.bind(ctx.EVENTS), begin = ctx.core.begin.bind(ctx.core), commit = ctx.core.commit.bind(ctx.core);
  ctx.EVENTS.put = async (key, value, options) => {
    order.push('r2.put:' + options.onlyIf.get('if-none-match')); await putGate.promise;
    const r = await put(key, value, options); order.push('r2.stored'); return r;
  };
  ctx.core.begin = input => { order.push('ledger.begin'); return begin(input); };
  ctx.core.commit = async input => { order.push('ledger.commit'); await commitGate.promise; const r = await commit(input); order.push('ledger.committed'); return r; };

  const response = handleWebhook(await request(ctx.current, payload(), id), ctx.env);
  assert.equal(await settled(response), false, 'no answer while the R2 write is outstanding');
  assert.deepEqual(order, ['ledger.begin', 'r2.put:*']);
  putGate.resolve();
  assert.equal(await settled(response), false, 'no answer while the ledger commit is outstanding');
  assert.deepEqual(order, ['ledger.begin', 'r2.put:*', 'r2.stored', 'ledger.commit']);
  assert.equal(entries(ctx), 0);
  commitGate.resolve();
  assert.equal((await response).status, 202);
  assert.deepEqual(order, ['ledger.begin', 'r2.put:*', 'r2.stored', 'ledger.commit', 'ledger.committed']);
  assert.equal(entries(ctx), 1); assert.ok(ctx.EVENTS.objects.has(`deliveries/2026/10/15/${id}.json`));
});

test('a failure at any step before the commit is a 5xx with no ledger entry, and the redelivery is then accepted once', async () => {
  const failures = {
    'reservation unavailable': ctx => { ctx.core.begin = () => { throw new Error('do unavailable'); }; },
    'R2 write throws': ctx => { ctx.EVENTS.fail = true; },
    'R2 object exists with other content': ctx => { ctx.preexisting = true; },
    'ledger commit throws': ctx => { ctx.core.commit = async () => { throw new Error('sqlite busy'); }; },
    'ledger commit loses its lease': ctx => { const commit = ctx.core.commit.bind(ctx.core); ctx.core.commit = input => commit({ ...input, token: 'stale' }); },
  };
  for (const [name, inject] of Object.entries(failures)) {
    const ctx = setup(), id = crypto.randomUUID(), saved = { begin: ctx.core.begin, commit: ctx.core.commit };
    inject(ctx);
    if (ctx.preexisting) ctx.EVENTS.objects.set(`deliveries/2026/10/15/${id}.json`, { bytes: new Uint8Array([1]), customMetadata: { body_sha256: '0'.repeat(64) } });
    const r = await handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
    assert.ok(r.status >= 500 && r.status < 600, name + ': 5xx, got ' + r.status);
    assert.equal(entries(ctx), 0, name + ': nothing ledgered');
    if (ctx.preexisting) continue; // a foreign object at the key is never overwritten; that delivery stays refused
    Object.assign(ctx.core, saved); ctx.EVENTS.fail = false;
    const retry = await handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
    assert.equal(retry.status, 202, name + ': redelivery accepted');
    assert.equal(entries(ctx), 1, name + ': exactly one entry');
  }
});

test('identical redelivery: idempotent 202, no second entry, no second R2 write, downstream queued once', async () => {
  const ctx = setup(), id = crypto.randomUUID();
  for (let i = 0; i < 3; i++) assert.equal((await handleWebhook(await request(ctx.current, payload(), id), ctx.env)).status, 202);
  assert.equal(entries(ctx), 1); assert.equal(ctx.EVENTS.puts, 1);
  assert.equal(ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM outbox').toArray()[0].n, 2);
  assert.equal(ctx.core.findings().items.length, 0);
});

test('two concurrent identical deliveries: both answered 202 only after the first is durable, one entry', async () => {
  const ctx = setup(), id = crypto.randomUUID(), gate = deferred(), put = ctx.EVENTS.put.bind(ctx.EVENTS);
  let puts = 0;
  ctx.EVENTS.put = async (...a) => { puts++; await gate.promise; return put(...a); };
  const first = handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
  const second = handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
  assert.equal(await settled(second), false, 'the second waits for the in-flight first instead of answering');
  assert.equal(entries(ctx), 0);
  gate.resolve();
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual([a.status, b.status], [202, 202]);
  assert.equal(entries(ctx), 1); assert.equal(puts, 1, 'the second never wrote R2');
  assert.equal(ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM outbox').toArray()[0].n, 2, 'downstream once');
});

test('concurrent identical delivery whose first attempt fails: the waiting one takes over and stores it', async () => {
  const ctx = setup(), id = crypto.randomUUID(), gate = deferred(), put = ctx.EVENTS.put.bind(ctx.EVENTS);
  let calls = 0;
  ctx.EVENTS.put = async (...a) => { if (++calls === 1) { await gate.promise; throw new Error('r2 down'); } return put(...a); };
  const first = handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
  const second = handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
  gate.resolve();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.status, 500); assert.equal(b.status, 202);
  assert.equal(entries(ctx), 1);
});

test('an in-flight identical delivery that does not settle in time is a 503 (GitHub retries), never a 2xx or 4xx', async () => {
  const ctx = setup(), id = crypto.randomUUID(), gate = deferred(), put = ctx.EVENTS.put.bind(ctx.EVENTS);
  ctx.EVENTS.put = async (...a) => { await gate.promise; return put(...a); };
  const first = handleWebhook(await request(ctx.current, payload(), id), ctx.env, fast);
  const second = await handleWebhook(await request(ctx.current, payload(), id), ctx.env, { waitMs: 40, stepMs: 5 });
  assert.equal(second.status, 503); assert.equal(entries(ctx), 0);
  gate.resolve(); assert.equal((await first).status, 202);
  assert.equal((await handleWebhook(await request(ctx.current, payload(), id), ctx.env)).status, 202, 'the next redelivery is a duplicate');
  assert.equal(entries(ctx), 1);
});

test('same id, different content: 409, first kept, delivery_conflict finding with both digests and an alert; no bodies anywhere', async () => {
  const ctx = setup(), id = crypto.randomUUID(), firstText = JSON.stringify(payload()), secondText = JSON.stringify(payload({ forced: true, after: sha(9) }));
  assert.equal((await handleWebhook(await request(ctx.current, firstText, id), ctx.env)).status, 202);
  const key = `deliveries/2026/10/15/${id}.json`, original = ctx.EVENTS.objects.get(key).bytes;
  const { result, lines } = await captureLogs(async () => {
    const r1 = await handleWebhook(await request(ctx.current, secondText, id), ctx.env);
    const r2 = await handleWebhook(await request(ctx.current, secondText, id), ctx.env);
    assert.equal(ctx.EVENTS.puts, 1, 'the conflicting body was never written');
    await ctx.core.alarm();
    return [r1.status, r2.status];
  });
  assert.deepEqual(result, [409, 409]);
  assert.deepEqual(ctx.EVENTS.objects.get(key).bytes, original, 'never overwritten');
  assert.equal(entries(ctx), 1);
  const found = ctx.core.findings().items;
  assert.equal(found.length, 1, 'recorded once however often it is redelivered');
  assert.equal(found[0].kind, 'delivery_conflict'); assert.equal(found[0].severity, 'critical'); assert.equal(found[0].delivery_id, id);
  assert.deepEqual(found[0].detail, { first_body_sha256: await sha256Hex(firstText), second_body_sha256: await sha256Hex(secondText), event: 'push', against: 'ledgered', entry_seq: 1 });
  const alert = ctx.alerts.map(a => JSON.parse(a.body)).find(a => a.code === 'delivery_conflict');
  assert.ok(alert, 'alert delivered'); assert.equal(alert.severity, 'critical'); assert.equal(alert.ledger, 'event');
  assert.equal(alert.detail.second_body_sha256, await sha256Hex(secondText));
  const everything = JSON.stringify({ found, alerts: ctx.alerts, lines, rows: ctx.storage.sql.exec('SELECT * FROM findings').toArray() });
  assert.ok(!everything.includes(MARKER), 'no body text in findings, alerts or logs');
  assert.ok(!everything.includes(sha(9)), 'not even fields of the conflicting body');
});

test('same id, different content while the first is still in flight: conflict recorded against the reservation', async () => {
  const ctx = setup(), id = crypto.randomUUID();
  assert.equal(ctx.core.begin({ delivery_id: id, body_sha256: 'a'.repeat(64), event: 'push' }).state, 'reserved');
  assert.equal(ctx.core.begin({ delivery_id: id, body_sha256: 'b'.repeat(64), event: 'push' }).state, 'conflict');
  const [f] = ctx.core.findings().items;
  assert.deepEqual(f.detail, { first_body_sha256: 'a'.repeat(64), second_body_sha256: 'b'.repeat(64), event: 'push', against: 'reserved', entry_seq: null });
  assert.equal(ctx.storage.sql.exec("SELECT COUNT(*) AS n FROM outbox WHERE kind = 'alert'").toArray()[0].n, 1);
});
