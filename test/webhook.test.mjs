import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleWebhook, MAX_BODY_BYTES, signatureValid } from '../src/webhook.mjs';
import { EventLedgerCore } from '../src/event-ledger-core.mjs';
import { sha256Hex } from '../src/bytes.mjs';
import { sqlStorage, memoryR2, secret, randomSecret, clock, sign, sha } from './fakes.mjs';

const OWNER = 215839550;

function setup(overrides = {}) {
  const now = clock(), storage = sqlStorage(), EVENTS = memoryR2(), current = randomSecret();
  const env = { GITHUB_OWNER_ID: String(OWNER), EVENTS, GITHUB_WEBHOOK_SECRET: secret(current), ...overrides };
  const core = new EventLedgerCore(storage, env, { now });
  env.EVENT_LEDGER = { idFromName: n => n, get: () => core };
  return { env, core, storage, EVENTS, current, now };
}

const pushPayload = (o = {}) => ({
  ref: 'refs/heads/main', before: sha(1), after: sha(2), created: false, deleted: false, forced: false,
  pusher: { name: 'susanbeasles', email: 'owner@users.noreply.github.com' }, commits: [{ id: sha(2), message: 'feat: x' }],
  repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: OWNER } }, installation: { id: 7 }, ...o,
});

async function delivery(key, payload, { event = 'push', id = crypto.randomUUID(), headers = {}, body, method = 'POST', path = '/github' } = {}) {
  const text = body ?? JSON.stringify(payload);
  return new Request('https://hooks.vespoli.me' + path, { method, body: method === 'GET' || method === 'HEAD' ? undefined : text, headers: {
    'content-type': 'application/json', 'x-github-event': event, 'x-github-delivery': id, 'x-github-hook-id': '123',
    'x-github-hook-installation-target-id': '456', 'x-hub-signature-256': await sign(key, text), ...headers,
  } });
}

const nothingStored = (t, ctx) => { assert.equal(ctx.EVENTS.objects.size, 0, t + ': R2 untouched'); assert.equal(ctx.core.head().seq, 0, t + ': ledger untouched'); };
const outboxKinds = storage => storage.sql.exec('SELECT kind FROM outbox ORDER BY id').toArray().map(r => r.kind);

test('signed delivery is captured raw in R2, ledgered, routed downstream and acknowledged 202', async () => {
  const ctx = setup(), id = crypto.randomUUID(), payload = pushPayload(), text = JSON.stringify(payload);
  const response = await handleWebhook(await delivery(ctx.current, payload, { id }), ctx.env);
  assert.equal(response.status, 202);
  assert.equal(await response.text(), '');
  const key = `deliveries/2026/10/15/${id}.json`, stored = ctx.EVENTS.objects.get(key), record = ctx.EVENTS.json(key);
  assert.deepEqual(Object.keys(record).sort(), ['body', 'body_sha256', 'delivery_id', 'event', 'hook_id', 'installation_target_id', 'received_at', 'v']);
  assert.equal(record.v, 1); assert.equal(record.body, text); assert.equal(record.event, 'push'); assert.equal(record.hook_id, '123'); assert.equal(record.installation_target_id, '456');
  assert.equal(record.body_sha256, await sha256Hex(text));
  assert.equal(stored.customMetadata.sha256, await sha256Hex(stored.bytes));
  assert.equal(stored.sha256, stored.customMetadata.sha256);
  const head = ctx.core.head(), [entry] = ctx.core.recent(10).items;
  assert.equal(head.seq, 1);
  assert.deepEqual({ ...entry, prev_hash: entry.prev_hash.length, entry_hash: entry.entry_hash.length }, {
    seq: 1, delivery_id: id, event: 'push', action: null, repo_id: 42, received_at: '2026-10-15T12:00:00.000Z', object_key: key,
    body_sha256: record.body_sha256, prev_hash: 64, entry_hash: 64 });
  assert.deepEqual(outboxKinds(ctx.storage), ['commit_ledger', 'backup']);
  const commitRow = JSON.parse(ctx.storage.sql.exec("SELECT payload FROM outbox WHERE kind = 'commit_ledger'").toArray()[0].payload);
  assert.equal(commitRow.pusher, 'susanbeasles');
  assert.ok(!JSON.stringify(commitRow).includes('noreply'), 'pusher email is not copied downstream');
  assert.ok(ctx.storage.alarmAt !== null, 'alarm armed for the outbox');
  assert.equal((await ctx.core.verify()).ok, true);
});

test('refusals are 401 with an empty body and store nothing', async () => {
  const cases = [
    ['bad signature', async c => delivery(randomSecret(), pushPayload())],
    ['signature over different bytes', async c => { const r = await delivery(c.current, pushPayload()); return new Request(r.url, { method: 'POST', headers: r.headers, body: JSON.stringify(pushPayload({ forced: true })) }); }],
    ['signature over the body plus one byte', async c => { const text = JSON.stringify(pushPayload()); return delivery(c.current, null, { body: text, headers: { 'x-hub-signature-256': await sign(c.current, text + ' ') } }); }],
    ['missing signature', async c => delivery(c.current, pushPayload(), { headers: { 'x-hub-signature-256': '' } })],
    ['sha1 signature only', async c => delivery(c.current, pushPayload(), { headers: { 'x-hub-signature-256': 'sha1=' + 'a'.repeat(40) } })],
    ['uppercase or truncated hex', async c => { const r = await delivery(c.current, pushPayload()); return delivery(c.current, pushPayload(), { headers: { 'x-hub-signature-256': r.headers.get('x-hub-signature-256').slice(0, 70) } }); }],
    ['missing event', async c => delivery(c.current, pushPayload(), { headers: { 'x-github-event': '' } })],
    ['malformed event', async c => delivery(c.current, pushPayload(), { headers: { 'x-github-event': 'Push;rm' } })],
    ['missing delivery', async c => delivery(c.current, pushPayload(), { headers: { 'x-github-delivery': '' } })],
    ['delivery not a UUID', async c => delivery(c.current, pushPayload(), { id: '../../etc/passwd' })],
    ['non-numeric hook id', async c => delivery(c.current, pushPayload(), { headers: { 'x-github-hook-id': '12a' } })],
    ['signed but not JSON', async c => delivery(c.current, null, { body: '{"ref":' })],
    ['signed JSON array', async c => delivery(c.current, null, { body: '[1,2]' })],
    ['signed invalid UTF-8', async c => { const bytes = new Uint8Array([123, 34, 97, 34, 58, 34, 0xff, 34, 125]); return new Request('https://hooks.vespoli.me/github', { method: 'POST', body: bytes, headers: { 'x-github-event': 'push', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': await sign(c.current, bytes) } }); }],
    ['declared length over the bound', async c => { const r = await delivery(c.current, pushPayload()); return { method: 'POST', url: r.url, headers: new Headers([...r.headers, ['content-length', String(MAX_BODY_BYTES + 1)]]), body: r.body }; }],
  ];
  for (const [name, build] of cases) {
    const ctx = setup(), response = await handleWebhook(await build(ctx), ctx.env);
    assert.equal(response.status, 401, name);
    assert.equal(await response.text(), '', name + ': empty body');
    nothingStored(name, ctx);
  }
});

function streamOf(totalBytes, chunk = 1024 * 1024) {
  let sent = 0, cancelled = false;
  const stream = new ReadableStream({
    pull(controller) { if (sent >= totalBytes) return controller.close(); const n = Math.min(chunk, totalBytes - sent); sent += n; controller.enqueue(new Uint8Array(n).fill(32)); },
    cancel() { cancelled = true; },
  });
  return { stream, read: () => sent, cancelled: () => cancelled };
}

test('oversized bodies are refused while reading, whatever Content-Length claims', async () => {
  for (const declared of [null, '10']) {
    const ctx = setup(), source = streamOf(MAX_BODY_BYTES + 5 * 1024 * 1024);
    const headers = new Headers({ 'x-github-event': 'push', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) });
    if (declared) headers.set('content-length', declared);
    const response = await handleWebhook({ method: 'POST', url: 'https://hooks.vespoli.me/github', headers, body: source.stream }, ctx.env);
    assert.equal(response.status, 401);
    assert.ok(source.cancelled(), 'stream cancelled at the bound');
    assert.ok(source.read() <= MAX_BODY_BYTES + 1024 * 1024, 'reading stopped near the bound');
    nothingStored('oversized', ctx);
  }
  // Exactly at the bound is accepted for verification (and then fails only on the signature here).
  const ctx = setup(), atBound = streamOf(MAX_BODY_BYTES);
  const response = await handleWebhook({ method: 'POST', url: 'https://hooks.vespoli.me/github', headers: new Headers({ 'x-github-event': 'push', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) }), body: atBound.stream }, ctx.env);
  assert.equal(response.status, 401); assert.equal(atBound.cancelled(), false); assert.equal(atBound.read(), MAX_BODY_BYTES);
});

test('only POST /github exists; everything else is 404 and nothing is ever a redirect', async () => {
  for (const [method, path] of [['GET', '/github'], ['HEAD', '/github'], ['PUT', '/github'], ['DELETE', '/github'], ['OPTIONS', '/github'], ['POST', '/github/'], ['POST', '/'], ['POST', '/ghcaretaker'], ['POST', '/GITHUB']]) {
    const ctx = setup(), response = await handleWebhook(await delivery(ctx.current, pushPayload(), { method, path }), ctx.env);
    assert.equal(response.status, 404, method + ' ' + path);
    assert.ok(response.status < 300 || response.status >= 400);
    nothingStored(method + ' ' + path, ctx);
  }
});

test('rotation: the previous secret verifies while bound; an absent previous secret is ignored', async () => {
  const old = randomSecret();
  let ctx = setup({ GITHUB_WEBHOOK_SECRET_PREVIOUS: secret(old) });
  assert.equal((await handleWebhook(await delivery(old, pushPayload()), ctx.env)).status, 202);
  assert.equal((await handleWebhook(await delivery(ctx.current, pushPayload()), ctx.env)).status, 202);
  ctx = setup({ GITHUB_WEBHOOK_SECRET_PREVIOUS: { get: async () => { throw Error('secret not found'); } } });
  assert.equal((await handleWebhook(await delivery(old, pushPayload()), ctx.env)).status, 401);
  assert.equal((await handleWebhook(await delivery(ctx.current, pushPayload()), ctx.env)).status, 202);
});

test('an unavailable or plain-var webhook secret fails closed with 500 and stores nothing', async () => {
  for (const binding of [undefined, 'plain-string-var', { get: async () => '' }, { get: async () => { throw Error('down'); } }]) {
    const ctx = setup({ GITHUB_WEBHOOK_SECRET: binding }), response = await handleWebhook(await delivery(randomSecret(), pushPayload()), ctx.env);
    assert.equal(response.status, 500); assert.equal(await response.text(), ''); nothingStored('secret', ctx);
  }
});

test('duplicate delivery: one ledger entry, the R2 object is never rewritten', async () => {
  const ctx = setup(), id = crypto.randomUUID(), payload = pushPayload();
  assert.equal((await handleWebhook(await delivery(ctx.current, payload, { id }), ctx.env)).status, 202);
  const key = `deliveries/2026/10/15/${id}.json`, first = ctx.EVENTS.objects.get(key).bytes;
  ctx.now.advance(3 * 86_400_000);
  assert.equal((await handleWebhook(await delivery(ctx.current, payload, { id }), ctx.env)).status, 202);
  assert.equal(ctx.EVENTS.puts, 1); assert.equal(ctx.EVENTS.objects.size, 1);
  assert.deepEqual(ctx.EVENTS.objects.get(key).bytes, first);
  assert.equal(ctx.core.head().seq, 1);
  assert.equal(ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM outbox').toArray()[0].n, 2, 'downstream not enqueued twice');
  // Same delivery id with a different (validly signed) body: refused, original kept.
  const conflict = await handleWebhook(await delivery(ctx.current, pushPayload({ forced: true }), { id }), ctx.env);
  assert.equal(conflict.status, 409); assert.deepEqual(ctx.EVENTS.objects.get(key).bytes, first); assert.equal(ctx.core.head().seq, 1);
});

test('storage failure is a 500 with no ledger entry; the redelivery reuses the reserved key', async () => {
  const ctx = setup(), id = crypto.randomUUID(), payload = pushPayload();
  ctx.EVENTS.fail = true;
  assert.equal((await handleWebhook(await delivery(ctx.current, payload, { id }), ctx.env)).status, 500);
  assert.equal(ctx.core.head().seq, 0);
  ctx.EVENTS.fail = false; ctx.now.advance(86_400_000);
  assert.equal((await handleWebhook(await delivery(ctx.current, payload, { id }), ctx.env)).status, 202);
  assert.ok(ctx.EVENTS.objects.has(`deliveries/2026/10/15/${id}.json`), 'original receive date kept');
  // A pre-existing object with different content (written by someone else) is never overwritten.
  const other = setup(), id2 = crypto.randomUUID();
  other.EVENTS.objects.set(`deliveries/2026/10/15/${id2}.json`, { bytes: new Uint8Array([1]), customMetadata: { body_sha256: '0'.repeat(64) } });
  assert.equal((await handleWebhook(await delivery(other.current, payload, { id: id2 }), other.env)).status, 500);
  assert.deepEqual(other.EVENTS.objects.get(`deliveries/2026/10/15/${id2}.json`).bytes, new Uint8Array([1]));
  assert.equal(other.core.head().seq, 0);
});

test('concurrent delivery of the same id is refused while the first holds the reservation', async () => {
  const ctx = setup(), id = crypto.randomUUID(), digest = 'a'.repeat(64);
  assert.equal(ctx.core.begin({ delivery_id: id, body_sha256: digest }).state, 'reserved');
  assert.equal(ctx.core.begin({ delivery_id: id, body_sha256: digest }).state, 'busy');
  assert.equal(ctx.core.begin({ delivery_id: id, body_sha256: 'b'.repeat(64) }).state, 'conflict');
  ctx.now.advance(301_000);
  const retaken = ctx.core.begin({ delivery_id: id, body_sha256: digest });
  assert.equal(retaken.state, 'reserved'); assert.equal(retaken.received_at, '2026-10-15T12:00:00.000Z');
});

test('signature comparison checks every configured secret and rejects malformed headers', async () => {
  const body = new TextEncoder().encode('{}'), a = randomSecret(), b = randomSecret();
  assert.equal(await signatureValid(await sign(b, body), body, [a, b]), true);
  assert.equal(await signatureValid(await sign(a, body), body, [b]), false);
  for (const header of [null, '', 'sha256=', 'sha256=' + 'g'.repeat(64), (await sign(a, body)).toUpperCase(), ' ' + await sign(a, body)]) assert.equal(await signatureValid(header, body, [a]), false);
});

test('events from repositories outside the pinned owner are ledgered but not routed downstream', async () => {
  const ctx = setup();
  const payload = pushPayload({ repository: { id: 99, full_name: 'someone/else', owner: { id: 1 } } });
  assert.equal((await handleWebhook(await delivery(ctx.current, payload), ctx.env)).status, 202);
  assert.equal(ctx.core.head().seq, 1); assert.deepEqual(outboxKinds(ctx.storage), []);
  assert.equal((await handleWebhook(await delivery(ctx.current, { zen: 'hi', hook_id: 1 }, { event: 'ping' }), ctx.env)).status, 202);
  assert.equal(ctx.core.recent(1).items[0].repo_id, null);
});
