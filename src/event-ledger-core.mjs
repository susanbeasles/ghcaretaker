// EventLedger: one SQLite Durable Object (instance `global`) holding the hash-chained record of every
// accepted GitHub delivery, the downstream outbox and the hourly R2 checkpoints. Runtime-independent: the
// Durable Object class in ledgers.mjs only forwards to this core, and tests drive it over node:sqlite.
import { GENESIS, link, verifyEntries, verifyRange, mutex } from './chain.mjs';
import { OUTBOX_SCHEMA, enqueue, drain, nextDue, pendingCounts, prune } from './outbox.mjs';
import { CodedError, sha256Hex } from './bytes.mjs';
import { deliverAlert } from './alerts.mjs';
import { metricsSinkFor } from './metrics-sink.mjs';
import { log, errorCode } from './log.mjs';

const HOUR = 3_600_000, LEASE_MS = 300_000, RETRY_MS = 300_000, KEEP_DONE_MS = 7 * 86_400_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const EVENT = /^[a-z_]{1,64}$/;
const DOWNSTREAM = new Set(['commit_ledger', 'backup', 'metrics']);
export const CHECKPOINT_PREFIX = 'checkpoints/';

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE, event TEXT NOT NULL,
    action TEXT, repo_id INTEGER, received_at TEXT NOT NULL, object_key TEXT NOT NULL, body_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS events_repo ON events(repo_id, seq)',
  "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'append only'); END",
  "CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'append only'); END",
  `CREATE TABLE IF NOT EXISTS reservations (delivery_id TEXT PRIMARY KEY, body_sha256 TEXT NOT NULL, token TEXT NOT NULL,
    reserved_at INTEGER NOT NULL, received_at TEXT NOT NULL, object_key TEXT NOT NULL)`,
  'CREATE TABLE IF NOT EXISTS checkpoints (seq INTEGER PRIMARY KEY, entry_hash TEXT NOT NULL, at TEXT NOT NULL, object_key TEXT NOT NULL)',
  'CREATE TABLE IF NOT EXISTS repos (repo_id INTEGER PRIMARY KEY, full_name TEXT, last_seen TEXT NOT NULL)',
  'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  ...OUTBOX_SCHEMA,
];

export const deliveryKey = (receivedAt, deliveryId) =>
  `deliveries/${receivedAt.slice(0, 4)}/${receivedAt.slice(5, 7)}/${receivedAt.slice(8, 10)}/${deliveryId}.json`;

const entryOf = r => ({ seq: r.seq, delivery_id: r.delivery_id, event: r.event, action: r.action, repo_id: r.repo_id,
  received_at: r.received_at, object_key: r.object_key, body_sha256: r.body_sha256, prev_hash: r.prev_hash, entry_hash: r.entry_hash });

export const boundedLimit = (limit, max = 100, fallback = 50) => {
  const n = limit ?? fallback;
  if (!Number.isSafeInteger(n) || n < 1 || n > max) throw new CodedError('bad_limit');
  return n;
};
export const optionalCursor = cursor => {
  if (cursor === undefined || cursor === null) return null;
  if (!Number.isSafeInteger(cursor) || cursor < 1) throw new CodedError('bad_cursor');
  return cursor;
};

export class EventLedgerCore {
  constructor(storage, env, deps = {}) {
    this.storage = storage; this.sql = storage.sql; this.env = env; this.deps = deps;
    this.now = deps.now || Date.now; this.lock = mutex();
    for (const statement of SCHEMA) this.sql.exec(statement);
  }

  headRow() { return this.sql.exec('SELECT seq, entry_hash FROM events ORDER BY seq DESC LIMIT 1').toArray()[0] ?? null; }
  meta(key) { return this.sql.exec('SELECT value FROM meta WHERE key = ?', key).toArray()[0]?.value ?? null; }
  setMeta(key, value) { this.sql.exec('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, String(value)); }
  byDelivery(id) { const r = this.sql.exec('SELECT * FROM events WHERE delivery_id = ?', id).toArray()[0]; return r ? entryOf(r) : null; }

  // Step 1 of capture: dedupe and reserve. The reservation fixes received_at and the object key so a retry after a
  // crash writes the same object, and a concurrent redelivery is told `busy` instead of racing the R2 write.
  begin({ delivery_id, body_sha256 }) {
    if (!UUID.test(delivery_id ?? '') || !HEX64.test(body_sha256 ?? '')) throw new CodedError('bad_request');
    const existing = this.byDelivery(delivery_id);
    if (existing) return existing.body_sha256 === body_sha256 ? { state: 'duplicate', entry: existing } : { state: 'conflict' };
    return this.storage.transactionSync(() => {
      const now = this.now(), r = this.sql.exec('SELECT * FROM reservations WHERE delivery_id = ?', delivery_id).toArray()[0];
      if (r && r.body_sha256 !== body_sha256) return { state: 'conflict' };
      if (r && now - r.reserved_at < LEASE_MS) return { state: 'busy' };
      const token = crypto.randomUUID(), received_at = r?.received_at ?? new Date(now).toISOString();
      const object_key = r?.object_key ?? deliveryKey(received_at, delivery_id);
      this.sql.exec('INSERT INTO reservations (delivery_id, body_sha256, token, reserved_at, received_at, object_key) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(delivery_id) DO UPDATE SET token = excluded.token, reserved_at = excluded.reserved_at',
        delivery_id, body_sha256, token, now, received_at, object_key);
      return { state: 'reserved', token, received_at, object_key };
    });
  }

  // Failure path: expire the lease but keep received_at/object_key, so an immediate redelivery reuses the same key.
  release({ delivery_id, token }) {
    if (!UUID.test(delivery_id ?? '') || typeof token !== 'string') throw new CodedError('bad_request');
    this.sql.exec('UPDATE reservations SET reserved_at = 0 WHERE delivery_id = ? AND token = ?', delivery_id, token);
    return { released: true };
  }

  // Step 3 of capture (after the R2 object exists): append the chained entry and its outbox rows atomically.
  commit({ delivery_id, token, event, action = null, repo_id = null, repo_full_name = null, body_sha256, downstream = [] }) {
    if (!UUID.test(delivery_id ?? '') || typeof token !== 'string' || !EVENT.test(event ?? '') || !HEX64.test(body_sha256 ?? '')) throw new CodedError('bad_request');
    if (action !== null && !EVENT.test(action)) throw new CodedError('bad_request');
    if (repo_id !== null && (!Number.isSafeInteger(repo_id) || repo_id < 1)) throw new CodedError('bad_request');
    if (!Array.isArray(downstream) || downstream.some(d => !DOWNSTREAM.has(d?.kind) || typeof d.payload !== 'object' || d.payload === null)) throw new CodedError('bad_request');
    return this.lock(async () => {
      const existing = this.byDelivery(delivery_id);
      if (existing) return { state: 'duplicate', entry: existing };
      const res = this.sql.exec('SELECT * FROM reservations WHERE delivery_id = ?', delivery_id).toArray()[0];
      if (!res || res.token !== token) throw new CodedError('lease_lost');
      if (res.body_sha256 !== body_sha256) throw new CodedError('conflict');
      const head = this.headRow();
      const [entry] = await link(head, [{ delivery_id, event, action, repo_id, received_at: res.received_at, object_key: res.object_key, body_sha256 }]);
      const now = this.now();
      this.storage.transactionSync(() => {
        if ((this.headRow()?.seq ?? 0) !== (head?.seq ?? 0)) throw new CodedError('head_moved');
        this.sql.exec('INSERT INTO events (seq, delivery_id, event, action, repo_id, received_at, object_key, body_sha256, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          entry.seq, entry.delivery_id, entry.event, entry.action, entry.repo_id, entry.received_at, entry.object_key, entry.body_sha256, entry.prev_hash, entry.entry_hash);
        for (const d of downstream) {
          const payload = d.kind === 'metrics' ? { ...d.payload, received_at: entry.received_at, object_key: entry.object_key, body_sha256 } : d.payload;
          enqueue(this.sql, { kind: d.kind, dedupe_key: d.kind + ':' + delivery_id, payload }, now);
        }
        if (repo_id !== null) this.sql.exec('INSERT INTO repos (repo_id, full_name, last_seen) VALUES (?, ?, ?) ON CONFLICT(repo_id) DO UPDATE SET full_name = COALESCE(excluded.full_name, repos.full_name), last_seen = excluded.last_seen',
          repo_id, typeof repo_full_name === 'string' ? repo_full_name.slice(0, 200) : null, entry.received_at);
        this.sql.exec('DELETE FROM reservations WHERE delivery_id = ?', delivery_id);
      });
      await this.wake(downstream.length ? now : now + HOUR);
      return { state: 'appended', entry };
    });
  }

  async wake(at) {
    const current = await this.storage.getAlarm();
    if (current === null || current === undefined || current > at) await this.storage.setAlarm(at);
  }

  handlers() {
    const env = this.env, deps = this.deps;
    return {
      commit_ledger: async p => {
        const ns = env.COMMIT_LEDGER, stub = deps.commitLedger ? deps.commitLedger(p.repo_id) : ns.get(ns.idFromName(String(p.repo_id)));
        const r = await stub.ingest(p);
        if (!r?.accepted) throw new CodedError('commit_ledger_refused');
      },
      backup: async p => {
        const backup = deps.backup ?? env.BACKUP;
        if (!backup) throw new CodedError('backup_unbound');
        await backup.capture({ repo_id: p.repo_id, reason: p.reason, delivery_id: p.delivery_id });
      },
      metrics: p => (deps.metricsSink ?? metricsSinkFor(env)).record(p),
      alert: p => deliverAlert(env, p, deps.fetcher ?? fetch),
    };
  }

  async alarm() {
    await drain(this.sql, this.handlers(), { now: this.now, source: 'event_ledger' });
    await this.checkpointIfDue();
    prune(this.sql, this.now() - KEEP_DONE_MS);
    await this.schedule();
  }

  async schedule() {
    const now = this.now(), due = nextDue(this.sql), checkpoint = Number(this.meta('next_checkpoint_at') ?? now + HOUR);
    const next = Math.min(due ?? Infinity, checkpoint);
    await this.storage.setAlarm(Math.max(next, now + 1000));
  }

  async checkpointIfDue() {
    const now = this.now(), next = this.meta('next_checkpoint_at');
    if (next !== null && now < Number(next)) return;
    try {
      await this.writeCheckpoint(now);
      this.setMeta('next_checkpoint_at', now + HOUR);
    } catch (error) {
      log('error', 'checkpoint_failed', { error: errorCode(error) });
      this.setMeta('next_checkpoint_at', now + RETRY_MS);
    }
  }

  async writeCheckpoint(now) {
    const head = this.headRow(), last = this.sql.exec('SELECT seq FROM checkpoints ORDER BY seq DESC LIMIT 1').toArray()[0];
    if (!head || (last && last.seq >= head.seq)) return null;
    const key = CHECKPOINT_PREFIX + head.seq + '.json';
    let record = { seq: head.seq, entry_hash: head.entry_hash, at: new Date(now).toISOString() };
    const body = JSON.stringify(record);
    const put = await this.env.EVENTS.put(key, body, {
      onlyIf: new Headers({ 'if-none-match': '*' }), httpMetadata: { contentType: 'application/json' }, customMetadata: { sha256: await sha256Hex(body) },
    });
    if (put === null) {
      // Written by an earlier attempt whose SQL bookkeeping did not complete. Never rewrite; adopt it if it agrees.
      const existing = JSON.parse(await (await this.env.EVENTS.get(key)).text());
      if (existing.seq !== head.seq || existing.entry_hash !== head.entry_hash) {
        enqueue(this.sql, { kind: 'alert', dedupe_key: 'checkpoint_conflict:' + head.seq, payload: { schema: 'ghcaretaker-alert/v1', type: 'operational', code: 'checkpoint_conflict', seq: head.seq, detected_at: new Date(now).toISOString() } }, now);
        throw new CodedError('checkpoint_conflict');
      }
      record = existing;
    }
    this.sql.exec('INSERT INTO checkpoints (seq, entry_hash, at, object_key) VALUES (?, ?, ?, ?) ON CONFLICT(seq) DO NOTHING', record.seq, record.entry_hash, record.at, key);
    return record;
  }

  // ---- Read side (exposed over RPC; see observatory-read.mjs) ----
  head() {
    const head = this.headRow(), checkpoint = this.sql.exec('SELECT seq, entry_hash, at, object_key FROM checkpoints ORDER BY seq DESC LIMIT 1').toArray()[0];
    return { seq: head?.seq ?? 0, entry_hash: head?.entry_hash ?? GENESIS, last_checkpoint: checkpoint ? { ...checkpoint } : null, outbox: pendingCounts(this.sql) };
  }

  recent(limit, cursor) {
    const n = boundedLimit(limit), before = optionalCursor(cursor);
    const rows = this.sql.exec('SELECT * FROM events WHERE seq < ? ORDER BY seq DESC LIMIT ?', before ?? Number.MAX_SAFE_INTEGER, n).toArray().map(entryOf);
    return { items: rows, next_cursor: rows.length === n && rows.at(-1).seq > 1 ? rows.at(-1).seq : null };
  }

  repos() { return this.sql.exec('SELECT repo_id, full_name, last_seen FROM repos ORDER BY repo_id').toArray().map(r => ({ ...r })); }

  async verify(fromSeq, toSeq) {
    const head = this.headRow();
    if (!head) return { ok: true, checked: 0, first_break: null, from: 0, to: 0, head_seq: 0 };
    const { from, to } = verifyRange(fromSeq, toSeq, head.seq);
    if (to < from) return { ok: true, checked: 0, first_break: null, from, to, head_seq: head.seq };
    let expectedPrev = GENESIS;
    if (from > 1) {
      const before = this.sql.exec('SELECT entry_hash FROM events WHERE seq = ?', from - 1).toArray()[0];
      if (!before) return { ok: false, checked: 0, first_break: { seq: from - 1, reason: 'missing_entry' }, from, to, head_seq: head.seq };
      expectedPrev = before.entry_hash;
    }
    const rows = this.sql.exec('SELECT * FROM events WHERE seq BETWEEN ? AND ? ORDER BY seq', from, to).toArray().map(entryOf);
    const result = await verifyEntries(rows, expectedPrev, from);
    if (result.ok && result.checked !== to - from + 1) return { ...result, ok: false, first_break: { seq: from + result.checked, reason: 'missing_entry' }, from, to, head_seq: head.seq };
    return { ...result, from, to, head_seq: head.seq };
  }
}
