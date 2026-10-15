// EventLedger: one SQLite Durable Object (instance `global`) holding the hash-chained record of every
// accepted GitHub delivery, the downstream outbox and the hourly R2 checkpoints. Runtime-independent: the
// Durable Object class in ledgers.mjs only forwards to this core, and tests drive it over node:sqlite.
// Also (ADR-0003): ledger-level findings (delivery_conflict, tail_truncation, anchor_mismatch), external anchors in
// R2 `observatory-anchors`, and the hourly reconciliation against GitHub's hook delivery log.
import { GENESIS, link, verifyEntries, verifyRange, mutex } from './chain.mjs';
import { OUTBOX_SCHEMA, enqueue, drain, nextDue, pendingCounts, prune } from './outbox.mjs';
import { CodedError, sha256Hex } from './bytes.mjs';
import { deliverAlert, findingAlert } from './alerts.mjs';
import { severityOf } from './integrity.mjs';
import { metricsSinkFor } from './metrics-sink.mjs';
import { ANCHOR_EVERY, ANCHOR_SCHEMA, anchorFindingDetail, sendBackupAnchor, verifyAnchors, writeAnchor } from './anchors.mjs';
import { HOOK_SCHEMA, reconcileHookDeliveries } from './hook-reconcile.mjs';
import { log, errorCode } from './log.mjs';

// BackupIngest refusals that a retry cannot change.
const BACKUP_PERMANENT = new Set(['not_in_inventory', 'bad_request']);

const HOUR = 3_600_000, LEASE_MS = 300_000, RETRY_MS = 300_000, KEEP_DONE_MS = 7 * 86_400_000;
export const CRON_TASKS = Object.freeze(['anchor', 'deliveries']);
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
  // Ledger-level findings: identifiers and hashes only, never bodies. `subject` deduplicates (one alert per fact).
  `CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, delivery_id TEXT,
    detail TEXT NOT NULL, detected_at TEXT NOT NULL, UNIQUE (kind, subject))`,
  // Repositories whose deliveries were handed to a CommitLedger (the cron fans out over these).
  'CREATE TABLE IF NOT EXISTS ledgered_repos (repo_id INTEGER PRIMARY KEY, first_seen TEXT NOT NULL)',
  ...ANCHOR_SCHEMA,
  ...HOOK_SCHEMA,
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
  // The same delivery id with different content never replaces the first: it is a `delivery_conflict` finding
  // holding both body digests (never the bodies) and an alert.
  begin({ delivery_id, body_sha256, event = null }) {
    if (!UUID.test(delivery_id ?? '') || !HEX64.test(body_sha256 ?? '') || (event !== null && !EVENT.test(event))) throw new CodedError('bad_request');
    const existing = this.byDelivery(delivery_id);
    if (existing) {
      if (existing.body_sha256 === body_sha256) return { state: 'duplicate', entry: existing };
      return this.conflict(delivery_id, existing.body_sha256, body_sha256, event, 'ledgered', existing.seq);
    }
    let conflicting = null;
    const result = this.storage.transactionSync(() => {
      const now = this.now(), r = this.sql.exec('SELECT * FROM reservations WHERE delivery_id = ?', delivery_id).toArray()[0];
      if (r && r.body_sha256 !== body_sha256) { conflicting = r.body_sha256; return null; }
      if (r && now - r.reserved_at < LEASE_MS) return { state: 'busy' };
      const token = crypto.randomUUID(), received_at = r?.received_at ?? new Date(now).toISOString();
      const object_key = r?.object_key ?? deliveryKey(received_at, delivery_id);
      this.sql.exec('INSERT INTO reservations (delivery_id, body_sha256, token, reserved_at, received_at, object_key) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(delivery_id) DO UPDATE SET token = excluded.token, reserved_at = excluded.reserved_at',
        delivery_id, body_sha256, token, now, received_at, object_key);
      return { state: 'reserved', token, received_at, object_key };
    });
    return conflicting === null ? result : this.conflict(delivery_id, conflicting, body_sha256, event, 'reserved', null);
  }

  conflict(delivery_id, first, second, event, against, entrySeq) {
    const now = this.now();
    const id = this.storage.transactionSync(() => this.recordFinding('delivery_conflict', delivery_id + ':' + second, delivery_id,
      { first_body_sha256: first, second_body_sha256: second, event, against, entry_seq: entrySeq }, now));
    if (id !== null) this.wake(now).catch(e => log('error', 'alarm_set_failed', { error: errorCode(e) }));
    return { state: 'conflict' };
  }

  // Stores a finding once per (kind, subject) and queues its alert in the same SQLite write. Returns the id, or null
  // when already recorded. Callers pass identifiers and digests only.
  recordFinding(kind, subject, delivery_id, detail, now) {
    const detected_at = new Date(now).toISOString();
    const row = this.sql.exec('INSERT INTO findings (kind, subject, delivery_id, detail, detected_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING id',
      kind, subject, delivery_id ?? null, JSON.stringify(detail ?? {}), detected_at).toArray()[0];
    if (!row) return null;
    log(severityOf(kind) === 'critical' ? 'critical' : 'warning', 'ledger_finding', { ledger: 'event', kind, finding_id: row.id, delivery_id: delivery_id ?? null });
    enqueue(this.sql, { kind: 'alert', dedupe_key: 'event_finding:' + row.id, payload: {
      ...findingAlert({ kind, id: row.id, delivery_id, entry_seq: detail?.entry_seq ?? detail?.anchor_seq ?? null, detail, detected_at }, { repo_id: null, full_name: null }), ledger: 'event',
    } }, now);
    return row.id;
  }

  operationalAlert(code, key, detail) {
    const now = this.now();
    enqueue(this.sql, { kind: 'alert', dedupe_key: code + ':event:' + key, payload: {
      schema: 'ghcaretaker-alert/v1', type: 'operational', code, ledger: 'event', ...detail, detected_at: new Date(now).toISOString(),
    } }, now);
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
        if (repo_id !== null && downstream.some(d => d.kind === 'commit_ledger')) this.sql.exec('INSERT INTO ledgered_repos (repo_id, first_seen) VALUES (?, ?) ON CONFLICT(repo_id) DO NOTHING', repo_id, entry.received_at);
        this.sql.exec('DELETE FROM reservations WHERE delivery_id = ?', delivery_id);
      });
      // Every ANCHOR_EVERY entries an anchor is due now (the alarm writes it; ingest never waits on R2 anchors).
      const anchorDue = this.anchorBacklog() >= ANCHOR_EVERY && !this.meta('anchor_blocked');
      if (anchorDue && this.meta('cron_due:anchor') === null) this.setMeta('cron_due:anchor', now);
      await this.wake(downstream.length || anchorDue ? now : now + HOUR);
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
        // BackupIngest.capture answers {ok:false, code} instead of throwing. Permanent refusals settle with an
        // operational alert (retrying cannot change them); every other refusal is retried by the outbox.
        const r = await backup.capture({ repo_id: p.repo_id, reason: p.reason, delivery_id: p.delivery_id });
        if (r?.ok === true) return;
        const code = typeof r?.code === 'string' ? r.code : 'backup_bad_response';
        if (BACKUP_PERMANENT.has(code)) { this.operationalAlert('backup_capture_refused', p.delivery_id ?? String(p.repo_id), { severity: 'warning', repo_id: p.repo_id, refusal: code }); return; }
        throw new CodedError('backup_' + code);
      },
      metrics: p => (deps.metricsSink ?? metricsSinkFor(env)).record(p),
      alert: p => deliverAlert(env, p, deps.fetcher ?? fetch),
      anchor_backup: p => sendBackupAnchor(env, p),
    };
  }

  async alarm() {
    await drain(this.sql, this.handlers(), { now: this.now, source: 'event_ledger' });
    await this.checkpointIfDue();
    await this.runDueTasks();
    prune(this.sql, this.now() - KEEP_DONE_MS);
    await this.schedule();
  }

  async schedule() {
    const now = this.now(), due = nextDue(this.sql), checkpoint = Number(this.meta('next_checkpoint_at') ?? now + HOUR);
    const tasks = CRON_TASKS.map(t => this.meta('cron_due:' + t)).filter(v => v !== null).map(Number);
    const next = Math.min(due ?? Infinity, checkpoint, ...tasks);
    await this.storage.setAlarm(Math.max(next, now + 1000));
  }

  // ---- Cron (src/cron.mjs): tasks are flagged due and run by the alarm, which retries them ----
  async requestCron(tasks) {
    if (!Array.isArray(tasks) || tasks.some(t => !CRON_TASKS.includes(t))) throw new CodedError('bad_request');
    const now = this.now();
    for (const t of tasks) this.setMeta('cron_due:' + t, now);
    await this.wake(now);
    return { accepted: true, tasks };
  }

  ledgeredRepos() { return this.sql.exec('SELECT repo_id FROM ledgered_repos ORDER BY repo_id').toArray().map(r => r.repo_id); }

  async runDueTasks() {
    const now = this.now(), due = t => { const v = this.meta('cron_due:' + t); return v !== null && Number(v) <= now; };
    if (due('anchor')) {
      try { await this.anchorCycle(); this.sql.exec("DELETE FROM meta WHERE key = 'cron_due:anchor'"); }
      catch (error) { log('error', 'anchor_failed', { ledger: 'event', error: errorCode(error) }); this.setMeta('cron_due:anchor', now + RETRY_MS); }
    }
    if (due('deliveries')) {
      // Once per cron: a failure waits for the next hour rather than hammering GitHub.
      this.sql.exec("DELETE FROM meta WHERE key = 'cron_due:deliveries'");
      try { await this.reconcileDeliveries(); }
      catch (error) {
        const code = errorCode(error);
        log('warning', 'hook_reconcile_failed', { error: code });
        this.setMeta('hooks_last_run', JSON.stringify({ at: new Date(now).toISOString(), ok: false, error: code }));
      }
    }
  }

  reconcileDeliveries() {
    return reconcileHookDeliveries({
      sql: this.sql, now: this.now, env: this.env, fetcher: this.deps.fetcher ?? fetch, deps: this.deps.github ?? {},
      meta: k => this.meta(k), setMeta: (k, v) => this.setMeta(k, v),
      inLedger: guid => this.byDelivery(guid) !== null,
      conflicted: guid => this.sql.exec("SELECT 1 FROM findings WHERE kind = 'delivery_conflict' AND delivery_id = ? LIMIT 1", guid).toArray().length > 0,
      operationalAlert: (code, key, detail) => this.operationalAlert(code, key, detail),
    });
  }

  // ---- External anchors (src/anchors.mjs) ----
  anchorAdapter() {
    const sql = this.sql, one = (q, ...b) => sql.exec(q, ...b).toArray()[0];
    return {
      ledger: 'event',
      headRow: () => this.headRow(),
      count: () => one('SELECT COUNT(*) AS n FROM events').n,
      countThrough: seq => one('SELECT COUNT(*) AS n FROM events WHERE seq <= ?', seq).n,
      entryAt: seq => { const r = one('SELECT * FROM events WHERE seq = ?', seq); return r ? entryOf(r) : null; },
      entriesBetween: (a, b) => sql.exec('SELECT * FROM events WHERE seq BETWEEN ? AND ? ORDER BY seq', a, b).toArray().map(entryOf),
      localLatest: () => one('SELECT * FROM anchors ORDER BY seq DESC LIMIT 1') ?? null,
      recordLocal: a => sql.exec('INSERT INTO anchors (seq, object_key, anchor_hash, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(seq) DO NOTHING', a.seq, a.object_key, a.anchor_hash, a.created_at),
      meta: k => this.meta(k), setMeta: (k, v) => this.setMeta(k, v),
    };
  }

  anchorBacklog() {
    const head = this.headRow(), last = this.sql.exec('SELECT MAX(seq) AS s FROM anchors').toArray()[0]?.s ?? 0;
    return (head?.seq ?? 0) - last;
  }

  // Verify against the latest external anchor; on success write the next one. A failed verification records
  // critical findings and stops further anchoring: a new anchor must never bless a truncated or rewritten ledger.
  async anchorCycle() {
    const adapter = this.anchorAdapter(), bucket = this.env.ANCHORS, now = this.now();
    const verified = await verifyAnchors(adapter, bucket, { advance: true });
    if (!verified.ok) { this.anchorProblems(verified.problems, now); return { ...publicVerify(verified), written: null }; }
    if (this.meta('anchor_blocked')) return { ...publicVerify(verified), written: null };
    const { written, problem } = await writeAnchor(adapter, bucket, verified.latest, now);
    if (problem) { this.anchorProblems([problem], now); return { ...publicVerify(verified), written: null }; }
    if (written && this.env.BACKUP_ANCHOR) enqueue(this.sql, { kind: 'anchor_backup', dedupe_key: 'anchor_backup:' + written.key, payload: written }, now);
    if (written) log('info', 'anchor_written', { ledger: 'event', seq: written.seq });
    return { ...publicVerify(verified), written };
  }

  anchorProblems(problems, now) {
    for (const p of problems) this.recordFinding(p.code, 'event:' + (p.anchor_seq ?? 0) + ':' + p.reason, null, anchorFindingDetail('event', p), now);
    if (!this.meta('anchor_blocked')) this.setMeta('anchor_blocked', JSON.stringify({ at: new Date(now).toISOString(), codes: problems.map(p => p.code + ':' + p.reason) }));
  }

  /** Read method: verification only (no findings, no anchor written). */
  async verifyAnchor() {
    const v = await verifyAnchors(this.anchorAdapter(), this.env.ANCHORS);
    return { ...publicVerify(v), blocked: this.meta('anchor_blocked') ? JSON.parse(this.meta('anchor_blocked')) : null };
  }

  findings(limit, cursor) {
    const n = boundedLimit(limit, 500, 100), before = optionalCursor(cursor);
    const rows = this.sql.exec('SELECT * FROM findings WHERE id < ? ORDER BY id DESC LIMIT ?', before ?? Number.MAX_SAFE_INTEGER, n).toArray()
      .map(r => ({ id: r.id, kind: r.kind, severity: severityOf(r.kind), delivery_id: r.delivery_id, detail: JSON.parse(r.detail), detected_at: r.detected_at }));
    return { ledger: 'event', items: rows, next_cursor: rows.length === n && rows.at(-1).id > 1 ? rows.at(-1).id : null };
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
    const anchor = this.sql.exec('SELECT seq, object_key, anchor_hash, created_at FROM anchors ORDER BY seq DESC LIMIT 1').toArray()[0];
    const json = k => { const v = this.meta(k); return v === null ? null : JSON.parse(v); };
    return { seq: head?.seq ?? 0, entry_hash: head?.entry_hash ?? GENESIS, last_checkpoint: checkpoint ? { ...checkpoint } : null, outbox: pendingCounts(this.sql),
      last_anchor: anchor ? { ...anchor } : null, anchor_blocked: json('anchor_blocked'), hook_reconcile: json('hooks_last_run') };
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

// Verification result without the internal `latest` handle.
function publicVerify({ latest: _internal, ...rest }) { return rest; }
