// Durable at-least-once outbox. Transient deliveries back off and escalate; backfills additionally
// have terminal deterministic errors, attempt/age limits and a pending-work quota. Terminal evidence is retained.
import { log, errorCode } from './log.mjs';

export const ESCALATE_AT = 8;
export const BACKFILL_MAX_ATTEMPTS = 12, BACKFILL_MAX_AGE_MS = 24 * 60 * 60_000, BACKFILL_MAX_PENDING = 100;
const TERMINAL_BACKFILL = new Set(['compare_too_many_commits', 'compare_too_large', 'compare_incomplete', 'github_body_too_large', 'bad_backfill', 'bad_compare_range']);
export const DEFER_MS = 30_000;
export const backoff = attempts => Math.min(30_000 * 2 ** Math.min(attempts, 10), 3_600_000);

export const OUTBOX_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error TEXT,
    created_at INTEGER NOT NULL, done_at INTEGER)`,
  'CREATE INDEX IF NOT EXISTS outbox_due ON outbox(done_at, next_attempt_at)',
];

export function enqueue(sql, { kind, dedupe_key, payload }, now) {
  if (kind === 'backfill' && sql.exec("SELECT COUNT(*) AS n FROM outbox WHERE kind = 'backfill' AND done_at IS NULL").toArray()[0].n >= BACKFILL_MAX_PENDING) {
    enqueue(sql, { kind: 'alert', dedupe_key: 'backfill-quota', payload: { schema: 'ghcaretaker-alert/v1', type: 'operational', code: 'backfill_quota_exhausted', detected_at: new Date(now).toISOString() } }, now);
    return false;
  }
  sql.exec('INSERT INTO outbox (kind, dedupe_key, payload, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(dedupe_key) DO NOTHING',
    kind, dedupe_key, JSON.stringify(payload), now, now);
}

export function nextDue(sql) {
  return sql.exec('SELECT MIN(next_attempt_at) AS t FROM outbox WHERE done_at IS NULL').toArray()[0]?.t ?? null;
}

export function pendingCounts(sql) {
  return Object.fromEntries(sql.exec('SELECT kind, COUNT(*) AS n, MAX(attempts) AS max_attempts FROM outbox WHERE done_at IS NULL GROUP BY kind')
    .toArray().map(r => [r.kind, { pending: r.n, max_attempts: r.max_attempts }]));
}

export function prune(sql, before) { sql.exec('DELETE FROM outbox WHERE done_at IS NOT NULL AND done_at < ?', before); }

// handlers: {kind: async payload => void}. A missing handler is a failure (retried), never a silent skip.
export async function drain(sql, handlers, { now, limit = 25, source }) {
  const rows = sql.exec('SELECT * FROM outbox WHERE done_at IS NULL AND next_attempt_at <= ? ORDER BY id LIMIT ?', now(), limit).toArray();
  for (const row of rows) {
    try {
      const handler = handlers[row.kind];
      if (!handler) throw Object.assign(new Error('no_handler'), { code: 'no_handler' });
      if (row.kind === 'backfill' && (row.attempts >= BACKFILL_MAX_ATTEMPTS || now() - row.created_at >= BACKFILL_MAX_AGE_MS)) throw Object.assign(new Error('backfill_retry_exhausted'), { code: 'backfill_retry_exhausted' });
      await handler(JSON.parse(row.payload));
      sql.exec('UPDATE outbox SET done_at = ?, last_error = NULL WHERE id = ?', now(), row.id);
    } catch (error) {
      // `deferred`: the handler ran out of this run's API budget. Not a failure: no attempt counted, retried shortly.
      if (error?.code === 'deferred') { sql.exec('UPDATE outbox SET next_attempt_at = ? WHERE id = ?', now() + DEFER_MS, row.id); continue; }
      const attempts = row.attempts + 1, code = errorCode(error);
      if (row.kind === 'backfill' && (TERMINAL_BACKFILL.has(code) || code === 'backfill_retry_exhausted' || attempts >= BACKFILL_MAX_ATTEMPTS || now() - row.created_at >= BACKFILL_MAX_AGE_MS)) {
        sql.exec('UPDATE outbox SET attempts = ?, done_at = ?, last_error = ? WHERE id = ?', attempts, now(), code, row.id);
        enqueue(sql, { kind: 'alert', dedupe_key: 'terminal:' + row.dedupe_key, payload: { schema: 'ghcaretaker-alert/v1', type: 'operational', code: 'backfill_incomplete_terminal', source, last_error: code, dedupe_key: row.dedupe_key, detected_at: new Date(now()).toISOString() } }, now());
        continue;
      }
      sql.exec('UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE id = ?', attempts, now() + backoff(attempts), code, row.id);
      log(row.kind === 'alert' ? 'critical' : 'warning', 'outbox_delivery_failed', { source, kind: row.kind, outbox_id: row.id, attempts, error: code });
      if (attempts === ESCALATE_AT && row.kind !== 'alert') {
        enqueue(sql, { kind: 'alert', dedupe_key: 'escalation:' + row.dedupe_key, payload: {
          schema: 'ghcaretaker-alert/v1', type: 'operational', code: 'downstream_retrying', source, target: row.kind,
          dedupe_key: row.dedupe_key, attempts, last_error: code, detected_at: new Date(now()).toISOString(),
        } }, now());
      }
    }
  }
  return rows.length;
}
