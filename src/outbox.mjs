// Durable at-least-once outbox inside a SQLite Durable Object. Rows are never dropped: a failing row backs off
// (30 s doubling to a 1 h ceiling) and keeps retrying; after ESCALATE_AT attempts an operational alert is queued.
import { log, errorCode } from './log.mjs';

export const ESCALATE_AT = 8;
export const backoff = attempts => Math.min(30_000 * 2 ** Math.min(attempts, 10), 3_600_000);

export const OUTBOX_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error TEXT,
    created_at INTEGER NOT NULL, done_at INTEGER)`,
  'CREATE INDEX IF NOT EXISTS outbox_due ON outbox(done_at, next_attempt_at)',
];

export function enqueue(sql, { kind, dedupe_key, payload }, now) {
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
      await handler(JSON.parse(row.payload));
      sql.exec('UPDATE outbox SET done_at = ?, last_error = NULL WHERE id = ?', now(), row.id);
    } catch (error) {
      const attempts = row.attempts + 1, code = errorCode(error);
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
