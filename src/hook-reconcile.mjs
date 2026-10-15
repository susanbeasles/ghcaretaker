// Missed-delivery reconciliation against GitHub's own delivery log (docs/adr/0003, decision 4a). Runs in the event
// ledger Durable Object on the hourly cron. Uses only the App JWT (App-level endpoints need no installation
// permission): GET /app/hook/deliveries (cursor-paginated, newest first) and POST /app/hook/deliveries/{id}/attempts.
//
// A delivery is redelivered when its guid (the X-GitHub-Delivery we ledger) is not in the event ledger, or when none
// of its attempts was a success. Never for a guid with a delivery_conflict finding (redelivery cannot fix that).
// Bounded: at most MAX_DELIVERY_PAGES pages read and MAX_REDELIVERIES_PER_RUN redeliveries per run, at most
// MAX_ATTEMPTS_PER_GUID redeliveries per guid, spaced REDELIVERY_SPACING_MS apart. State lives in the ledger's SQLite.
// Nothing from a request or response body is read, stored or logged: ids, guids, status codes and counts only.
import { appJwt, listHookDeliveries, redeliverHookDelivery } from './github-app.mjs';
import { log, errorCode } from './log.mjs';

export const MAX_DELIVERY_PAGES = 10, MAX_REDELIVERIES_PER_RUN = 20, MAX_ATTEMPTS_PER_GUID = 3;
export const REDELIVERY_SPACING_MS = 3_600_000, OVERLAP_MS = 3_600_000, LOOKBACK_MS = 3 * 86_400_000;

export const HOOK_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS hook_redeliveries (guid TEXT PRIMARY KEY, attempts INTEGER NOT NULL, last_attempt_at INTEGER NOT NULL,
    last_hook_delivery_id INTEGER NOT NULL, last_result TEXT NOT NULL)`,
];

const success = d => d.status_code >= 200 && d.status_code < 300;

/**
 * ctx: {sql, now, env, fetcher, meta(k), setMeta(k, v), inLedger(guid), conflicted(guid), operationalAlert(code, key, detail),
 *       deps: {appJwt?, listHookDeliveries?, redeliverHookDelivery?}}
 * State (meta `hooks_state`): {watermark, pending_watermark, resume_cursor}. A run that reaches the watermark (minus
 * OVERLAP_MS) or the end of GitHub's log advances the watermark; a run cut short by the page cap stores the cursor
 * and the next run continues from it before scanning newer deliveries again.
 */
export async function reconcileHookDeliveries(ctx) {
  const { sql, now, env, fetcher } = ctx, deps = ctx.deps ?? {}, started = now();
  const list = deps.listHookDeliveries ?? listHookDeliveries, redeliver = deps.redeliverHookDelivery ?? redeliverHookDelivery;
  const state = JSON.parse(ctx.meta('hooks_state') ?? '{}');
  const jwt = await (deps.appJwt ?? appJwt)(env);
  const floor = (state.watermark ?? started - LOOKBACK_MS) - OVERLAP_MS, resuming = typeof state.resume_cursor === 'string';
  let cursor = resuming ? state.resume_cursor : null, pages = 0, reachedEnd = false, newest = null, invalid = 0;
  const byGuid = new Map();
  while (pages < MAX_DELIVERY_PAGES) {
    let page;
    try { page = await list(jwt, cursor, fetcher); }
    catch (e) {
      // An expired or rejected resume cursor: start over from the newest delivery next time.
      if (resuming && e?.status >= 400 && e?.status < 500) { ctx.setMeta('hooks_state', JSON.stringify({ ...state, resume_cursor: null })); }
      throw e;
    }
    pages++; invalid += page.invalid;
    let older = false;
    for (const d of page.items) {
      newest = Math.max(newest ?? 0, d.delivered_at);
      if (d.delivered_at < floor) { older = true; continue; }
      if (!byGuid.has(d.guid)) byGuid.set(d.guid, []);
      byGuid.get(d.guid).push(d);
    }
    cursor = page.next_cursor;
    if (older || cursor === null) { reachedEnd = true; break; }
  }

  const counts = { scanned: byGuid.size, missing: 0, unacknowledged: 0, redelivered: 0, failed: 0, skipped_conflict: 0, skipped_exhausted: 0, skipped_spacing: 0, deferred: 0 };
  const oldestFirst = [...byGuid].sort((a, b) => Math.min(...a[1].map(d => d.delivered_at)) - Math.min(...b[1].map(d => d.delivered_at)));
  for (const [guid, attempts] of oldestFirst) {
    const inLedger = ctx.inLedger(guid);
    if (inLedger && attempts.some(success)) continue;
    if (ctx.conflicted(guid)) { counts.skipped_conflict++; continue; }
    counts[inLedger ? 'unacknowledged' : 'missing']++;
    const row = sql.exec('SELECT attempts, last_attempt_at FROM hook_redeliveries WHERE guid = ?', guid).toArray()[0];
    if (row && row.attempts >= MAX_ATTEMPTS_PER_GUID) {
      counts.skipped_exhausted++;
      if (!inLedger) ctx.operationalAlert('redelivery_exhausted', guid, { delivery_id: guid, attempts: row.attempts });
      continue;
    }
    if (row && started - row.last_attempt_at < REDELIVERY_SPACING_MS) { counts.skipped_spacing++; continue; }
    if (counts.redelivered + counts.failed >= MAX_REDELIVERIES_PER_RUN) { counts.deferred++; continue; }
    const latest = attempts.reduce((a, b) => (b.delivered_at > a.delivered_at ? b : a));
    let result = 'requested';
    try { await redeliver(jwt, latest.id, fetcher); counts.redelivered++; }
    catch (e) { result = errorCode(e); counts.failed++; }
    const n = (row?.attempts ?? 0) + 1;
    sql.exec(`INSERT INTO hook_redeliveries (guid, attempts, last_attempt_at, last_hook_delivery_id, last_result) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(guid) DO UPDATE SET attempts = excluded.attempts, last_attempt_at = excluded.last_attempt_at, last_hook_delivery_id = excluded.last_hook_delivery_id, last_result = excluded.last_result`,
    guid, n, started, latest.id, result);
    log('warning', 'hook_redelivery', { delivery_id: guid, hook_delivery_id: latest.id, in_ledger: inLedger, attempts: n, result });
  }

  const next = { ...state };
  if (reachedEnd) {
    next.watermark = resuming ? (state.pending_watermark ?? newest ?? state.watermark ?? null) : (newest ?? state.watermark ?? null);
    next.pending_watermark = null; next.resume_cursor = null;
  } else {
    if (!resuming) next.pending_watermark = newest;
    next.resume_cursor = cursor;
  }
  ctx.setMeta('hooks_state', JSON.stringify(next));
  const lastRun = { at: new Date(started).toISOString(), ok: true, pages, invalid, complete: reachedEnd, resumed: resuming, ...counts };
  ctx.setMeta('hooks_last_run', JSON.stringify(lastRun));
  if (counts.missing || counts.unacknowledged) log('warning', 'hook_reconcile', lastRun);
  return lastRun;
}
