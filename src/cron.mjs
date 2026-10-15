// Cron triggers (wrangler.jsonc `triggers.crons`, docs/adr/0003). The Worker only flags work as due; each ledger's
// alarm does it, inside its own Durable Object, with its own API budget and retry state.
//   CRON_HOURLY: event ledger anchor + verification and hook-delivery reconciliation; every commit ledger's anchor.
//   CRON_REFS:   every commit ledger's ref reconciliation against GitHub's branches and tags.
import { eventLedger } from './webhook.mjs';
import { commitLedgerFor } from './observatory-read.mjs';
import { log, errorCode } from './log.mjs';

export const CRON_HOURLY = '7 * * * *';
export const CRON_REFS = '37 */6 * * *';
export const CRONS = Object.freeze([CRON_HOURLY, CRON_REFS]);

export async function runCron(cron, env) {
  if (!CRONS.includes(cron)) { log('error', 'cron_unknown', { cron: String(cron).slice(0, 64) }); return { ok: false, reason: 'unknown_cron' }; }
  const ledger = eventLedger(env);
  if (cron === CRON_HOURLY) await ledger.requestCron(['anchor', 'deliveries']);
  const repos = await ledger.ledgeredRepos(), tasks = cron === CRON_HOURLY ? ['anchor'] : ['refs'];
  const results = await Promise.allSettled(repos.map(id => commitLedgerFor(env, id).requestCron(tasks)));
  const failed = results.filter(r => r.status === 'rejected');
  for (const r of failed) log('error', 'cron_fanout_failed', { cron, error: errorCode(r.reason) });
  // Thrown so the platform records the invocation as failed; the work already flagged still runs.
  if (failed.length) throw new Error('cron fan-out incomplete: ' + failed.length + ' of ' + repos.length);
  return { ok: true, repos: repos.length };
}
