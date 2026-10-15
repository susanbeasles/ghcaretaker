// Read API for the caretaker dashboard and the metrics collector (ADR-0001 section 3). Internal functions only:
// no route exposes them yet. The dashboard must sit behind Access and validate Cf-Access-Jwt-Assertion before
// calling any of these. Every function validates its inputs and returns plain JSON-serialisable data.
import { CodedError, decodeUtf8, readBounded, sha256Hex } from './bytes.mjs';
import { MAX_BODY_BYTES } from './webhook.mjs';

const eventLedger = env => env.EVENT_LEDGER.get(env.EVENT_LEDGER.idFromName('global'));
const repoIdArg = id => { if (!Number.isSafeInteger(id) || id < 1) throw new CodedError('bad_repo_id'); return id; };
export const commitLedgerFor = (env, repoId) => env.COMMIT_LEDGER.get(env.COMMIT_LEDGER.idFromName(String(repoIdArg(repoId))));

/** Newest first. `cursor` is the `next_cursor` of the previous page (an exclusive upper seq bound). */
export const recentEvents = (env, limit = 50, cursor = null) => eventLedger(env).recent(limit, cursor);

/** {seq, entry_hash, last_checkpoint, outbox} of the event ledger. */
export const ledgerHead = env => eventLedger(env).head();

/** Recompute the event ledger chain over [fromSeq, toSeq] (at most 5000 entries per call). */
export const verifyLedger = (env, fromSeq, toSeq) => eventLedger(env).verify(fromSeq, toSeq);

/** Newest first ledger entries of one repository plus that ledger's head. */
export async function commitLedger(env, repoId, limit = 50, cursor = null) {
  const stub = commitLedgerFor(env, repoId);
  const [page, head] = await Promise.all([stub.entries(limit, cursor), stub.head()]);
  return { head, ...page };
}

export const verifyCommitLedger = (env, repoId, fromSeq, toSeq) => commitLedgerFor(env, repoId).verify(fromSeq, toSeq);

/** Findings of one repository, or of every repository the event ledger has seen (fan-out, newest first). */
export async function findings(env, repoId) {
  if (repoId !== undefined && repoId !== null) return (await commitLedgerFor(env, repoId).findings(100)).items;
  const repos = await eventLedger(env).repos();
  const pages = await Promise.all(repos.map(r => commitLedgerFor(env, r.repo_id).findings(100)));
  return pages.flatMap(p => p.items.map(f => ({ ...f, repo_id: p.repo_id }))).sort((a, b) => b.detected_at.localeCompare(a.detected_at));
}

/** Raw delivery payload from R2, digest-checked (bound allows for JSON-escaping of the raw body). For the metrics collector; never render it unescaped. */
export async function readDelivery(env, objectKey, bodySha256) {
  if (!/^deliveries\/\d{4}\/\d{2}\/\d{2}\/[0-9a-f-]{36}\.json$/.test(objectKey ?? '')) throw new CodedError('bad_object_key');
  const object = await env.EVENTS.get(objectKey);
  if (!object) throw new CodedError('delivery_missing');
  const record = JSON.parse(decodeUtf8(await readBounded(object.body, 3 * MAX_BODY_BYTES)));
  if (record.v !== 1 || typeof record.body !== 'string' || record.body_sha256 !== bodySha256 || await sha256Hex(record.body) !== bodySha256) throw new CodedError('delivery_digest_mismatch');
  return { ...record, payload: JSON.parse(record.body) };
}
