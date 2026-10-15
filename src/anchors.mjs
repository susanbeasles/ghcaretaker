// External checkpoint anchors (docs/adr/0003-completeness-and-anchors.md). A hash chain proves that the entries it
// holds were not edited in place; it cannot prove that its tail was not cut off, or that the whole chain was not
// recomputed after an edit. An anchor is a statement written outside the ledger's own storage, to the R2 bucket
// `observatory-anchors` (bucket lock; keys written once with If-None-Match: *):
//
//   anchors/<ledger>/<seq, 16 digits>.json = canonical({ledger, seq, head_hash, entry_count, created_at, prev_anchor_hash})
//
// `ledger` is `event` or `commit-<repo_id>`; `head_hash` is the entry_hash at `seq`; `entry_count` is the number of
// entries with seq <= `seq`; `prev_anchor_hash` is sha256(canonical text of the previous anchor), 64 zeros for the first.
// Runtime-independent: each ledger passes an adapter over its own SQLite tables.
import { GENESIS, canonical, entryHash, verifyEntries } from './chain.mjs';
import { CodedError, decodeUtf8, readBounded, sha256Hex } from './bytes.mjs';

export const ANCHOR_EVERY = 100;          // entries between anchors, in addition to the hourly cron
export const ANCHOR_VERIFY_WINDOW = 1000; // chain entries re-verified up to the anchored seq on every verification
export const ANCHOR_MAX_SEGMENT = 5000;   // entries certified by one new anchor (larger backlogs take several)
const MAX_LIST_PAGES = 50, MAX_CHAIN_STEPS = 100, MAX_ANCHOR_BYTES = 4096;
const LEDGER = /^(?:event|commit-[1-9][0-9]{0,15})$/;
const KEY = /^anchors\/(event|commit-[1-9][0-9]{0,15})\/([0-9]{16})\.json$/;
const HEX64 = /^[0-9a-f]{64}$/;
const FIELDS = ['created_at', 'entry_count', 'head_hash', 'ledger', 'prev_anchor_hash', 'seq'];

export const ANCHOR_SCHEMA = [
  'CREATE TABLE IF NOT EXISTS anchors (seq INTEGER PRIMARY KEY, object_key TEXT NOT NULL, anchor_hash TEXT NOT NULL, created_at TEXT NOT NULL)',
];

export const anchorPrefix = ledger => `anchors/${ledger}/`;
export const anchorKey = (ledger, seq) => anchorPrefix(ledger) + String(seq).padStart(16, '0') + '.json';

// Strict parse: exact field set, types, the key it was read from, and the canonical encoding itself.
export function parseAnchor(text, key) {
  let record;
  try { record = JSON.parse(text); } catch { throw new CodedError('anchor_malformed'); }
  const ok = record !== null && typeof record === 'object' && !Array.isArray(record)
    && Object.keys(record).sort().join() === FIELDS.join()
    && LEDGER.test(record.ledger) && Number.isSafeInteger(record.seq) && record.seq >= 1
    && Number.isSafeInteger(record.entry_count) && record.entry_count >= 0
    && HEX64.test(record.head_hash) && HEX64.test(record.prev_anchor_hash)
    && typeof record.created_at === 'string' && Number.isFinite(Date.parse(record.created_at))
    && key === anchorKey(record.ledger, record.seq) && canonical(record) === text;
  if (!ok) throw new CodedError('anchor_malformed');
  return record;
}

async function readAnchor(bucket, key) {
  const object = await bucket.get(key);
  if (!object) return null;
  const text = decodeUtf8(await readBounded(object.body, MAX_ANCHOR_BYTES));
  return { key, record: parseAnchor(text, key), hash: await sha256Hex(text) };
}

// Anchor keys after `startAfter` in ascending order (zero padding makes lexical order numeric). Keys that are not
// anchors of this ledger are ignored: anything else in the prefix cannot hide a real anchor.
async function listKeys(bucket, ledger, startAfter, max = Infinity) {
  const prefix = anchorPrefix(ledger), keys = [];
  let cursor, pages = 0;
  do {
    if (++pages > MAX_LIST_PAGES) throw new CodedError('anchor_list_too_long');
    const page = await bucket.list(cursor ? { prefix, cursor } : { prefix, ...(startAfter ? { startAfter } : {}) });
    for (const o of page.objects) {
      const m = KEY.exec(o.key);
      if (m && m[1] === ledger && (!startAfter || o.key > startAfter)) keys.push(o.key);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor && keys.length < max);
  return keys.slice(0, max);
}

// The latest anchor of `ledger` in the external store. Local state is only a starting point for the listing: the
// listing still finds anchors written after it, and a hint that no longer exists is itself evidence.
export async function latestAnchor(bucket, ledger, hintKey = null) {
  const keys = await listKeys(bucket, ledger, hintKey);
  const key = keys.at(-1) ?? hintKey;
  if (!key) return null;
  const anchor = await readAnchor(bucket, key);
  if (!anchor) throw new CodedError('anchor_missing');
  return anchor;
}

// Walks anchors after `from` ({key, hash, seq} of the last verified anchor, or null for the first) and checks each
// links to its predecessor. Bounded per call; the caller persists `through` to continue next time.
export async function verifyAnchorChain(bucket, ledger, from, maxSteps = MAX_CHAIN_STEPS) {
  let prevHash = from?.hash ?? GENESIS, prevSeq = from?.seq ?? 0, through = from ?? null, checked = 0;
  for (const key of await listKeys(bucket, ledger, from?.key ?? null, maxSteps)) {
    let anchor;
    try { anchor = await readAnchor(bucket, key); } catch (e) { return { ok: false, checked, through, at: key, reason: e.code ?? 'anchor_unreadable' }; }
    if (!anchor) return { ok: false, checked, through, at: key, reason: 'anchor_missing' };
    if (anchor.record.prev_anchor_hash !== prevHash) return { ok: false, checked, through, at: key, reason: 'prev_anchor_hash_mismatch' };
    if (anchor.record.seq <= prevSeq) return { ok: false, checked, through, at: key, reason: 'seq_not_increasing' };
    prevHash = anchor.hash; prevSeq = anchor.record.seq; through = { key, hash: anchor.hash, seq: anchor.record.seq }; checked++;
  }
  return { ok: true, checked, through };
}

// Recomputes [from, to] against the entry before it. Returns null when intact, else {seq, reason}.
async function chainBreak(adapter, from, to) {
  if (to < from) return null;
  let expectedPrev = GENESIS;
  if (from > 1) {
    const before = adapter.entryAt(from - 1);
    if (!before) return { seq: from - 1, reason: 'missing_entry' };
    expectedPrev = before.entry_hash;
  }
  const rows = adapter.entriesBetween(from, to), result = await verifyEntries(rows, expectedPrev, from);
  if (!result.ok) return result.first_break;
  if (result.checked !== to - from + 1) return { seq: from + result.checked, reason: 'missing_entry' };
  return null;
}

/**
 * Verifies the ledger against its latest external anchor:
 *  - tail_truncation: the ledger now holds fewer entries, or a lower head, than the anchor certified;
 *  - anchor_mismatch: the entry at the anchored seq is missing or does not hash to head_hash, entries up to it are
 *    missing or no longer chain, the anchors themselves do not chain, or local and external anchor records disagree.
 * adapter: {ledger, headRow(), count(), countThrough(seq), entryAt(seq), entriesBetween(a, b), localLatest(),
 *           meta(key), setMeta(key, value)}. `advance` persists the anchor-chain verification pointer.
 */
export async function verifyAnchors(adapter, bucket, { advance = false } = {}) {
  if (!bucket) throw new CodedError('anchors_unbound');
  const problems = [], local = adapter.localLatest(), head = adapter.headRow(), headSeq = head?.seq ?? 0, count = adapter.count();
  const out = (latest, chain = null) => ({
    ok: problems.length === 0, ledger: adapter.ledger, head_seq: headSeq, entry_count: count, problems, chain,
    anchor: latest ? { key: latest.key, anchor_hash: latest.hash, ...latest.record } : null, latest,
  });
  let latest;
  try { latest = await latestAnchor(bucket, adapter.ledger, local?.object_key ?? null); }
  catch (e) {
    if (!['anchor_missing', 'anchor_malformed'].includes(e?.code)) throw e;
    problems.push({ code: 'anchor_mismatch', reason: e.code, anchor_key: local?.object_key ?? null });
    return out(null);
  }
  if (!latest) {
    if (local) problems.push({ code: 'anchor_mismatch', reason: 'anchors_missing', anchor_key: local.object_key });
    return out(null);
  }
  const a = latest.record, at = { anchor_seq: a.seq, anchor_hash: latest.hash };
  if (local && local.seq === a.seq && local.anchor_hash !== latest.hash) problems.push({ code: 'anchor_mismatch', reason: 'local_anchor_differs', ...at });
  if (headSeq < a.seq || count < a.seq) problems.push({ code: 'tail_truncation', reason: headSeq < a.seq ? 'head_below_anchor' : 'count_below_anchor', head_seq: headSeq, entry_count: count, ...at });
  else {
    let entry = null, unreadable = false;
    try { entry = adapter.entryAt(a.seq); } catch { unreadable = true; }
    if (!entry) problems.push({ code: 'anchor_mismatch', reason: unreadable ? 'anchored_entry_unreadable' : 'anchored_entry_missing', ...at });
    else if (entry.entry_hash !== a.head_hash || await entryHash(entry) !== a.head_hash) problems.push({ code: 'anchor_mismatch', reason: 'head_hash', ...at });
    const through = adapter.countThrough(a.seq);
    if (through < a.entry_count) problems.push({ code: 'anchor_mismatch', reason: 'entries_missing', entry_count_through_anchor: through, ...at });
    let broken = null;
    try { broken = await chainBreak(adapter, Math.max(1, a.seq - ANCHOR_VERIFY_WINDOW + 1), a.seq); } catch { broken = { seq: null, reason: 'unparseable_entry' }; }
    if (broken) problems.push({ code: 'anchor_mismatch', reason: 'chain_break', first_break: broken, ...at });
  }
  const pointer = adapter.meta('anchor_chain_verified');
  const chain = await verifyAnchorChain(bucket, adapter.ledger, pointer ? JSON.parse(pointer) : null);
  if (!chain.ok) problems.push({ code: 'anchor_mismatch', reason: 'anchor_chain', chain_reason: chain.reason, at_key: chain.at, ...at });
  else if (advance && chain.through) adapter.setMeta('anchor_chain_verified', JSON.stringify(chain.through));
  return out(latest, { ok: chain.ok, checked: chain.checked, verified_through_seq: chain.through?.seq ?? null });
}

/**
 * Writes the next anchor after a verification that passed (`latest` from verifyAnchors). Certifies at most
 * ANCHOR_MAX_SEGMENT entries past the previous anchor, and only after re-verifying that segment links to it.
 * Returns {written: record|null, problem: {...}|null}. Never overwrites: an existing key is adopted only if it says
 * exactly the same thing apart from created_at.
 * VERIFY https://developers.cloudflare.com/r2/buckets/bucket-locks/ and
 * https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#r2putoptions : a locked bucket accepts new
 * keys, `onlyIf` If-None-Match: * returns null for an existing key, and `list` honours `startAfter`.
 */
export async function writeAnchor(adapter, bucket, latest, nowMs) {
  const head = adapter.headRow();
  if (!head) return { written: null, problem: null };
  const fromSeq = latest ? latest.record.seq : 0;
  if (head.seq <= fromSeq) return { written: null, problem: null };
  const seq = Math.min(head.seq, fromSeq + ANCHOR_MAX_SEGMENT);
  let broken;
  try { broken = await chainBreak(adapter, fromSeq + 1, seq); } catch { broken = { seq: fromSeq + 1, reason: 'unparseable_entry' }; }
  if (!broken && latest && adapter.entryAt(fromSeq)?.entry_hash !== latest.record.head_hash) broken = { seq: fromSeq, reason: 'anchored_entry_changed' };
  if (broken) return { written: null, problem: { code: 'anchor_mismatch', reason: 'chain_break', first_break: broken, anchor_seq: fromSeq } };
  const entry = adapter.entryAt(seq);
  const record = { ledger: adapter.ledger, seq, head_hash: entry.entry_hash, entry_count: adapter.countThrough(seq), created_at: new Date(nowMs).toISOString(), prev_anchor_hash: latest ? latest.hash : GENESIS };
  const key = anchorKey(adapter.ledger, seq), text = canonical(record);
  let hash = await sha256Hex(text);
  const put = await bucket.put(key, text, { onlyIf: new Headers({ 'if-none-match': '*' }), sha256: hash, httpMetadata: { contentType: 'application/json' }, customMetadata: { anchor_hash: hash } });
  let written = record;
  if (put === null) {
    // Written by an earlier attempt whose local bookkeeping did not complete. Never rewrite; adopt it only if it agrees.
    let existing = null;
    try { existing = await readAnchor(bucket, key); } catch { existing = null; }
    const same = existing && ['ledger', 'seq', 'head_hash', 'entry_count', 'prev_anchor_hash'].every(k => existing.record[k] === record[k]);
    if (!same) return { written: null, problem: { code: 'anchor_mismatch', reason: 'anchor_key_conflict', anchor_seq: seq, anchor_key: key } };
    written = existing.record; hash = existing.hash;
  }
  adapter.recordLocal({ seq, object_key: key, anchor_hash: hash, created_at: written.created_at });
  return { written: { ...written, key, anchor_hash: hash }, problem: null };
}

/**
 * Secondary anchor seam (docs/adr/0003, decision 6). The backup service's BackupIngest.capture accepts exactly
 * {repo_id, reason, delivery_id} and nothing else, so anchors cannot ride on it. A future backup entrypoint that
 * stores each anchor in B2 with Object Lock COMPLIANCE binds here as `BACKUP_ANCHOR` (service `backup`, entrypoint
 * `BackupAnchor`). It is deliberately unbound in wrangler.jsonc until that entrypoint exists.
 * @typedef {{ledger: string, seq: number, head_hash: string, entry_count: number, created_at: string, prev_anchor_hash: string}} AnchorRecord
 * @typedef {{anchor(record: AnchorRecord & {key: string, anchor_hash: string}): Promise<{ok: true} | {ok: false, code: string}>}} AnchorSink
 */
export async function sendBackupAnchor(env, payload) {
  if (!env.BACKUP_ANCHOR) throw new CodedError('backup_anchor_unbound');
  const result = await env.BACKUP_ANCHOR.anchor(payload);
  if (result?.ok !== true) throw new CodedError('backup_anchor_' + (typeof result?.code === 'string' ? result.code.replace(/[^a-z0-9_]/g, '').slice(0, 40) : 'refused'));
}

// Finding detail for a verification problem: identifiers and hashes only.
export const anchorFindingDetail = (ledger, problem) => ({ ledger, ...problem });
