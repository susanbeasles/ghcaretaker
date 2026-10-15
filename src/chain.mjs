// Hash chain shared by the event ledger and the commit ledgers.
// entry_hash = sha256_hex( prev_hash || canonical(entry without entry_hash) ), genesis prev_hash = 64 zeros.
import { sha256Hex } from './bytes.mjs';

export const GENESIS = '0'.repeat(64);

// Canonical JSON: object keys sorted by UTF-16 code unit, no whitespace, integers only, undefined refused.
// Restricting numbers to safe integers keeps the encoding identical across runtimes (no float formatting).
export function canonical(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string': return JSON.stringify(value);
    case 'boolean': return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new TypeError('canonical: only safe integers are allowed');
      return String(value);
    case 'object':
      if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
      return '{' + Object.keys(value).sort().map(k => {
        if (value[k] === undefined) throw new TypeError('canonical: undefined value for ' + k);
        return JSON.stringify(k) + ':' + canonical(value[k]);
      }).join(',') + '}';
    default: throw new TypeError('canonical: unsupported type ' + typeof value);
  }
}

export async function entryHash(entry) {
  const { entry_hash: _ignored, ...rest } = entry;
  if (typeof rest.prev_hash !== 'string') throw new TypeError('entry requires prev_hash');
  return sha256Hex(rest.prev_hash + canonical(rest));
}

// Links new bodies after `head` ({seq, entry_hash} or null). Returns complete entries in order.
export async function link(head, bodies) {
  let seq = head ? head.seq : 0, prev = head ? head.entry_hash : GENESIS;
  const out = [];
  for (const body of bodies) {
    const entry = { ...body, seq: seq + 1, prev_hash: prev };
    entry.entry_hash = await entryHash(entry);
    out.push(entry);
    seq = entry.seq; prev = entry.entry_hash;
  }
  return out;
}

// Recomputes a contiguous run. `expectedPrev` is the entry_hash before entries[0] (GENESIS for seq 1).
// Reports the first break only: what failed and where, so an operator knows where to start reading.
export async function verifyEntries(entries, expectedPrev, expectedStartSeq) {
  let prev = expectedPrev, seq = expectedStartSeq, checked = 0;
  for (const entry of entries) {
    if (entry.seq !== seq) return { ok: false, checked, first_break: { seq, reason: 'missing_entry' } };
    if (entry.prev_hash !== prev) return { ok: false, checked, first_break: { seq, reason: 'prev_hash_mismatch' } };
    if (await entryHash(entry) !== entry.entry_hash) return { ok: false, checked, first_break: { seq, reason: 'entry_hash_mismatch' } };
    prev = entry.entry_hash; seq++; checked++;
  }
  return { ok: true, checked, first_break: null, last: checked ? { seq: seq - 1, entry_hash: prev } : null };
}

// Validated verify range: at most `max` entries per call so a Durable Object stays inside its CPU budget.
export function verifyRange(fromSeq, toSeq, headSeq, max = 5000) {
  const from = fromSeq ?? 1, to = Math.min(toSeq ?? headSeq, headSeq, from + max - 1);
  if (!Number.isSafeInteger(from) || from < 1 || !Number.isSafeInteger(to)) throw new TypeError('invalid verify range');
  return { from, to };
}

// In-memory serialization for async hash computation followed by a synchronous SQL transaction.
export function mutex() {
  let tail = Promise.resolve();
  return fn => { const run = tail.then(() => fn()); tail = run.catch(() => {}); return run; };
}
