// Pure integrity rules from ADR-0001 section 2. Each finding is an alert.
export const MAIN = 'refs/heads/main';
export const ZERO = /^0+$/;
export const PROMOTION_GRACE_MS = 15 * 60 * 1000;

export const FINDING_KINDS = Object.freeze([
  'main_forced_update', 'main_deleted', 'tag_forced_update', 'tag_deleted', 'tag_moved',
  'main_commit_unverified', 'main_commit_multiple_parents', 'main_commit_missing_promotion_tag',
  // Completeness and tamper evidence (ADR-0003 of this repository).
  'force_push', 'ref_gap', 'ref_drift', 'incomplete_push', 'delivery_conflict', 'tail_truncation', 'anchor_mismatch',
]);

// Carried in every alert. `critical`: integrity of main, tags or a ledger is in doubt. `high`: the ledger and GitHub
// disagree in a way the ledger cannot explain. `warning`: expected in normal use but worth a look.
export const FINDING_SEVERITY = Object.freeze({
  main_forced_update: 'critical', main_deleted: 'critical', tag_forced_update: 'critical', tag_deleted: 'critical', tag_moved: 'critical',
  main_commit_unverified: 'critical', main_commit_multiple_parents: 'critical', main_commit_missing_promotion_tag: 'critical',
  delivery_conflict: 'critical', tail_truncation: 'critical', anchor_mismatch: 'critical',
  ref_drift: 'high', force_push: 'warning', ref_gap: 'warning', incomplete_push: 'warning',
});
export const severityOf = kind => FINDING_SEVERITY[kind] ?? 'high';

// The ref this ledger last recorded ({sha, deleted} or null) against an incoming push. A push whose `before` is not
// that head was delivered late, out of order, or after a missed delivery: a gap. Returns null when in sequence, or
// when the push only confirms the recorded head (a reconciliation already moved the ref there).
export function refGap(recorded, push) {
  if (!recorded) return null;
  const head = recorded.deleted ? null : recorded.sha;
  if (head === null ? ZERO.test(push.before) : push.before === head) return null;
  if (head !== null && !push.deleted && push.after === head) return null;
  return { recorded_head: head, recorded_deleted: Boolean(recorded.deleted) };
}

// The generic forced-push record for every ref (main and tags additionally raise their own rule above).
export function forcePushFinding(update) {
  return update.forced ? [{ kind: 'force_push', ref: update.ref, sha: update.after, detail: { before: update.before, after: update.after } }] : [];
}

const isTag = ref => ref.startsWith('refs/tags/');

// update: ref_update data; previousTarget: last sha this ledger saw for the ref (null if never seen).
export function refFindings(update, previousTarget) {
  const out = [], { ref, before, after, created, deleted, forced } = update;
  if (ref === MAIN) {
    if (deleted) out.push({ kind: 'main_deleted', ref, sha: before, detail: { before } });
    else if (forced) out.push({ kind: 'main_forced_update', ref, sha: after, detail: { before, after } });
  } else if (isTag(ref)) {
    if (deleted) out.push({ kind: 'tag_deleted', ref, sha: before, detail: { before } });
    else {
      if (forced) out.push({ kind: 'tag_forced_update', ref, sha: after, detail: { before, after } });
      // A tag pointing somewhere new: an in-place update, or a re-creation after deletion to a different target.
      const prior = created ? previousTarget : before;
      if (prior && !ZERO.test(prior) && prior !== after) out.push({ kind: 'tag_moved', ref, sha: after, detail: { from: prior, to: after } });
    }
  }
  return out;
}

// Rules for one commit arriving on main. Fail closed: anything other than verified === true is unverified.
export function mainCommitFindings(details) {
  const out = [];
  if (details.verified !== true) out.push({ kind: 'main_commit_unverified', ref: MAIN, sha: details.sha, detail: { reason: details.verification_reason ?? 'unknown' } });
  if (Array.isArray(details.parents) && details.parents.length > 1) out.push({ kind: 'main_commit_multiple_parents', ref: MAIN, sha: details.sha, detail: { parents: details.parents } });
  return out;
}

// Commits that arrived on main with this push: the pushed list plus the new tip (covers empty or truncated lists).
export function mainCommits(push) {
  if (push.ref !== MAIN || push.deleted) return [];
  const list = [...push.commits];
  if (push.after && !ZERO.test(push.after) && !list.includes(push.after)) list.push(push.after);
  return list;
}

// `promote/pr-<n>-<first 12 hex of S>` (ADR-0001 section 1 step 6). Returns the 12-hex prefix or null.
export function promotionTagPrefix(tag) {
  const m = /^(?:refs\/tags\/)?promote\/pr-[1-9]\d{0,9}-([0-9a-f]{12})$/.exec(tag ?? '');
  return m ? m[1] : null;
}
