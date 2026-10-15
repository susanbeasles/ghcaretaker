# ADR-0003 (ghcaretaker): Completeness of the observatory and external anchors

Status: accepted for implementation, not activated
Date: 2026-10-15
Implements: owner requirements for a complete and tamper-evident observatory; builds on ADR-0001 and ADR-0002 of this
repository and on infra-root `docs/adr/0001-pipeline-surround.md` section 2 (event capture, ledgers).

## Context

ADR-0001 records every delivery GitHub sends and chains the ledgers. That leaves four gaps: a delivery GitHub never
sent, or that we answered without storing, is invisible; push payloads list a bounded number of commits; deliveries
arrive in any order; and a hash chain proves the entries it holds were not edited, not that its tail was not cut off
or that the whole chain was not recomputed after an edit.

## Decisions

1. **The acknowledgement is the durability point.** `POST /github` answers 2xx only after the R2 create-only write
   (`If-None-Match: *`) and the event-ledger commit have both completed, or when an identical delivery was already
   committed. Every failure before that is a 5xx (proved by `test/durability.test.mjs`, which holds each effect open
   and injects a failure at each step). An identical delivery that is in flight is waited on for up to 8 s (GitHub
   times out at 10 s): it then answers 202 as a duplicate, takes over a released reservation, or answers 503. It
   is never a 409 any more. VERIFY that a Durable Object RPC result is only returned once its SQLite writes are
   durable (output gates): https://developers.cloudflare.com/durable-objects/api/storage-api/

2. **Same delivery id, different content: never overwrite, record and alert.** Answered 409 (the only 4xx after
   authentication), and recorded once as a `delivery_conflict` finding in the event ledger with both body digests,
   the event name and whether it collided with a ledgered entry or an in-flight reservation. Never the bodies. The
   second body is not written anywhere. Hook-delivery reconciliation never redelivers such a guid.

3. **The ledger order is arrival order; domain state is not.** The commit ledger records every `ref_update` as it
   arrived. Its per-ref head table is derived state: a push whose `before` is not the recorded head is a `ref_gap`
   finding (`recorded_head`, `before`, `after`). The head then follows the push, the range from the recorded head to
   `before` (the missed push, or nothing for a late one) is backfilled through compare, and a ref reconciliation is
   scheduled 10 minutes later. That reconciliation settles the head against GitHub. Out-of-order and in-order
   deliveries converge to the same heads and commit set (`test/completeness.test.mjs`); only the ledger entries and
   the gap findings differ, which is the record of what arrived when. The metrics collector already converges by
   status rank (ADR-0002) and is unchanged.

4. **Truncated pushes are completed from the compare API; every commit says where it came from.** A push is
   *possibly truncated* when it lists 20 or more commits, more than the 2048 we keep, or fewer than its `size`. The
   owner's figure is 20; the webhook reference says 2048 (VERIFY). Treating 20 or more as possibly truncated is safe
   either way: it only costs a compare call. Such a push is fetched with
   `GET /repos/{r}/compare/{before}...{after}`, paginated, at most 1000 commits and 32 MiB. A created branch compares
   against the default branch; a deletion needs nothing. Commit entries carry `source: webhook | api_compare`. The
   compare items carry `commit.verification`, so no per-commit lookups are needed. When compare fails (3 inline
   attempts) or exceeds the bounds, the commits the payload listed are recorded, the `ref_update` says
   `complete: false`, an `incomplete_push` finding is raised and a `backfill` outbox row retries forever with
   backoff and escalation. When it succeeds it appends a `reconcile` entry with `complete: true`. A forced push is a
   `force_push` finding with old and new heads for every ref (main and tags also raise their ADR-0001 rule). Commits
   the new head no longer contains stay in the ledger. Nothing is ever deleted. Commits that reach `main` through
   compare or reconciliation are judged by the same main-branch rules and promotion checks.

5. **Reconciliation against GitHub.** (a) Hourly, the event ledger reads `GET /app/hook/deliveries` with the App
   JWT. This is an App-level endpoint, so no new installation permission is needed. It redelivers
   (`POST /app/hook/deliveries/{id}/attempts`) every guid that is not in the ledger, and every guid none of whose
   attempts succeeded. Limits: at most 20 per run, 3 per guid, 1 h apart, 10 pages per run. A run cut short stores
   its cursor and the next run resumes from it before moving the watermark. A guid that exhausts its attempts and
   is still missing raises an operational alert. (b) Every six hours each commit ledger lists `refs/heads` and
   `refs/tags` through `git/matching-refs` (installation token, contents:read) and settles each difference with a
   `reconcile` entry. A first complete listing is a baseline (`complete: false`, no findings). A fast-forward is
   backfilled through compare and needs no finding, because compare explains it. An unobserved deletion,
   creation, tag move or history rewrite is a `ref_drift` finding. The synthetic update also gets the ADR-0001
   rules (`main_deleted`, `main_forced_update`, `tag_moved`, ...) and, for a rewrite, `force_push`. A capped
   listing proves nothing about absent refs. Refs updated in the last 10 minutes are left to their in-flight
   deliveries, and nothing runs while the inbox holds a delivery. Cursors, watermarks, attempts and last-run
   state live in each Durable Object's SQLite (`meta`, `hook_redeliveries`).

6. **External anchors.** On the hourly cron and every 100 entries, each ledger (`event`, `commit-<repo_id>`) writes
   `canonical({ledger, seq, head_hash, entry_count, created_at, prev_anchor_hash})` to R2 `observatory-anchors` at
   `anchors/<ledger>/<seq, 16 digits>.json`, create-only. A bucket lock covers that prefix. Before writing, the
   ledger verifies itself against the latest anchor. The latest anchor is found by listing the bucket, not by
   trusting local state. The checks: the ledger still has at least `seq` entries and its head is at least `seq`;
   the entry at `seq` recomputes to `head_hash`; the count through `seq` equals `entry_count`; the 1000 entries up
   to `seq` chain; and the anchors themselves chain through `prev_anchor_hash`. A failure is a critical
   `tail_truncation` or `anchor_mismatch` finding with an alert, and **anchoring of that ledger stops**: a new
   anchor must never bless a truncated or rewritten ledger. The same check, without side effects, is the read
   method `verifyLedgerAnchor` / `verifyCommitLedgerAnchor`. An R2 outage is retried in 5 minutes and is not
   evidence. The anchors are separate from the hourly `checkpoints/` in `github-events` (ADR-0001), which stay and
   are weaker because they share the bucket of the data they vouch for.

7. **Secondary anchor: a seam, unbound.** The backup service's `BackupIngest.capture` accepts exactly
   `{repo_id, reason, delivery_id}` and rejects any other key, so it cannot carry anchors. Repurposing it would also
   start a capture job. The seam is `BACKUP_ANCHOR` (service `backup`, entrypoint `BackupAnchor`,
   `anchor(record) -> {ok: true} | {ok: false, code}`, see `src/anchors.mjs`). When it is bound, every written anchor
   is sent through the outbox and retried until accepted. It is not bound in `wrangler.jsonc`, and `check-config`
   refuses binding it to `BackupIngest`.

8. **Severity travels with every alert** (`critical`, `high`, `warning`, from `FINDING_SEVERITY` in
   `src/integrity.mjs`). Findings, alerts and logs carry identifiers, digests, shas and ref names only: never
   payload bodies, commit messages, tokens or keys.

## What this proves, and what it does not

Proves, provided the anchor store is honest:

- No entry at or below the latest anchored `seq` was removed or changed. Truncating the tail below it, deleting a
  middle row, or rewriting an entry and recomputing every later hash are all detected at the next verification.
- The ledger was not rolled back below that anchor, and no anchor in the verified part of the anchor chain was
  replaced or removed. A removed latest anchor is detected through the local pointer to it. A removed older one is
  detected by the chain walk.
- A delivery is acknowledged only once it is durable. GitHub's own log of the last days is compared against the
  ledger hourly, and GitHub's current refs every six hours.

Does not prove:

- **The unanchored tail.** Entries after the latest anchor (at most 100 entries or about an hour) can be removed
  without a trace from the anchors. Hook-delivery reconciliation would redeliver them while GitHub still lists
  them (about 3 days, VERIFY), and the ref reconciliation covers their effect on refs. Nothing covers other event
  types beyond that window.
- **A compromised Worker or deployment.** Whoever can deploy this Worker can write new anchors (create-only stops
  overwrites, not new keys). They can certify forged entries from that point on. Anchors protect history up to the
  last anchor written before the compromise.
- **The Cloudflare account administrator.** An account admin can change or remove the bucket lock rule, then
  delete or overwrite anchors. They can also delete the Durable Objects, and redeploy the Worker without these
  checks. Bucket lock is a policy the admin controls, so `observatory-anchors` is evidence against everyone except
  the admin. The stronger anchor is **B2 Object Lock in COMPLIANCE mode through the backup service**, on a
  different provider with different credentials: there the retention cannot be shortened or removed by anyone,
  the B2 account owner included, until it expires (VERIFY: https://www.backblaze.com/docs/cloud-storage-object-lock).
  That is what the unbound `BACKUP_ANCHOR` seam is for. It also needs an off-Cloudflare verifier, because a
  verifier running in the same account inherits the same admin.
- **Intermediate states between reconciliations.** A ref moved and moved back between two runs, with both
  deliveries lost, leaves nothing to compare.
- **GitHub itself.** Compare, refs and the delivery log are taken as GitHub's truth.
- **Time.** `created_at` is the Worker's clock, not a trusted timestamp. Anchors are not countersigned by a third
  party (for example RFC 3161).

## Alternatives considered

- **Anchors in `github-events`:** the same bucket and lock as the data they vouch for, so one policy change defeats
  both.
- **An anchor per entry:** one R2 write per webhook on the ingest path. Every 100 entries plus hourly bounds the
  unanchored tail at a fraction of the writes, and ingest never waits on anchoring.
- **Riding on `BackupIngest.capture`:** its contract rejects extra keys and it would enqueue a capture job; changing
  it belongs to the backup repository.
- **Following redirects or trusting local anchor rows:** refused. Every GitHub call uses `fetchNoRedirect` (any 3xx
  is a failure), and the latest anchor always comes from the bucket listing.

## Consequences

- Two cron triggers (`7 * * * *` hourly, `37 */6 * * *` refs) in `wrangler.jsonc`, dispatched by `src/cron.mjs`. The
  Worker only flags work; each Durable Object's alarm does it within its own API budget (40 calls per alarm) and
  retry state.
- New commit-ledger entry kind `reconcile`. `ref_update` gains `size, listed, truncated, complete, gap`, and `commit`
  gains `source`. Nothing is deployed yet, so the `entries` CHECK constraint was widened in place. Once deployed,
  any further change needs a migration.
- After an anchor finding, anchoring of that ledger stays stopped until a person has investigated. There is
  deliberately no method to unblock it. Recovery is a deliberate change, for example a new ledger name, recorded
  in an ADR.
