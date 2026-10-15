# ADR-0001 (ghcaretaker): Observatory ingest, ledgers and outboxes

Status: accepted for implementation, not activated
Date: 2026-10-15
Implements: infra-root `docs/adr/0001-pipeline-surround.md` section 2 (binding), seam for section 3

## Decisions

1. **Language: `.mjs`, not TypeScript.** The repository is `.mjs` throughout, `scripts/check.mjs` syntax-checks
   `src/*.mjs`, and `node --test` runs the suite with no build step and no new devDependencies. Spec section 10
   prefers TypeScript for Workers; converting is a separate, repository-wide change. JSDoc types document the
   seams (`src/metrics-sink.mjs`).

2. **Runtime-independent cores.** `EventLedgerCore` and `CommitLedgerCore` take `(storage, env, deps)`; the Durable
   Object classes in `src/ledgers.mjs` only forward. Unit tests run the cores over `node:sqlite` (same SQLite
   engine and dialect as Durable Object SQL storage); `test/observatory-runtime.test.mjs` runs the real classes in
   workerd through Miniflare. Vitest with `@cloudflare/vitest-pool-workers` (spec section 10) was not added to
   avoid a new dependency tree; the Miniflare test already covers the runtime.

3. **Never rewrite a captured delivery: reservation plus create-only put.** The event ledger reserves the delivery
   id first (`begin`), fixing `received_at` and the object key. The Worker then writes R2 with
   `onlyIf: If-None-Match: *` (create-only). If the object already exists, it is adopted only when its
   `body_sha256` metadata matches; otherwise the request fails with 500 and nothing is overwritten. A concurrent
   redelivery of the same id gets 409 while the first holds the 5-minute lease; a failure releases the lease but
   keeps the key, so an immediate redelivery writes the same object path. The `github-events` bucket lock is
   the last line of defence.

4. **Hashing outside, appending inside.** WebCrypto digests are asynchronous and `transactionSync` callbacks are
   synchronous, so entries are linked first and inserted in a transaction that re-checks the head. An in-memory
   mutex serialises appenders within the object; the head check makes a lost race fail instead of forking.

5. **Downstream work goes through a durable outbox in the same transaction as the ledger entry.** GitHub does not
   redeliver automatically, so backup triggers, commit-ledger hand-offs and metrics observations are rows written
   atomically with the event and drained by the alarm with backoff (30 s doubling to 1 h, forever). After 8
   attempts an operational alert is queued; rows are never dropped.

6. **The commit ledger processes its inbox strictly in order.** A `push` waits until every commit's details
   (`GET /repos/{r}/commits/{sha}`) are known, then appends its `ref_update` and `commit` entries in one
   transaction. An API outage delays the ledger; it never reorders it or records guesses. A commit that no longer
   exists upstream (404/422) is recorded with `verified: false` and `verification_reason: commit_unavailable_<status>`,
   which on `main` is a `main_commit_unverified` finding (fail closed).

7. **Main-branch rules judge every commit that reaches `main`**, including commits already in the ledger from a
   `shadow/pr-<n>` push (the promotion flow pushes `S` to the shadow branch first). Commit entries are one per sha
   per repository; findings reference the existing entry's `seq`.

8. **Promotion-tag check.** A pending check per `main` commit is due 15 minutes after the push. A `create` event for
   `promote/pr-<n>-<12 hex>` clears matching pending checks by name (the tag ruleset lets only the promoter create
   `promote/*`), and a tag seen before the push (deliveries are unordered) satisfies the check immediately. When
   due, the alarm asks the API and dereferences annotated tags to the full commit sha before deciding. A late tag
   does not erase an already-raised finding.

9. **Minimum necessary downstream.** Only repositories owned by `GITHUB_OWNER_ID` are routed downstream. The pusher
   email and commit messages are not copied into outbox rows, ledgers or alerts (`message_sha256` only).

10. **Routes stay in `wrangler.jsonc` for now.** The repository already keeps routes there; `hooks.vespoli.me/github`
    was added with no wildcard. Per spec section 10 routes belong to the `infra` repository; moving all routes is a
    separate change coordinated with infra.
