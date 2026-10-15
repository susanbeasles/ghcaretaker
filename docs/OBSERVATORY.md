# GitHub event observatory

Implements infra-root ADR-0001 section 2 (event capture, event ledger, commit ledgers, downstream) and section 3
(workflow metrics collector and the caretaker dashboard). Design decisions:
[docs/adr/0001-observatory-ingest.md](adr/0001-observatory-ingest.md),
[docs/adr/0002-metrics-and-dashboard.md](adr/0002-metrics-and-dashboard.md) and
[docs/adr/0003-completeness-and-anchors.md](adr/0003-completeness-and-anchors.md) (acknowledgement contract, duplicate
and out-of-order deliveries, truncated pushes, reconciliation against GitHub, external anchors, and what they do not
prove).

## Status: not activated

The code, configuration and tests are in this repository. Nothing has been deployed, no GitHub App delivers to it,
and no acceptance check has run against a live account. Until every item below is done and shown passing, treat
every statement in this document as a description of the code, not of production.

Activation checklist (owner or the appropriate runner; none of it needs a human to see a secret):

1. **infra**: DNS and route for `hooks.vespoli.me` (proxied, **no Access application**; spec rule P3 forbids bypass
   policies, authentication is the HMAC). Move the `hooks.vespoli.me/github` route out of `wrangler.jsonc` into
   `infra` together with the existing `mcp.vespoli.me` routes (spec section 10: routes belong to `infra`).
2. **infra-root**: R2 bucket `github-events` with its indefinite bucket lock. Note: a lock blocks deletes and
   overwrites, which this Worker never attempts; it does not block the create-only writes it does make.
3. **seed / root runner**: Secrets Store (store `b6504fe2d5f64352954629bc7185fb79`) values `OBSERVATORY_WEBHOOK_SECRET`,
   `OBSERVATORY_APP_KEY` (PEM, PKCS8 or PKCS1) and `ALERT_WEBHOOK_URL` (https). `OBSERVATORY_WEBHOOK_SECRET_PREVIOUS` is
   bound but only populated during rotation (see below). VERIFY whether `wrangler deploy` refuses a Secrets Store
   binding whose secret does not exist yet; if it does, create it with a random value the runner discards.
4. **backup**: the `backup` Worker with its `BackupIngest` entrypoint must be deployed first; a service binding to a
   missing service is expected to fail the deploy (VERIFY).
5. **observatory App** (see "The observatory App" below): register the separate read-only App from
   `observatoryAppManifest()` in `src/github-app.mjs` (permissions and events exactly as listed below, including
   `actions: read`, which run timing and job logs need), webhook URL `https://hooks.vespoli.me/github`, set the webhook
   secret through the API, install it on the personal account, and set the non-secret var `OBSERVATORY_APP_ID` in
   `wrangler.jsonc` (numeric App id or `Iv…` client id). Until it is set, commit lookups fail closed with
   `app_unconfigured` and the commit ledger inbox waits; metrics rows are stored without billing or telemetry.
6. Deploy (`npm run deploy` in the Cloudflare build environment) applies Durable Object migration `v2`
   (`EventLedger`, `CommitLedger`, SQLite).
7. Acceptance: a GitHub `ping` and a `push` redelivered from the App's delivery log are answered 202, appear in R2 and
   in `verifyLedger` output; a delivery with a wrong signature is 401; the backup Worker records the capture; a test
   force-push to `main` of a scratch repository raises `main_forced_update` at `ALERT_WEBHOOK_URL`.

Completeness and anchors (ADR-0003):

7a. **infra-root**: R2 bucket `observatory-anchors` (already in the names table) with a bucket lock rule on prefix
    `anchors/` (indefinite, or the longest retention the owner accepts). Like `github-events`, the lock blocks
    overwrites and deletes, which this Worker never attempts. It does not block the create-only writes it does make
    (VERIFY https://developers.cloudflare.com/r2/buckets/bucket-locks/). Create it before deploying (VERIFY whether
    `wrangler deploy` refuses, or auto-provisions, a binding to a missing bucket; infra-root should own it either way).
7b. The two cron triggers in `wrangler.jsonc` (`7 * * * *` hourly; `37 */6 * * *` refs) deploy with the Worker.
    Hook-delivery reconciliation needs `OBSERVATORY_APP_ID` and `OBSERVATORY_APP_KEY` (item 5); until then each
    run records `{ok: false, error: "app_unconfigured"}` and nothing is fetched.
7c. **backup** (later, optional): a `BackupAnchor` entrypoint storing each anchor in B2 with Object Lock COMPLIANCE,
    then a `BACKUP_ANCHOR` service binding here (see "External anchors"). Not required for activation.
7d. Acceptance: after the first hourly cron, `anchors/event/<seq>.json` and `anchors/commit-<repo_id>/<seq>.json`
    exist and `verifyLedgerAnchor` / `verifyCommitLedgerAnchor` return `ok: true`. A delivery deleted from the ledger
    side is impossible to stage live, so tamper detection is shown by the tests (`test/anchors.test.mjs`). A
    delivery answered 500 on purpose (for example during an R2 outage drill) is redelivered by the next hourly run
    and appears in the ledger. A push of more than 20 commits to a scratch branch records every commit, with
    `source: api_compare` for those beyond the payload's list.

Metrics and dashboard (section 3):

8. **infra**: create D1 `ghcaretaker-observatory`; put its `database_id` on the `METRICS_DB` entry of `wrangler.jsonc`
   (the entry has none yet; `check-config --production` prints a "pending activation" line until it does). VERIFY
   what `wrangler deploy` does with a D1 binding that has no id (current Wrangler may auto-provision a database by
   name; the owner wants infra to own it, so set the id first). `npm run deploy` applies `migrations-observatory/`.
9. **infra**: DNS and route for `caretaker.vespoli.me` and a Cloudflare Access self-hosted application on the whole
   hostname: identity provider login, MFA required, a single allow policy for the owner's identity, no bypass or
   service-token policy. Copy its AUD tag into the var `ACCESS_AUD` and the owner's Access email into `OWNER_EMAIL`
   (neither is a secret). While either is empty the Worker answers 403 to every dashboard request.
10. **backup**: the `BackupStatus` entrypoint with `summary()` (the dashboard tolerates it being absent or failing).
11. **observatory App**: confirm `actions: read` is granted on the installation (job logs and run timing need it).
12. Acceptance: an unauthenticated browser is stopped by Access (its login page, served by Cloudflare, not the
    Worker); after owner login with MFA the overview renders. The Worker's own gate is checked by the tests in
    `test/access.test.mjs` and must also hold live: an assertion from another Access application (other AUD) or for
    another email is 403 with an empty body, and no path on the host answers 3xx from the Worker.
    A job using `actions/runner-telemetry` shows CPU and memory on `/actions` after it completes.

## What is captured, and where

| Item | Location | Notes |
|---|---|---|
| Every authenticated delivery | R2 `github-events` `deliveries/<yyyy>/<mm>/<dd>/<delivery>.json` | Date is the UTC receive date. Written once (`If-None-Match: *`). |
| Event ledger | Durable Object `EventLedger`, instance `global` | Hash chained, append-only (SQL triggers refuse UPDATE/DELETE). |
| Event ledger checkpoints | R2 `github-events` `checkpoints/<seq>.json` | Hourly when the head advanced. |
| Commit ledgers | Durable Object `CommitLedger`, one per `idFromName(String(repo_id))` | Hash chained, append-only. |
| Commit ledger mirror | R2 `github-events` `commits/<repo_id>/<seq>.json` | Every entry, written once. |
| Integrity findings | `findings` table in each `CommitLedger`, and `ALERT_WEBHOOK_URL` | Alert retried until delivered. |
| Ledger findings (`delivery_conflict`, `tail_truncation`, `anchor_mismatch`) | `findings` table in `EventLedger` (commit ledgers record their own anchor findings) | Digests and ids only. |
| External anchors | R2 `observatory-anchors` `anchors/<ledger>/<seq, 16 digits>.json` | Hourly and every 100 entries, written once; see "External anchors". |
| Reconciliation state | `meta` and `hook_redeliveries` in `EventLedger`; `meta` in each `CommitLedger` | Watermark, resume cursor, per-guid attempts, last-run summaries. |

Delivery object (JSON, `body` is the raw JSON text exactly as received):

```json
{"v":1,"delivery_id":"<X-GitHub-Delivery>","event":"<X-GitHub-Event>","hook_id":"<X-GitHub-Hook-ID|null>",
 "installation_target_id":"<X-GitHub-Hook-Installation-Target-ID|null>","received_at":"<ISO-8601>",
 "body_sha256":"<hex sha256 of the raw body bytes>","body":"<raw JSON text>"}
```

Custom metadata: `sha256` (hex sha256 of the stored object bytes; also sent as the R2 upload checksum),
`body_sha256`, `event`. The signature header itself is not stored.

## Ingress contract (`POST https://hooks.vespoli.me/github`)

| Condition | Response | Stored |
|---|---|---|
| Method other than POST, or path other than exactly `/github` | 404, empty | nothing |
| `X-GitHub-Event` missing or not `[a-z_]{1,64}`; `X-GitHub-Delivery` missing or not a UUID; hook id headers not numeric | 401, empty | nothing |
| Body over 25 MiB (counted while reading; a declared `Content-Length` over the bound is refused before reading) | 401, empty | nothing |
| `X-Hub-Signature-256` not `sha256=<64 lowercase hex>` or no configured secret matches (HMAC-SHA256 over the raw bytes, constant-time) | 401, empty | nothing |
| Signed body not UTF-8 JSON object | 401, empty | nothing |
| `OBSERVATORY_WEBHOOK_SECRET` unavailable | 500, empty | nothing |
| Delivery id already ledgered with the same body | 202, empty | nothing new |
| Same delivery id with the same body in flight | waits up to 8 s for it: 202 once it committed (or after taking over a released reservation), else 503 | nothing new |
| Same delivery id, different body (ledgered or in flight) | 409, empty | a `delivery_conflict` finding with both body digests, and its alert; the body is not stored |
| R2 or ledger failure | 500, empty | possibly the R2 object; never a ledger entry without its object |
| Accepted | 202, empty | R2 object, ledger entry, outbox rows |

A 2xx is sent only after the R2 create-only write and the ledger commit have completed (`test/durability.test.mjs`).

Never a 3xx. The MCP paths do not exist on `hooks.vespoli.me`, and `/github` does not exist on `mcp.vespoli.me`.

## Ledger formats

Both ledgers use the same chain (`src/chain.mjs`):

```
entry_hash = hex(sha256( prev_hash || canonical(entry without entry_hash) ))      prev_hash of seq 1 = 64 zeros
```

`canonical` is JSON with object keys sorted by UTF-16 code unit, no whitespace, strings escaped as by
`JSON.stringify`, numbers restricted to safe integers, `undefined` refused. `||` is string concatenation of the
64-hex `prev_hash` and the canonical text, hashed as UTF-8.

**Event ledger entry**: `{seq, delivery_id, event, action, repo_id, received_at, object_key, body_sha256, prev_hash, entry_hash}`
(`action` and `repo_id` are `null` when the payload has none).

**Checkpoint** `checkpoints/<seq>.json`: `{seq, entry_hash, at}`.

**Commit ledger entry**: `{seq, repo_id, kind, delivery_id, recorded_at, data, prev_hash, entry_hash}` where `data` is

- `kind: "ref_update"`: `{ref, before, after, created, deleted, forced, pusher, delivery_id, size, listed, truncated,
  complete, gap}` (`pusher` is the pusher's name; the email is not recorded). `size` is the payload's `size` or
  `null`, `listed` the number of commits the payload listed, `truncated` whether that list was possibly incomplete,
  `complete` whether every commit of the push's range is recorded (a later `reconcile` entry may complete it; this
  entry is never changed), `gap` whether `before` differed from the recorded head.
- `kind: "commit"`: `{sha, tree, parents, author_name, author_date, committer_name, committer_date, message_sha256,
  verified, verification_reason, ref, source}` from `GET /repos/{full_name}/commits/{sha}` or from the compare
  response; `ref` is the ref of the push that first brought the commit into this ledger; `source` is `webhook`
  (listed in the payload, or its `after`) or `api_compare` (found only through compare). One entry per commit per
  repository.
- `kind: "reconcile"`: `{ref, reason, from, to, deleted, compare_status, commits, complete, delivery_id}`.
  `reason` is `push_backfill` (an incomplete push completed), `ref_gap` (the range a gap skipped), `ref_reconcile`
  (the head settled against GitHub's refs) or `baseline` (first observation of a ref that predates the ledger,
  `complete: false`). `commits` is the number of commit entries that follow it. The entry's own `delivery_id`
  column is the push's delivery id, or `reconcile:<uuid>` for a reconciliation run.

The R2 mirror object `commits/<repo_id>/<seq>.json` is exactly `canonical(entry)` including `entry_hash`, with
metadata `sha256` and `entry_hash`.

## Verifying the chain

- In the Worker: `verifyLedger(env, fromSeq, toSeq)` and `verifyCommitLedger(env, repoId, fromSeq, toSeq)` from
  `src/observatory-read.mjs` recompute up to 5000 entries per call and return
  `{ok, checked, first_break: {seq, reason} | null, last, from, to, head_seq}`; `reason` is `entry_hash_mismatch`,
  `prev_hash_mismatch` or `missing_entry`. Page through larger ranges with consecutive calls. The dashboard (next
  agent) exposes these behind Access.
- Against the checkpoints: `checkpoints/<seq>.json` must equal `{seq, entry_hash}` of the ledger at that `seq`. A
  checkpoint that disagrees with a verifying chain means history was rewritten before that point.
- Offline, for a commit ledger: list `commits/<repo_id>/`, order by numeric `seq`, and for each object check
  `prev_hash == previous entry_hash` (64 zeros for `seq` 1) and
  `entry_hash == sha256(prev_hash + canonical(object without entry_hash))`.

## Integrity findings

Raised by the commit ledger (`src/integrity.mjs`); each is stored once and sent to `ALERT_WEBHOOK_URL`.

| `code` | Meaning | Expected response |
|---|---|---|
| `main_forced_update` | `main` was force-updated (history rewritten) | Treat as a compromise of the `main` ruleset or the promoter until explained. |
| `main_deleted` | `main` was deleted | Same. Restore from the backup ledger. |
| `tag_forced_update` | A tag was force-updated | Tags are immutable by ruleset; investigate the bypass. |
| `tag_deleted` | A tag was deleted | Same. |
| `tag_moved` | A tag now points somewhere new (in place, or re-created after deletion with a different target). Re-creating an annotated tag yields a new tag object, so a delete-and-recreate also reports `tag_deleted`. | Same. |
| `main_commit_unverified` | A commit reached `main` whose GitHub verification is not `verified: true` (including a commit no longer retrievable: `commit_unavailable_404`) | Promotion should only ever produce GitHub-signed commits. |
| `main_commit_multiple_parents` | A merge commit reached `main` | `main` must be linear; something bypassed the promoter. |
| `main_commit_missing_promotion_tag` | No `promote/pr-<n>-<sha12>` tag targeting the commit 15 minutes after it reached `main` | A commit landed without provenance. A tag created later does not clear an already-raised finding. |
| `force_push` (warning) | Any forced push, or a history rewrite found by reconciliation; detail `{before, after}` | Expected on feature branches; on `main` or tags it comes with the rule above. |
| `ref_gap` (warning) | A push whose `before` is not the head this ledger recorded (late, out of order or after a missed delivery); detail `{recorded_head, recorded_deleted, before, after}` | None by itself: the skipped range is backfilled and the ref reconciled 10 minutes later. |
| `incomplete_push` (warning) | A possibly truncated push (or reconciled move) whose full range could not be fetched (`reason`: the compare error or bound) | Retried through the outbox until complete; a `reconcile` entry with `complete: true` closes it. |
| `ref_drift` (high) | GitHub's ref differs in a way no delivery explains: `deleted_unobserved`, `created_unobserved`, `tag_target_changed`, `history_rewritten`, `compare_unavailable` | Find the missing delivery; for main and tags the matching rule finding is raised too. |
| `delivery_conflict` (critical, event ledger) | Same `X-GitHub-Delivery` with a different body; detail `{first_body_sha256, second_body_sha256, event, against}` | GitHub never does this: suspect the webhook secret. |
| `tail_truncation` (critical) | The ledger holds fewer entries, or a lower head, than its latest external anchor | Ledger storage was tampered with or lost. Anchoring of that ledger stops. |
| `anchor_mismatch` (critical) | The anchored entry, the chain up to it, the entry count, or the anchor chain disagrees with the external anchors (`reason`) | Same. |

Every alert carries `severity` (`critical`, `high`, `warning`; the rules of ADR-0001 are `critical`).

Alert body (`schema: ghcaretaker-alert/v1`): `{type: "integrity_finding", code, severity, repo_id, repo, ref, sha,
delivery_id, entry_seq, finding_id, detail, detected_at}` (event-ledger findings add `ledger: "event"` with
`repo_id`, `ref`, `sha` null). Operational alerts use `type: "operational"` with `code`
`downstream_retrying`, `commit_ledger_stalled`, `promotion_check_failing`, `mirror_conflict`,
`checkpoint_conflict`, `ref_reconcile_failing` or `redelivery_exhausted`. Alerts never contain tokens, bodies or commit messages. Delivery never follows a redirect (`redirect: "manual"`, any 3xx is a failure) and uses
a 10 s timeout; any non-2xx is retried with backoff (30 s doubling to 1 h) forever, and each failure is logged as a
`critical` structured line.

## Reconciliation against GitHub (cron, ADR-0003)

| Cron | Work (flagged by `src/cron.mjs`, done by each Durable Object's alarm) |
|---|---|
| `7 * * * *` | Event ledger: verify against the latest anchor, write the next one; reconcile hook deliveries. Every commit ledger: verify and anchor. |
| `37 */6 * * *` | Every commit ledger: reconcile its refs against GitHub. |

- **Hook deliveries** (event ledger, App JWT): `GET /app/hook/deliveries` newest first, down to the last watermark
  minus 1 h (first run: 3 days), at most 10 pages. A guid not in the ledger, or with no successful attempt, is
  redelivered with `POST /app/hook/deliveries/{id}/attempts`: at most 20 per run, 3 per guid, 1 h apart, never for
  a `delivery_conflict` guid. A run cut short stores its cursor and the next one resumes from it. `head()` reports
  `hook_reconcile` (the last run's counts).
- **Refs** (each commit ledger, installation token, contents:read): `git/matching-refs/heads` and `/tags` (at most
  10 pages each) are compared with the recorded heads. Each difference becomes a `reconcile` entry: a baseline,
  a fast-forward backfilled through compare, or a `ref_drift` finding (see above). The run is skipped while the inbox
  holds a delivery, refs updated in the last 10 minutes are skipped, and a capped listing never implies a deletion.
  A `ref_gap` schedules a run 10 minutes later. `head()` reports `refs_last_run`.

## External anchors (R2 `observatory-anchors`, binding `ANCHORS`)

`anchors/<ledger>/<seq, zero-padded to 16 digits>.json`, `ledger` = `event` or `commit-<repo_id>`, written with
`If-None-Match: *`, body exactly:

```
canonical({ledger, seq, head_hash, entry_count, created_at, prev_anchor_hash})
```

`head_hash` is the ledger's `entry_hash` at `seq`, `entry_count` the number of entries with seq ≤ `seq`, and
`prev_anchor_hash` is the hex sha256 of the previous anchor's exact text (64 zeros for the first). Custom metadata
`anchor_hash` is the sha256 of this object's text. Written on the hourly cron and every 100 entries, only after the
ledger verified against the latest anchor, certifying at most 5000 new entries at a time.

Verification (cron, and without side effects through `verifyLedgerAnchor(env)` /
`verifyCommitLedgerAnchor(env, repoId)`): find the latest anchor by listing the bucket. Then require that the ledger
head and entry count are ≥ its `seq` (else `tail_truncation`), that the entry at `seq` recomputes to `head_hash`, that
the count through `seq` equals `entry_count`, that the 1000 entries up to `seq` chain, and that the anchors chain
(else `anchor_mismatch`). Returns `{ok, ledger, anchor, head_seq, entry_count, problems, chain, blocked}`. After a
failed verification that ledger is no longer anchored (`anchor_blocked` in `head()`).

Offline: list `anchors/<ledger>/`, check each object's `prev_anchor_hash` against the sha256 of the previous object's
text, then check the ledger (or its R2 mirror `commits/<repo_id>/`) has an entry at each anchored `seq` whose
`entry_hash` equals `head_hash`.

Secondary anchor (unbound seam): `BACKUP_ANCHOR.anchor(record)` → `{ok: true}` (service `backup`, entrypoint
`BackupAnchor`). `BackupIngest.capture` accepts only `{repo_id, reason, delivery_id}` and cannot carry anchors.

## Downstream

- **Backup**: `push` and `create` events of owned repositories queue `BACKUP.capture({repo_id, reason, delivery_id})`
  (`reason` is the event name) in the event ledger outbox, delivered at least once by the alarm. The backup Worker
  must be idempotent on `delivery_id`. "Green means accepted": a 202 here says nothing about the backup.
- **Commit ledger**: `push` and `create` are handed to the repository's `CommitLedger.ingest` the same way.
- **Metrics**: `workflow_run` and `workflow_job` events of owned repositories queue a `metrics` row; the alarm calls
  `metricsSinkFor(env).record(observation)` (`src/metrics-sink.mjs`), which is the D1 collector in `src/metrics.mjs`
  (see "Workflow metrics" below). Without the `METRICS_DB` binding it throws `metrics_db_unbound`, so rows wait in
  the outbox instead of being dropped. Observation: `{delivery_id, event, action, repo_id, received_at, object_key,
  body_sha256}`. Contract: idempotent per `delivery_id`; throw to be retried.
- **Read API** (`src/observatory-read.mjs`, used by the dashboard): `recentEvents(env, limit, cursor)`,
  `ledgerHead(env)`, `knownRepos(env)`, `commitLedger(env, repoId, limit, cursor)`, `findings(env, repoId?)` (without
  a repository it includes the event ledger's own findings), `verifyLedger`, `verifyCommitLedger`,
  `verifyLedgerAnchor`, `verifyCommitLedgerAnchor`, `readDelivery`. Cursors are the `next_cursor` of the previous page; limits are
  1 to 100.

## Workflow metrics (D1 `ghcaretaker-observatory`, binding `METRICS_DB`)

Schema: `migrations-observatory/0001_metrics.sql` (separate from the audit migrations in `migrations/`).

| Table | Key | Content |
|---|---|---|
| `runs` | `(repo_id, run_id, attempt)` | workflow id, name, path, event, branch, head sha, actor id, status, conclusion, `created_at`, `run_started_at`, `updated_at`; `billable_ms`, `billable_json`, `billable_kind` |
| `jobs` | `job_id` | run id, attempt, repo id, name, workflow name, status, runner name, labels (JSON), runner group, `queued_at` (= job `created_at`), `started_at`, `completed_at`, conclusion; `telemetry`, `telemetry_kind` |
| `steps` | `(job_id, number)` | name, status, conclusion, `started_at`, `completed_at` (from the job payload) |
| `deliveries_seen` | `delivery_id` | idempotency: a delivery recorded here is never processed again |

- **Owner only**: the payload's `repository.owner.id` must equal `GITHUB_OWNER_ID` (215839550) and `repository.id`
  must equal the observation's; anything else is acknowledged and ignored.
- **Convergence**: upserts guarded by status rank (`completed` > `in_progress` > anything else). A higher rank always
  wins; an equal rank wins only if it is not older (`updated_at` for runs, the latest job/step timestamp otherwise);
  a terminal row never moves back. Nullable descriptive fields are only ever filled in, never blanked.
- **Order of writes**: the run/job/steps upsert lands first; enrichment (billing, telemetry) and the `deliveries_seen`
  row land together in one D1 batch. A failure in between is retried and converges.
- **Billing (reported)**: on a completed run, `GET /repos/{r}/actions/runs/{id}/timing` (token: `actions: read`, one
  repository). `billable_ms` is the sum of `billable.<OS>.total_ms`; `billable_json` keeps the API's own structure and
  units (`total_ms`, `jobs`, `job_runs[{job_id, duration_ms}]`, `run_duration_ms`), validated field by field;
  `billable_kind = 'reported'`. 404/410 store nothing (NULL): never invented. Other errors are retried.
- **Telemetry (measured)**: on a completed job, `GET /repos/{r}/actions/jobs/{id}/logs` with `redirect: "manual"`.
  The 3xx `Location` is followed exactly once and only to `https` hosts ending in `.blob.core.windows.net` or
  `.actions.githubusercontent.com` (default port, no userinfo); the storage request carries no `Authorization` header
  and follows no further redirect. It asks for the last 2 MiB (`Range: bytes=-2097152`); a 200 is streamed through a
  2 MiB window and abandoned past 64 MiB; a 416 is retried once without `Range`. Only the last line containing
  `##[runner-telemetry]` is considered; it must be `<timestamp> ##[runner-telemetry]{json}` and the JSON must match
  `runner-telemetry/v1` exactly (`src/telemetry.mjs`: exact key set, bounded numbers, no text fields except `os` and
  `arch`). The log bytes live only in memory during parsing; nothing but the validated object is stored
  (`telemetry_kind = 'measured'`). No line, no telemetry: a job without telemetry is complete, not an error.
  404 within 10 minutes of completion is retried (logs can lag); later it is final. A refused redirect is logged
  (host only) and stored as no telemetry.
- **Token**: an installation token minted for one repository with `{actions: read}` only; a broader grant is revoked
  and refused. Tokens are cached in memory, never stored or logged. App not configured: rows stored, enrichment skipped.

## Caretaker dashboard (`https://caretaker.vespoli.me/`, var `DASHBOARD_ORIGIN`)

- **Gate** (`src/access.mjs`), before anything else on every request, including `/style.css`, `/api/*` and unknown
  paths: `Cf-Access-Jwt-Assertion` must be an RS256 JWT signed by a key from
  `https://vespoli.cloudflareaccess.com/cdn-cgi/access/certs` (cached 1 h; an unknown `kid` triggers one refresh, at
  most every 30 s), `iss` equal to `ACCESS_TEAM_DOMAIN`, `aud` containing `ACCESS_AUD`, `exp`/`nbf`/`iat` valid with
  30 s skew, and `email` equal to `OWNER_EMAIL` (case-insensitive). Anything else: 403 with an empty body; the reason
  code is logged, the token never. The Worker never answers 3xx on this host.
- **Pages** (GET/HEAD only, 405 otherwise; JSON twins under `/api/` return exactly the data the page renders):

| Page | JSON | Content |
|---|---|---|
| `/` | `/api/overview` | event ledger head and chain status (last 1000 entries verified), findings count, last 24 h runs (count, failure rate, duration p50/p95, queue p95, reported billable minutes, estimated minutes), backup summary, repositories |
| `/events?cursor=&limit=` | `/api/events` | event ledger, newest first, cursor paging (limit 1 to 100) |
| `/repos/:id/commits?cursor=&limit=` | `/api/repos/:id/commits` | commit ledger and integrity findings |
| `/repos/:id/verify` | `/api/repos/:id/verify` | `verifyCommitLedger` over the last 1000 entries |
| `/promotions?repo=` | `/api/promotions` | `main` updates with their `promote/*` tag, PR number, and time from the candidate's `shadow/pr-<n>` push to `main` when both are in the window (newest 200 entries per repository) |
| `/actions?days=7\|30` | `/api/actions?days=` | by repository, workflow and job: runs, failure rate, duration p50/p95, queue p95, reported and estimated minutes, CPU mean and p95, memory peak |

- **Provenance**: every figure in the JSON is `{value, kind, unit, n}` with `kind` one of `measured` (GitHub event
  timestamps and conclusions; runner-telemetry samples), `reported` (GitHub billing API, stored verbatim) or
  `estimated` (derived, never stored). The only estimate is "minutes": for completed runs with no reported billing,
  the sum of their GitHub-hosted (`runner_group` `GitHub Actions`) job durations rounded up to whole minutes, with no
  runner-type multiplier. Reported and estimated minutes cover disjoint runs and are never added together. The HTML
  prints estimates as `≈ n` with an `est.` badge and shows missing data as "missing", never as 0.
- **Rendering**: server-side HTML, no scripts, no external resources; CSP
  `default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` with the
  stylesheet served by the Worker; `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, `no-store`. Every value is
  escaped by the `html` template tag (payload text such as repository, workflow, job, branch and author names is
  untrusted). Light and dark via `prefers-color-scheme`; tables scroll horizontally on a phone.
- **Bounds**: page limits 1 to 100; 7- or 30-day windows on indexed `created_at`/`queued_at`; at most 10,000 runs and
  20,000 jobs per query (a "row limit reached" notice when hit); promotions read at most 200 entries for at most 100
  repositories.

## Rotating the webhook secret

No human sees the value. Run by the root runner (it holds `CF_SECRETS_WRITE`) with the observatory App JWT:

1. Generate a new random secret `N` (32 bytes or more) inside the runner.
2. Write `N` to `OBSERVATORY_WEBHOOK_SECRET_PREVIOUS`. The Worker now accepts the current secret and `N`.
3. `PATCH /app/hook/config` with `{"secret": N}` using the App JWT. GitHub now signs with `N`.
4. Redeliver a recent delivery (`POST /app/hook/deliveries/{id}/attempts`) and require 202 (a duplicate is 202).
5. Write `N` to `OBSERVATORY_WEBHOOK_SECRET`.
6. Overwrite `OBSERVATORY_WEBHOOK_SECRET_PREVIOUS` with a fresh random value that is discarded (or delete it), so the old
   secret is no longer accepted.

The second slot is named "previous" in the ADR; during step 2 to 5 it holds the next secret, which gives the same
overlap without ever reading a Secrets Store value back. VERIFY how quickly a Secrets Store update reaches running
Workers before step 3; if it is cached, wait for that interval.

## The observatory App

The observatory uses its own read-only GitHub App. It shares nothing with the caretaker MCP App (which stays pinned
by `src/policy.mjs`, `assertApp` and `AppVault` to `contents:read, metadata:read, actions:read, issues:write,
pull_requests:write` with webhooks inactive). Its credentials have their own names: Secrets Store
`OBSERVATORY_APP_KEY`, `OBSERVATORY_WEBHOOK_SECRET`, `OBSERVATORY_WEBHOOK_SECRET_PREVIOUS`, and the var
`OBSERVATORY_APP_ID`. `scripts/check-config.mjs` refuses the retired names `CARETAKER_APP_KEY`, `CARETAKER_APP_ID`,
`GITHUB_WEBHOOK_SECRET` and `GITHUB_WEBHOOK_SECRET_PREVIOUS` anywhere in `wrangler.jsonc` or `src/`.

Permissions (all read; pinned as `OBSERVATORY_APP_PERMISSIONS` in `src/github-app.mjs`; tokens are minted per
repository with a single one of them, `contents` for the commit ledger and `actions` for metrics):

| Permission | Read | Needed for |
|---|---|---|
| Contents | read | `push`, `create`, `delete`, `release`; commit details for the commit ledger |
| Pull requests | read | `pull_request`, `pull_request_review` |
| Actions | read | `workflow_run`, `workflow_job`; run timing and job logs (metrics) |
| Checks | read | `check_suite` |
| Commit statuses | read | `status` |
| Deployments | read | `deployment`, `deployment_status` |
| Packages | read | `package` |
| Administration | read | only so the App can receive `repository_ruleset` and `branch_protection_rule` |
| Metadata | read | `repository` (mandatory for every App) |

Events, exactly (pinned as `OBSERVATORY_APP_EVENTS`): `push`, `create`, `delete`, `release`, `pull_request`,
`pull_request_review`, `workflow_run`, `workflow_job`, `check_suite`, `status`, `deployment`, `deployment_status`,
`repository`, `repository_ruleset`, `branch_protection_rule`, `package`. GitHub also always delivers `ping` and the
installation events. VERIFY each event's required permission against
https://docs.github.com/en/webhooks/webhook-events-and-payloads and the App settings page when registering.

## VERIFY items touched

| Item | Where it matters | Source to check |
|---|---|---|
| R2 `put` with `onlyIf` conditional headers (`If-None-Match: *`) returns `null` when the object exists | create-only capture and mirror | https://developers.cloudflare.com/r2/api/workers/workers-api-reference (states `put` returns `null` on a failed precondition and that conditional headers are accepted; wildcard semantics confirmed only in Miniflare) |
| Secrets Store binding `get()` semantics, caching, and deploy behaviour for a missing secret | webhook secret, rotation | https://developers.cloudflare.com/secrets-store/integrations/workers/ |
| Route `hooks.vespoli.me/github` without wildcard matches only that path | route scoping | https://developers.cloudflare.com/workers/configuration/routing/routes/ |
| Service binding to a not-yet-deployed Worker fails the deploy | activation order | https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/ |
| `GET /repos/{r}/commits/{sha}` returns `commit.verification` and honours `per_page` for `files` | commit entries | https://docs.github.com/en/rest/commits/commits#get-a-commit |
| `GET /repos/{r}/git/matching-refs/tags/promote/pr-` and `GET /git/tags/{sha}` | promotion tag check | https://docs.github.com/en/rest/git/refs , https://docs.github.com/en/rest/git/tags |
| `X-GitHub-Api-Version: 2026-03-10` (reused from `src/github.mjs`) | every API call | https://docs.github.com/en/rest/about-the-rest-api/api-versions |
| `PATCH /app/hook/config` sets the App webhook secret | rotation | https://docs.github.com/en/rest/apps/webhooks |
| Push payload `commits` cap (owner: 20; webhook reference: 2048; Events API: 20) and whether push webhooks carry `size` / `distinct_size`; 20 or more listed, or `size` above the list, triggers compare | commit ledger completeness | https://docs.github.com/en/webhooks/webhook-events-and-payloads#push , https://docs.github.com/en/rest/using-the-rest-api/github-event-types#pushevent |
| `GET /repos/{r}/compare/{base}...{head}`: `page`/`per_page` pagination, the 250-commit response limit (more than GitHub returns is `compare_incomplete`), `total_commits`, `status`, `merge_base_commit`, oldest-first `commits` with `commit.verification`, a percent-encoded branch name as base | truncated pushes, gaps, reconciliation | https://docs.github.com/en/rest/commits/commits#compare-two-commits |
| `GET /app/hook/deliveries` (App JWT, Link-header `cursor` pagination, newest first, item fields, retention of about 3 days) and `POST /app/hook/deliveries/{id}/attempts` (App JWT, 202) | missed-delivery reconciliation | https://docs.github.com/en/rest/apps/webhooks#list-deliveries-for-an-app-webhook , https://docs.github.com/en/rest/apps/webhooks#redeliver-a-delivery-for-an-app-webhook |
| `GET /repos/{r}/git/matching-refs/{heads,tags}` with contents:read, its pagination, and that an annotated tag's `object.sha` is the tag object (as in push `after`) | ref reconciliation | https://docs.github.com/en/rest/git/refs#list-matching-references |
| R2 bucket lock with create-only (`onlyIf` If-None-Match: *) writes of new keys, and `list` with `startAfter` | external anchors | https://developers.cloudflare.com/r2/buckets/bucket-locks/ , https://developers.cloudflare.com/r2/api/workers/workers-api-reference/ |
| A Durable Object RPC result is returned only after its SQLite writes are durable (output gates) | 2xx only after commit | https://developers.cloudflare.com/durable-objects/api/storage-api/ |
| Cron triggers (`scheduled` with `controller.cron`), syntax `37 */6 * * *` | reconciliation, anchors | https://developers.cloudflare.com/workers/configuration/cron-triggers/ |
| B2 Object Lock COMPLIANCE cannot be shortened or removed before expiry, by anyone | stronger secondary anchor (seam) | https://www.backblaze.com/docs/cloud-storage-object-lock |
| Workers `fetch` rejects `redirect: "error"` (confirmed in workerd 2026-10 via Miniflare: "must be one of follow or manual"); observatory fetches use `"manual"` and treat any 3xx as a failure | every outbound call | https://developers.cloudflare.com/workers/runtime-apis/request/ |
| `GET /repos/{r}/actions/runs/{id}/timing` is still served and its `billable` shape (`total_ms`, `jobs`, `job_runs`) | reported billing | https://docs.github.com/en/rest/actions/workflow-runs#get-workflow-run-usage |
| `GET /repos/{r}/actions/jobs/{id}/logs` answers 302 to a signed URL on `*.blob.core.windows.net` or `*.actions.githubusercontent.com`, needs `actions: read`, and the storage host honours a suffix `Range` | telemetry | https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run |
| The raw job log keeps a `##[runner-telemetry]{json}` stdout line verbatim (the runner does not treat the unknown `##[...]` prefix as a command or rewrite it) | telemetry | https://github.com/actions/runner (log/command processing) |
| `workflow_job.workflow_name`, `runner_group_name`, `run_attempt` and `steps[]` in the webhook payload | jobs/steps rows | https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_job |
| Access JWT claims (`aud` array, `email`, `iss` = team domain) and the certs endpoint format | dashboard gate | https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/ |
| Route `caretaker.vespoli.me/*` catches every path on the host, so nothing bypasses the Worker's gate | dashboard | https://developers.cloudflare.com/workers/configuration/routing/routes/ |
| D1 binding without `database_id`: deploy behaviour (auto-provisioning) | activation | https://developers.cloudflare.com/d1/ |
| Service-binding RPC `BackupStatus.summary()` return shape | overview | the backup repository's read API |

## Changes the owner must apply in protected paths

None required for this change: `.github/workflows/ci-deploy.yml` already runs `npm run check`, `npm test` (which now
includes the Miniflare runtime test) and `npm run build` on Node 24. Unrelated observation: that workflow sets
`permissions: contents: read` at the top level; spec section 10 asks for `permissions: {}` at the top with
per-job grants:

```yaml
permissions: {}
jobs:
  validate:
    permissions:
      contents: read
```

## Known limits

- A possibly truncated push is completed through compare up to 1000 commits and 32 MiB per range (and whatever limit
  GitHub's compare has, VERIFY); beyond that it stays `incomplete_push`, retried hourly at the backoff ceiling,
  forever. A truncated push that creates the default branch, or a truncated tag push, has no compare base: it is
  recorded `complete: false` with an `incomplete_push` finding and is not retried.
- A branch created without any delivery reaching the ledger (`created_unobserved`) records the head only, no
  commits (`complete: false`).
- Hook-delivery reconciliation only sees what GitHub still lists (about 3 days); ref reconciliation sees current refs
  only, so a ref that moved and moved back between two runs with both deliveries lost leaves no trace.
- Entries after the latest anchor (at most 100 or about an hour) are not covered by an anchor; see ADR-0003 for the
  account-admin threat and why B2 Object Lock through backup is the stronger anchor.
- `findings(env)` without a repository fans out over every repository the event ledger has seen; fine at personal
  scale, to be replaced by an index if it grows.
- Event ledger entries are not mirrored to R2 individually; integrity outside the Durable Object rests on the raw
  deliveries plus hourly checkpoints.
- Very large deliveries (near 25 MiB) are buffered in memory while being stored; GitHub caps payloads at 25 MB.
- Run billing is per run, not per attempt: the timing response is stored on the attempt whose `completed` event
  fetched it. Job rows carry no minutes for that reason.
- Workflow and job grouping on `/actions` is by name; a renamed workflow shows as two rows.
- Promotions are derived from ledger time (`recorded_at`), which trails the push by the commit-detail lookups; the
  time from PR head to `main` is not derivable from the ledger (the head is only in the tag message) and is omitted.
- Telemetry is advisory: any step can print a line with the marker. The action must be the first step so its post
  step runs last and its line is the last one; a forged later line would still have to pass the strict schema.
