# GitHub event observatory

Implements infra-root ADR-0001 section 2 (event capture, event ledger, commit ledgers, downstream) and the seam for
section 3 (workflow metrics). Design decisions: [docs/adr/0001-observatory-ingest.md](adr/0001-observatory-ingest.md).

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
3. **seed / root runner**: Secrets Store (store `b6504fe2d5f64352954629bc7185fb79`) values `GITHUB_WEBHOOK_SECRET`,
   `CARETAKER_APP_KEY` (PEM, PKCS8 or PKCS1) and `ALERT_WEBHOOK_URL` (https). `GITHUB_WEBHOOK_SECRET_PREVIOUS` is
   bound but only populated during rotation (see below). VERIFY whether `wrangler deploy` refuses a Secrets Store
   binding whose secret does not exist yet; if it does, create it with a random value the runner discards.
4. **backup**: the `backup` Worker with its `BackupIngest` entrypoint must be deployed first; a service binding to a
   missing service is expected to fail the deploy (VERIFY).
5. **caretaker App** (see "App and permissions" below): decide which App delivers, set its webhook URL to
   `https://hooks.vespoli.me/github`, set the webhook secret through the API, subscribe it to the events listed
   below, and set the non-secret var `CARETAKER_APP_ID` in `wrangler.jsonc` (numeric App id or `Iv…` client id).
   Until it is set, commit lookups fail closed with `app_unconfigured` and the commit ledger inbox waits.
6. Deploy (`npm run deploy` in the Cloudflare build environment) applies Durable Object migration `v2`
   (`EventLedger`, `CommitLedger`, SQLite).
7. Acceptance: a GitHub `ping` and a `push` redelivered from the App's delivery log are answered 202, appear in R2 and
   in `verifyLedger` output; a delivery with a wrong signature is 401; the backup Worker records the capture; a test
   force-push to `main` of a scratch repository raises `main_forced_update` at `ALERT_WEBHOOK_URL`.

## What is captured, and where

| Item | Location | Notes |
|---|---|---|
| Every authenticated delivery | R2 `github-events` `deliveries/<yyyy>/<mm>/<dd>/<delivery>.json` | Date is the UTC receive date. Written once (`If-None-Match: *`). |
| Event ledger | Durable Object `EventLedger`, instance `global` | Hash chained, append-only (SQL triggers refuse UPDATE/DELETE). |
| Event ledger checkpoints | R2 `github-events` `checkpoints/<seq>.json` | Hourly when the head advanced. |
| Commit ledgers | Durable Object `CommitLedger`, one per `idFromName(String(repo_id))` | Hash chained, append-only. |
| Commit ledger mirror | R2 `github-events` `commits/<repo_id>/<seq>.json` | Every entry, written once. |
| Integrity findings | `findings` table in each `CommitLedger`, and `ALERT_WEBHOOK_URL` | Alert retried until delivered. |

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
| `GITHUB_WEBHOOK_SECRET` unavailable | 500, empty | nothing |
| Delivery id already ledgered with the same body | 202, empty | nothing new |
| Same delivery id in flight, or already ledgered with a different body | 409, empty | nothing new |
| R2 or ledger failure | 500, empty | possibly the R2 object; never a ledger entry without its object |
| Accepted | 202, empty | R2 object, ledger entry, outbox rows |

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

- `kind: "ref_update"`: `{ref, before, after, created, deleted, forced, pusher, delivery_id}` (`pusher` is the
  pusher's name; the email is not recorded).
- `kind: "commit"`: `{sha, tree, parents, author_name, author_date, committer_name, committer_date, message_sha256,
  verified, verification_reason, ref}` from `GET /repos/{full_name}/commits/{sha}`; `ref` is the ref of the push
  that first brought the commit into this ledger. One entry per commit per repository.

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

Alert body (`schema: ghcaretaker-alert/v1`): `{type: "integrity_finding", code, repo_id, repo, ref, sha, delivery_id,
entry_seq, finding_id, detail, detected_at}`. Operational alerts use `type: "operational"` with `code`
`downstream_retrying`, `commit_ledger_stalled`, `promotion_check_failing`, `mirror_conflict` or
`checkpoint_conflict`. Alerts never contain tokens, bodies or commit messages. Delivery uses `redirect: "error"` and
a 10 s timeout; any non-2xx is retried with backoff (30 s doubling to 1 h) forever, and each failure is logged as a
`critical` structured line.

## Downstream

- **Backup**: `push` and `create` events of owned repositories queue `BACKUP.capture({repo_id, reason, delivery_id})`
  (`reason` is the event name) in the event ledger outbox, delivered at least once by the alarm. The backup Worker
  must be idempotent on `delivery_id`. "Green means accepted": a 202 here says nothing about the backup.
- **Commit ledger**: `push` and `create` are handed to the repository's `CommitLedger.ingest` the same way.
- **Metrics seam** (for the section 3 collector): `workflow_run` and `workflow_job` events of owned repositories queue
  a `metrics` row; the alarm calls `metricsSinkFor(env).record(observation)` (`src/metrics-sink.mjs`). The default is
  a no-op that acknowledges. The collector replaces `metricsSinkFor` and reads payloads with
  `readDelivery(env, object_key, body_sha256)` (digest-checked). Observation:
  `{delivery_id, event, action, repo_id, received_at, object_key, body_sha256}`. Contract: idempotent per
  `delivery_id`; throw to be retried.
- **Read API** (internal functions, no routes yet; `src/observatory-read.mjs`): `recentEvents(env, limit, cursor)`,
  `ledgerHead(env)`, `commitLedger(env, repoId, limit, cursor)`, `findings(env, repoId?)`, `verifyLedger`,
  `verifyCommitLedger`, `readDelivery`. Cursors are the `next_cursor` of the previous page; limits are 1 to 100.

## Rotating the webhook secret

No human sees the value. Run by the root runner (it holds `CF_SECRETS_WRITE`) with the caretaker App JWT:

1. Generate a new random secret `N` (32 bytes or more) inside the runner.
2. Write `N` to `GITHUB_WEBHOOK_SECRET_PREVIOUS`. The Worker now accepts the current secret and `N`.
3. `PATCH /app/hook/config` with `{"secret": N}` using the App JWT. GitHub now signs with `N`.
4. Redeliver a recent delivery (`POST /app/hook/deliveries/{id}/attempts`) and require 202 (a duplicate is 202).
5. Write `N` to `GITHUB_WEBHOOK_SECRET`.
6. Overwrite `GITHUB_WEBHOOK_SECRET_PREVIOUS` with a fresh random value that is discarded (or delete it), so the old
   secret is no longer accepted.

The second slot is named "previous" in the ADR; during step 2 to 5 it holds the next secret, which gives the same
overlap without ever reading a Secrets Store value back. VERIFY how quickly a Secrets Store update reaches running
Workers before step 3; if it is cached, wait for that interval.

## App and permissions (owner decision required)

GitHub only lets an App subscribe to an event when it holds the permission that event needs, so "subscribed to every
event" means read access to every resource. The existing caretaker App is pinned by `src/policy.mjs` and
`assertApp` to exactly `contents:read, metadata:read, actions:read, issues:write, pull_requests:write`, and its
manifest (`src/manifest.mjs`) has webhooks inactive with no events. Widening that App would make `AppVault.install()`
refuse it. Options: (a) a separate read-only observatory App whose key is `CARETAKER_APP_KEY` (recommended: the event
App never needs write access, and the MCP App keeps its narrow pin), or (b) widen the pinned set in `policy.mjs`.
This change does neither; it only uses `contents:read` tokens scoped to one repository.

Repository and account events to subscribe (VERIFY each name and its permission against
https://docs.github.com/en/webhooks/webhook-events-and-payloads and the App settings page; `installation`,
`installation_repositories`, `installation_target` and `github_app_authorization` are always delivered):

| Permission (read) | Events |
|---|---|
| Metadata | `label`, `public`, `repository`, `star`, `watch`, `meta` |
| Contents | `commit_comment`, `create`, `delete`, `fork`, `gollum`, `push`, `release`, `repository_dispatch`, `workflow_dispatch` |
| Actions | `workflow_run`, `workflow_job` |
| Administration | `branch_protection_configuration`, `branch_protection_rule`, `deploy_key`, `member`, `repository_ruleset`, `security_and_analysis`, `repository_import` |
| Checks | `check_run`, `check_suite` |
| Commit statuses | `status` |
| Deployments | `deployment`, `deployment_status`, `deployment_protection_rule`, `deployment_review` |
| Discussions | `discussion`, `discussion_comment` |
| Issues | `issues`, `issue_comment`, `milestone`, `sub_issues` |
| Pull requests | `pull_request`, `pull_request_review`, `pull_request_review_comment`, `pull_request_review_thread` |
| Merge queues | `merge_group` |
| Pages | `page_build` |
| Packages | `package`, `registry_package` |
| Code scanning alerts | `code_scanning_alert` |
| Dependabot alerts | `dependabot_alert`, `repository_vulnerability_alert` |
| Secret scanning alerts | `secret_scanning_alert`, `secret_scanning_alert_location`, `secret_scanning_scan` |
| Repository security advisories | `repository_advisory` |
| Custom properties | `custom_property_values` |

Organisation-only events (`organization`, `team`, `team_add`, `membership`, `projects_v2*`, `org_block`,
`personal_access_token_request`, `sponsorship`) do not occur for a personal-account installation.

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
| Push payload `commits` holds at most 2048 commits (`commits_truncated` is recorded; the new `main` tip is always judged) | commit ledger completeness | https://docs.github.com/en/webhooks/webhook-events-and-payloads#push |

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

- The commit ledger records commits listed in the push payload (at most 2048) plus the new `main` tip; a larger push
  to a non-`main` ref is recorded partially and logged as `push_commits_truncated` (the ADR's `ref_update` fields
  have no slot for it).
- `findings(env)` without a repository fans out over every repository the event ledger has seen; fine at personal
  scale, to be replaced by an index if it grows.
- Event ledger entries are not mirrored to R2 individually; integrity outside the Durable Object rests on the raw
  deliveries plus hourly checkpoints.
- Very large deliveries (near 25 MiB) are buffered in memory while being stored; GitHub caps payloads at 25 MB.
