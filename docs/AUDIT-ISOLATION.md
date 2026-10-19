# Repository audit isolation

Audit MCP tools use the repository grants carried by the central gate's authenticated
caretaker session. A record is readable only when its explicit repository matches an
exact grant, or belongs to the configured owner and the session has that owner's `/*`
grant. Category filtering and the 100-row limit are applied after authorization in SQL.
Record lookup checks authorization in D1 before fetching the R2 object; unknown and
unauthorized IDs receive the same error.

Single-repository GitHub calls label their intent, result and failure records with
`owner/repo`. Validated and granted MCP calls label their request, response and error
records likewise. Installation verification, credential minting, provisioning, invalid
requests, aggregate calls and audit-tool replies remain unscoped. In particular, a
multi-repository audit reply must never become a record readable through one of those
repositories. This does not introduce a global audit grant or change GitHub permissions.

## Migration and release compatibility

`migrations/0002-audit-repository.sql` adds a nullable column and indexes. It does not
rewrite historical rows or R2 objects, recompute digests, or remove the append-only
triggers. Existing rows remain NULL. Older writers that omit the column still insert
NULL. All unscoped records, including historical records, are inaccessible through the
MCP audit tools even to owner-wildcard sessions. Ownership is never inferred from a
request body, response body, correlation ID, or current session.

Prepare and approve migration application as part of release. Applying the additive
migration before deploying the new Worker avoids an availability gap. The current
deploy script deploys first and applies D1 migrations afterward; with that ordering,
new requests fail closed with 503 until the migration completes. There is no permissive
fallback if the column is absent. Do not roll back to the old Worker as a security
recovery strategy: its unfiltered audit readers reintroduce the disclosure.

This change has only been exercised with local synthetic records. No live migration,
deployment, or production record access is part of its validation.

## Regressions

`test/audit-isolation.test.mjs` covers exact, multiple and owner-wildcard grants,
foreign-owner denial, no-grant denial, authorization before R2 reads and before LIMIT,
unscoped historical data, additive migration compatibility with old writers, immutable
history, aggregate response isolation, invalid input, and failure before upstream work
when migration is missing. `test/security.test.mjs` checks repository labels on upstream
records while installation and credential operations remain unscoped.


## Promotion evidence and deployment qualification

Promotion creation evidence must carry the authenticated webhook sender's numeric ID and an exact dereferenced commit target. `PROMOTER_ACTOR_ID` must identify the independently approved existing promoter; an absent/invalid identity trusts no promotion evidence. No identity or GitHub bypass is granted by this source change. Old prefix-only cached evidence is not trusted. Initial tag creation is protected by the generated ruleset, whose bypass list remains empty; live policy activation and any existing trusted-promoter allowance require separate deployment qualification.

Job-log telemetry is reported untrusted data, including historical rows. Apply observatory migration `0002_reported_telemetry.sql` before collector deployment. Parser validation proves shape, not provenance. Backfill exhaustion leaves the ledger incomplete and emits operational evidence; it never establishes clean history or completed reconciliation.
