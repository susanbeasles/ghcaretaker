# ADR-0002 (ghcaretaker): Workflow metrics collector and caretaker dashboard

Status: accepted for implementation, not activated
Date: 2026-10-15
Implements: infra-root `docs/adr/0001-pipeline-surround.md` section 3 (binding); builds on ADR-0001 of this repository

## Decisions

1. **Separate D1 database and migrations directory.** `ghcaretaker-observatory` (`METRICS_DB`) with
   `migrations-observatory/`, so the audit database and its append-only migrations stay untouched. Two columns beyond
   the ADR's list: `jobs.status` (needed to converge out-of-order job events without regressing a terminal state)
   and `jobs.workflow_name` (groups jobs by workflow even when the run event has not arrived). `deliveries_seen`
   carries `seen_at` for operators.

2. **Convergence by status rank, not arrival order.** Upserts carry a `WHERE` guard: higher rank wins, equal rank wins
   only if not older, `completed` never moves back. Nullable descriptive fields are filled with `COALESCE`, never
   blanked. Rows land before enrichment so an API outage never loses the event itself.

3. **Enrichment failures: retry what can heal, settle what cannot.** Network errors, 5xx, 401/403 and a 404 job log
   within 10 minutes of completion throw (outbox backoff and the existing escalation alert). Timing 404/410, a log
   gone after the grace window, a refused redirect host, an oversize log, an unparseable telemetry line and an
   unconfigured App settle as "no data" (NULL), so no observation retries forever and starves the outbox.

4. **Provenance is part of the data model.** `billable_kind = 'reported'` and `telemetry_kind = 'measured'` are tied to
   their values by CHECK constraints. Estimates are never stored; they are computed at read time, labelled
   `estimated` in JSON (`{value, kind, unit, n}`), drawn with `≈` and an `est.` badge in HTML, and never summed with
   reported values. Statistics over measured values (percentiles, rates) stay `measured`: they summarise
   observations, they do not stand in for a missing one. Missing data is `null` / "missing", never zero.

5. **Job logs: one allowlisted hop, no credential forwarding, bounded tail.** The API request uses
   `redirect: "manual"`; the `Location` must be https on `*.blob.core.windows.net` or `*.actions.githubusercontent.com`
   (dot-boundary suffix, default port, no userinfo). The storage request is a fresh request without `Authorization`
   that follows nothing further. A suffix `Range` asks for 2 MiB; if ignored, the body streams through a fixed
   window and is abandoned past 64 MiB. Only the marker line is decoded (fatal UTF-8) and only the validated object
   is kept.

6. **`redirect: "manual"` everywhere in the observatory.** workerd rejects `redirect: "error"` at call time, which
   made every observatory GitHub call and alert fail in the real runtime (found by the Miniflare test). The shared
   helper `fetchNoRedirect` (`src/bytes.mjs`) sends `"manual"` and turns any 3xx into an error, which is the
   guarantee `"error"` was meant to give. The MCP code paths (`src/github.mjs`, `src/vault-core.mjs`) have the same
   issue and were left alone: outside this change; see the report.

7. **Access is verified in the Worker as well as at the edge.** RS256 only, JWKS cached 1 h with a rate-limited kid-miss
   refresh, issuer and AUD exact, 30 s skew, owner email exact. The gate runs before routing for every path, including
   the stylesheet and unknown paths, and answers an empty 403. Configuration that is empty or malformed denies
   everyone. `ACCESS_AUD` and `OWNER_EMAIL` are plain vars (not secrets) left empty until activation, following the
   `OBSERVATORY_APP_ID` precedent, so `check-config --production` passes and the dashboard fails closed.

8. **Server-rendered HTML with escape-by-default templates.** A tagged template escapes every interpolation; only its
   own fragments pass through. No scripts, no inline styles (SVG bars use classes), stylesheet served by the Worker
   under `style-src 'self'`. JSON twins return the same data the page renders.

9. **Promotions from the commit ledger only.** `main` updates are matched to `promote/pr-<n>-<sha12>` tag pushes and to
   the candidate's `shadow/pr-<n>` push. "PR head to main" is not derivable (the head sha lives only in the tag
   message), so it is omitted; "shadow to main" in ledger time is reported instead.

10. **The observatory is its own read-only App with its own credential names** (`OBSERVATORY_APP_KEY`,
    `OBSERVATORY_WEBHOOK_SECRET(_PREVIOUS)`, `OBSERVATORY_APP_ID`). Its permission set and event list are pinned in
    `src/github-app.mjs`; token minting refuses any permission outside that read-only set. `check-config` refuses the
    retired MCP-like names in configuration and source. The MCP App, `AppVault` and `policy.mjs` are unchanged.
