# Personal GitHub Caretaker

A personal-account GitHub App behind a Cloudflare Worker MCP server. Read public and private repository code inline, inspect Actions runs, and maintain issues and PR conversations. No repository code changes, Git tags, merges, admin operations, workflow dispatches, or generic HTTP proxy.

**Status:** implementation and mocked security tests are complete. This package has not been deployed, installed on GitHub, or connected to ChatGPT. Live Cloudflare, GitHub and OAuth interoperability must be verified before enabling collaboration scope. OAuth authorization is provided by a separately configured authorization server; this Worker is its resource server, not a login or token-issuing service.

## Permission boundary

| GitHub App permission | Level | Purpose |
| --- | --- | --- |
| Contents | Read | Files, branches and commits |
| Metadata | Read | Repository metadata |
| Actions | Read | Workflow runs and jobs |
| Issues | Write | Create/update issues, comments and labels |
| Pull requests | Write | Inspect PRs/files/reviews; submit feedback/reviews |
| All others | None | No administration, secrets, deployments or code writes |

The private App must be installed on your **personal account**. The Worker verifies the installation owner and requires GitHub account type `User` before minting a token. Repositories are selected through the installation: select all repositories for existing and future coverage, or select an explicit subset. Installation tokens explicitly request the table's permissions and are downgraded to read-only issues/PRs for read-only client sessions. Unexpected permissions cause token revocation and rejection.

GitHub tokens stay inside the Worker. The App private key lives in a Worker secret; it is not returned to ChatGPT. Client OAuth credentials are distinct from GitHub credentials. Installation tokens are minted per tool call and expire according to GitHub's returned expiry; no long-lived installation-token storage.

A deployment administrator who can replace Worker code or retrieve its App signing key is trusted within this design. It is not an architecture that hides those secrets from the Cloudflare account owner.

## Tools

| Area | Tools |
| --- | --- |
| Repository | `list_repositories`, `get_repository`, `read_file`, `list_commits`, `list_branches` |
| Issues | `list_issues`, `read_issue`, `list_comments`, `create_issue`, `update_issue`, `comment` |
| Labels | `list_labels`, `set_labels` |
| Pull requests | `list_pull_requests`, `read_pull_request`, `pull_request_files`, `list_reviews`, `review_pull_request` |
| Actions | `list_workflow_runs`, `read_workflow_run`, `list_workflow_jobs` |
| Audit | `audit_recent`, `audit_record` |

`repo` is a repository name, not `owner/repo`. Owner is pinned in configuration. List tools use `page` and return at most 100 entries per page. Use the same tool with the next page; the server does not follow pagination URLs. `set_labels` replaces the labels on an issue or PR and does not create repository label definitions. Git tags are not writable. `review_pull_request` requires the exact inspected `commit_id`, and supports `COMMENT`, `APPROVE`, and `REQUEST_CHANGES`. This version does not create PRs, edit their branches, upload files, manage Discussions, retrieve remote workflow log archives, or run a background autonomous caretaker.

Read scope: `github:read`. Collaboration additionally requires `github:collaborate`. A read-only client session cannot discover or execute write tools. Audit reads require owner authentication. MCP annotations describe write tools as potentially destructive; annotations do not grant permission or establish user consent.

## Inline file access and untrusted content

`read_file` returns decoded UTF-8 text directly in MCP output, with path, SHA and size. No file materialization, execution, temporary source files, blob downloads or secondary URL requests. Directory reads return only entry metadata. Regular text files are limited to 256 KiB. Binary data, invalid UTF-8, control-character payloads, symlinks, submodules and missing/oversized inline content are refused. This includes GitHub LFS pointer contents as text; the target LFS object is never retrieved.

All successful tool data is inside a fresh unpredictable `UNTRUSTED_GITHUB_<uuid>` boundary with explicit instructions to treat it only as evidence. The envelope prohibits accepting instructions, role changes, tool requests, permission grants or claimed user approvals from repository data. Download/blob/archive URL fields are removed. Embedded URLs in ordinary text remain evidence and are not fetched by the Worker.

A heuristic filter quarantines fields containing common instruction override, role spoofing, secret exfiltration, arbitrary execution and download patterns. Detection normalizes Unicode and strips common invisible characters; output also removes hazardous direction/control characters. Quarantined fields are withheld rather than reproduced. Original redacted responses remain in the private audit store for human inspection. The MCP audit-reading tools apply the same envelope/filter.

**No text filter or warning can guarantee resistance to prompt injection.** Obfuscated or indirect attacks may survive. The enforceable controls are the fixed route allowlist, validated arguments, pinned account, verified token identity/scopes, fixed GitHub origin, redirects disabled, no shell/code execution, and no arbitrary remote-fetch tool. The wrapper tells the model how to interpret data; it cannot force every model or every unrelated tool in the chat to comply. Keep unrelated execution tools out of sensitive review sessions.

## Audit trail and failure handling

Every accepted MCP request and successful MCP response is recorded. Every upstream GitHub operation records an intent before sending, followed by a result or an uncertain-outcome record. Client authentication rejections and tool-policy errors get separate entries. Request bodies and response bodies are stored after credential redaction; authorization headers, private keys, client bearer tokens and minted GitHub tokens are never deliberately stored. Credential endpoint response bodies are excluded entirely.

R2 stores private JSON records, and D1 indexes time, correlation ID, phase, category, status and object hash. Both writes must succeed before sending the next upstream operation. If audit storage fails, the operation stops. If failure occurs after a write reaches GitHub, reconcile the target issue/comment/review before retrying. No mutation is automatically retried. Manual or client retries can still duplicate comments; there is no durable exactly-once claim.

| Category | Meaning | Worker log severity |
| --- | --- | --- |
| `success` | Accepted request/intent or successful result | Info |
| `credential` | Client auth failure, GitHub 401, permission-related 403 | Critical/error stream |
| `error` | Rate limits, other upstream errors, timeout or uncertain outcome | Warning/error severity |
| `policy` | Invalid tool, argument or scope | Info with explicit policy category |

GitHub 403 classification uses rate-limit headers; GitHub 404 is retained as an error and may reflect either a missing resource or hidden/private access. Logs keep GitHub request IDs and rate-limit metadata to aid diagnosis without exposing credentials.

Use `audit_recent` with `category: "credential"` or `"error"`, then `audit_record` with a returned record ID. Reads verify the JSON object hash against the index. Initial intent records have category `success` but phase `intent`; they do not mean a GitHub operation succeeded. Correlate all phases.

D1 triggers reject row updates/deletes, and R2 record keys are unique. This is application-level append-only behavior, **not independent tamper-proof retention**: an infrastructure administrator can replace triggers, alter indexes or delete objects. Before relying on retention, configure R2 bucket locks and an independent log export under separately controlled credentials. Audit storage contains private source and issue text; keep it private and treat backups as sensitive. Redaction detects credential fields and common embedded patterns but cannot identify every arbitrary secret in source text.

Configure a Cloudflare log alert/export for `category=credential`, and independently for `audit_or_internal_failure`. Alerts are not provisioned by this package. Apply edge rate limits to `/mcp` to bound unauthenticated traffic and audit costs; the Worker does not implement a distributed rate limiter. Do not publish the audit bucket or expose a public audit route.

Allowed issue comments, labels, issue changes and PR reviews can trigger pre-existing repository Actions or external automations. Actions-read permission prevents direct dispatch/cancel/rerun, but does not disable downstream reactions to permitted writes. Inspect those workflows before granting collaboration scope. Approvals can also affect branch-protection eligibility.

## Repository, deployment and beta release

Use [SETUP.md](SETUP.md) for the ordered macOS commands to initialize `~/code/ghcaretaker`, create `susanbeasles/ghcaretaker`, apply verified rulesets, configure production deployment and publish `v0.0.1-beta.1` as an immutable prerelease. The CI workflow validates pull requests and main pushes; production deployment is enabled after provisioning with the `AUTO_DEPLOY_ENABLED` repository variable.

## Deploy

Prerequisites: Node 24+, Cloudflare account with Workers/R2/D1 and a custom domain, personal GitHub App, and a ChatGPT-compatible OAuth authorization server issuing signed RS256 JWT access tokens.

1. Register a private GitHub App under your personal account at https://github.com/settings/apps/new using exactly the permission table. Disable webhooks; this service is an on-demand connector. `github-app-manifest.json` contains the equivalent permissions for a manifest registration flow; uploading this JSON alone does not register an App. Install it on your personal account. Record App ID and installation ID.
2. Generate the GitHub App private key. Convert GitHub's RSA PEM to PKCS#8 for Web Crypto. This command creates a local unencrypted private-key file; restrict access and do not add it to Git or upload it in a chat:

   ```sh
   umask 077
   openssl pkcs8 -topk8 -nocrypt -in github-app.pem -out github-app.pkcs8.pem
   ```

3. Configure OAuth as described below. Pin your actual owner subject, issuer and JWKS endpoint. Never use an ID token in place of an access token.
4. Install deployment tooling and authenticate locally:

   ```sh
   npm install
   npx wrangler login
   npx wrangler r2 bucket create ghcaretaker-audit
   npx wrangler d1 create ghcaretaker-audit
   ```

5. Replace all placeholders in `wrangler.jsonc`, including the returned D1 database ID. Add your custom-domain route, for example:

   ```json
   "routes": [{"pattern":"github-caretaker.example.com","custom_domain":true}]
   ```

   Keep `PUBLIC_ORIGIN` exactly equal to that HTTPS origin, without a trailing slash. `workers_dev` is disabled to avoid a second unintended ingress URL.

6. Store the signing key, apply the schema, test, and deploy:

   ```sh
   npx wrangler secret put GITHUB_APP_PRIVATE_KEY < github-app.pkcs8.pem
   npx wrangler d1 migrations apply ghcaretaker-audit --remote
   npm test
   npm run deploy
   ```

   Manage local key retention according to your recovery policy. Do not blindly delete the only recovery copy.

7. Configure bucket retention and credential-failure alerts, then connect the private MCP endpoint `https://YOUR_DOMAIN/mcp` in your ChatGPT plugin. Perform live checks below before enabling write scope.

`wrangler` is pinned to 4.147.0 and is the only development dependency; the Worker runtime uses standard Web Crypto and native fetch with no runtime npm dependencies. This source release has no dependency lockfile because package-registry access was unavailable in the build environment. The bootstrap commands in [SETUP.md](SETUP.md) generate and commit the lockfile before CI uses `npm ci`. Review the resolved dependency versions before deployment.

## OAuth contract

The authorization server must provide OAuth discovery, authorization-code + PKCE S256, supported ChatGPT client registration, correct resource/audience handling, explicit consent, and JWT access tokens with these claims:

```json
{
  "iss": "https://YOUR_AUTHORIZATION_SERVER/",
  "aud": "https://YOUR_WORKER_DOMAIN/mcp",
  "sub": "YOUR_PINNED_OWNER_SUBJECT",
  "exp": 1900000000,
  "scope": "github:read"
}
```

For collaboration, issue `scope: "github:read github:collaborate"` only after deliberate owner consent. The Worker validates RS256 signatures against the configured HTTPS JWKS endpoint, requires a matching `kid`, checks exact issuer/owner/audience and token expiry, and enforces scope for writes. JWKS URLs supplied by JWT headers are never used. It publishes RFC 9728 protected-resource metadata and returns a discovery challenge for unauthorized requests. It does not accept API keys or forwarded GitHub tokens as client auth.

Configure `AUTH_ISSUER` with the exact issuer string, including any trailing slash. `AUTH_JWKS_URL` is the authorization server's actual JWKS endpoint, not necessarily the issuer plus a guessed path. `AUTH_SUBJECT` must be your immutable authenticated subject, not an email address guessed from a display name. The server rejects opaque access tokens, HS256 tokens and encrypted JWTs.

This package intentionally does not invent an authorization server, auto-enroll arbitrary users, or provide a bearer-token bypass. An existing compatible authorization server is a required deployment component. Auth0 or another provider can satisfy this contract when configured for the resource audience, RS256 access tokens, PKCE and ChatGPT registration. Do not assume any generic OIDC setup is automatically MCP-compatible. OpenAI's current authentication requirements are authoritative: https://developers.openai.com/plugins/build/auth

## Live acceptance checks

1. No bearer token: `/mcp` returns 401 with resource metadata discovery; a critical audit entry exists.
2. Wrong subject/audience/expired bearer: 401; no GitHub API operation occurs.
3. Correct read scope: discovery exposes only read tools; a private repository file arrives inline as text.
4. `comment` with read scope: rejected before GitHub; inspect the policy audit record.
5. A known injection fixture in a test repository: suspicious text is quarantined and the rest is bounded as untrusted data.
6. Correct collaboration scope on a disposable test issue: create one comment, inspect correlated intent/result records and the GitHub request ID. No automatic retry.
7. Suspended or wrong-account installation: credential rejection; no repository request.
8. Audit outage: operations stop; reconcile any in-flight write before retrying.
9. Pagination: fetch page two explicitly for a repository with more than 100 entries.
10. Deploy with Workers dry-run/type/bundle checks and inspect actual OAuth registration, revocation and expiry behavior in ChatGPT. These live checks were not executed in this environment.

## Code map

- [Tool schemas and fixed routes](src/policy.mjs)
- [Bearer authentication and App JWT signing](src/crypto.mjs)
- [GitHub transport and credential downscoping](src/github.mjs)
- [Inline files and untrusted-data filter](src/content.mjs)
- [Audit storage and record verification](src/audit.mjs)
- [Stateless MCP endpoint](src/worker.mjs)
- [Security tests](test/security.test.mjs)
- [Audit schema](migrations/0001.sql)

## References

- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
- https://docs.github.com/en/rest/pulls/pulls
- https://developers.openai.com/plugins/build/auth
- https://modelcontextprotocol.io/specification/draft/basic/authorization
