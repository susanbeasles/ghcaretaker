# Security policy

This is an experimental beta. Report vulnerabilities using GitHub's private vulnerability reporting for this repository; do not post live credentials, private source, or exploit material in public issues.

Repository contents remain read-only. Writable issue and PR operations can affect workflow triggers and merge eligibility; enable collaboration scope deliberately. Prompt-injection filters are heuristic. A deployment administrator is trusted and can replace this Worker.

Review the security boundaries and deployment acceptance checks in [README.md](README.md). Signed commits and locked tags do not prevent a repository administrator from changing repository settings or rulesets. Protect your GitHub and Cloudflare administrative identities independently.

The GitHub App signing key and OAuth client secret stay in the private Cloudflare Durable Object credential vault. It has no public HTTP interface and no secret-export RPC method. The Cloudflare deployment credential remains in Cloudflare Workers Builds. Owner-only Cloudflare Access protects installation; the public MCP endpoint uses PKCE OAuth and a pinned numeric GitHub owner. Audit records can contain private source code; keep the R2 bucket private.

Platform invocation logs are disabled to avoid capturing authorization callback query strings. Application logs contain only structured, redacted audit metadata. Do not enable full URL or body tracing on the OAuth or setup paths. See [SETUP.md](SETUP.md) for the remaining deployment trust and recovery limits.

## Shared authentication migration

Owner identity and MCP sessions now come exclusively from personal-control. The previous GitHub-user OAuth issuer and standalone setup Access checks have been removed. Private capability methods receive a scoped identity from the shared gate; public routes cannot call them directly. The owner UI uses central CSRF checks and one-use action nonces. Repository policy and audit enforcement remain inside the capability.
