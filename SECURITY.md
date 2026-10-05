# Security policy

This is an experimental beta. Report vulnerabilities using GitHub's private vulnerability reporting for this repository; do not post live credentials, private source, or exploit material in public issues.

Repository contents remain read-only. Writable issue and PR operations can affect workflow triggers and merge eligibility; enable collaboration scope deliberately. Prompt-injection filters are heuristic. A deployment administrator is trusted and can replace this Worker.

Review the security boundaries and deployment acceptance checks in [README.md](README.md). Signed commits and locked tags do not prevent a repository administrator from changing repository settings or rulesets. Protect your GitHub and Cloudflare administrative identities independently.

The GitHub App signing key belongs in Cloudflare Worker secrets, not GitHub repository secrets or Git. The Cloudflare deployment token belongs in the protected production GitHub environment. Audit records can contain private source code; keep the R2 bucket private.
