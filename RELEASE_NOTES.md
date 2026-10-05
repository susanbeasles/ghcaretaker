# ghcaretaker 0.0.1 beta 1

Personal GitHub MCP connector with read-only repository contents and Actions access, and scoped issue, comment, label and PR-review operations.

- Owner-pinned GitHub App installation authentication and explicitly downscoped tokens.
- Inline UTF-8 file reads without blob materialization or remote-download fallbacks.
- Untrusted-data envelopes and heuristic injection quarantine.
- Private request/response audit records, credential-failure classification and audit inspection tools.
- Official GitHub/Cloudflare actions pinned to full commit SHAs for automatic deployment on main.
- Repository ruleset provisioning, immutable-release setup and signed beta packaging.

This beta requires external OAuth configuration, Cloudflare resources, a personal GitHub App installation and live acceptance testing. It has no claim of guaranteed prompt-injection prevention, independently tamper-proof audit retention or exactly-once writes. Deployment and live GitHub/ChatGPT integration are not qualified by the mocked unit tests alone.
