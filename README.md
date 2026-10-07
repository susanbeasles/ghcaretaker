# GitHub caretaker capability

Audited, repository-scoped GitHub read and collaboration tools. Authentication, OAuth, owner approval and navigation are owned by the shared control plane at https://control.vespoli.me/owner/apps/caretaker.

Canonical integrated source and release pipeline: https://github.com/susanbeasles/personal-control. This repository remains a compatible component deployment mirror while the existing Cloudflare Build trigger is active.

The public worker delegates MCP authentication to the shared gateway. `CaretakerCapability` exposes focused private service methods; it does not issue sessions or manage an independent login. App credentials remain in the existing AppVault Durable Object. Setup redirects to the shared owner pane.

Run `npm ci`, `npm run check`, `npm test`, and `npm run build`. Deployment uses the explicitly versioned Cloudflare resource bindings in `wrangler.jsonc`; `npm run deploy` deploys the component and applies its audit database migrations. It does not provision another OAuth store.

New clients connect to `https://control.vespoli.me/mcp/caretaker`; the legacy MCP path delegates to that same gate. Existing independent OAuth grants require authorization again through the shared issuer.
