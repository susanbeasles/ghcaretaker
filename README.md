# GitHub caretaker capability

Audited, repository-scoped GitHub read and collaboration tools. Authentication, OAuth, owner approval and navigation are owned by the shared control plane at https://control.vespoli.me/owner/apps/caretaker.

Canonical integrated source and release pipeline: https://github.com/susanbeasles/personal-control. This repository remains a compatible component deployment mirror while the existing Cloudflare Build trigger is active.

The public worker delegates MCP authentication to the shared gateway. `CaretakerCapability` exposes focused private service methods; it does not issue sessions or manage an independent login. App credentials remain in the existing AppVault Durable Object. Setup redirects to the shared owner pane.

Run `npm ci`, `npm run check`, `npm test`, and `npm run build`. Deployment uses the explicitly versioned Cloudflare resource bindings in `wrangler.jsonc`; `npm run deploy` deploys the component and applies its audit database migrations. It does not provision another OAuth store.

New clients connect to `https://control.vespoli.me/mcp/caretaker`; the legacy MCP path delegates to that same gate. Existing independent OAuth grants require authorization again through the shared issuer.

All returned GitHub content is wrapped as untrusted data. Suspicious instructions are quarantined by a heuristic filter. Read tools decode bounded UTF-8 files inline instead of asking the caller to materialize or execute GitHub blobs. Permission and endpoint allowlists enforce the boundary even when the filter misses an attack.

Audit records separate successful requests, errors, rejected credentials and policy violations. Credential failures emit critical structured log events. Secrets and OAuth payloads are excluded from stored request/response bodies. Auditing fails closed; uncertain collaboration writes must be reconciled before retrying.

```bash
npm ci --ignore-scripts
npm rebuild esbuild workerd --ignore-scripts=false --foreground-scripts
npm run check
npm test
npm run build
```

`npm run deploy` is intended for the Cloudflare build environment. It deploys and provisions bindings, then applies audit migrations. Follow [SETUP.md](SETUP.md) for initial DNS routing and the owner-only installation policy. Live account deployment and ChatGPT authorization must be tested after installation; a dry run alone does not verify them.

### Deployment tooling qualification

The Wrangler 4.147.0 development toolchain uses a Miniflare-scoped Sharp 0.35.5
override. On October 7, 2026, `npm audit` reported zero vulnerabilities; all 22
tests, source/action policy checks, an isolated Wrangler dry-run bundle and a
native Sharp SVG metadata check passed. Deployed discovery and unauthenticated
request-denial smoke checks also passed. This tooling patch does not change
provider permissions or deploy a Worker. Authenticated owner OAuth, live
repository/Actions visibility and durable audit qualification remain separate
acceptance checks.
>>>>>>> 4fea9a1 (Patch Sharp tooling and document local qualification)