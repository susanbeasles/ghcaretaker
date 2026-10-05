# ghcaretaker

Personal GitHub MCP connector at `https://mcp.vespoli.me/ghcaretaker`.

Read public/private repository files inline, inspect pull requests and Actions, and optionally manage issues, comments and PR reviews. Repository contents and Actions are read-only. Collaboration writes are limited to fixed issue and review endpoints; no push, merge, administration, dispatch, arbitrary URL fetch, or executable blob tool exists.

[Install and deploy](SETUP.md) · [Security boundaries](SECURITY.md)

Cloudflare Workers Builds deploys on `main`. Wrangler provisions R2 audit storage, a D1 audit index and OAuth KV storage. A private Durable Object receives GitHub App credentials through the official manifest conversion flow and keeps them server-side. The installation route verifies owner-only Cloudflare Access authentication; ChatGPT uses OAuth backed by personal GitHub login. GitHub Actions runs validation with pinned official actions and holds no deployment credential.

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
