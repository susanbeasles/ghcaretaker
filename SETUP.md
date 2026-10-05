# Install ghcaretaker

Endpoint: `https://mcp.vespoli.me/ghcaretaker`.

This revision deploys through Cloudflare Workers Builds. GitHub Actions validates the code using pinned official GitHub actions. It does not hold Cloudflare deployment credentials. No GitHub App private key or client secret is downloaded to your laptop. The App credential vault is a Cloudflare Durable Object with no public HTTP interface or secret-export RPC method. Cloudflare account administrators and anyone able to deploy modified Worker code remain trusted administrators.

## 1. Connect the repository in Cloudflare

Open https://dash.cloudflare.com/ → Workers & Pages → Create application → Import a repository.

- Repository: `susanbeasles/ghcaretaker`
- Worker name: `ghcaretaker`
- Production branch: `main`
- Root directory: repository root
- Build command: `npm run check && npm test && npm run build`
- Deploy command: `npm run deploy`
- Preview deployments: off
- Whole-Worker Cloudflare Access protection: off
- Deployment token: automatically created by Cloudflare
- Build variable `NODE_VERSION`: `24`

Wrangler automatically provisions the missing R2, D1 and KV bindings. The deploy script then applies the D1 audit migrations. The Worker refuses requests while the audit database is unavailable. Its Durable Object is provisioned through the checked-in migration.

The deployment identity needs Worker deployment, Durable Object migrations, Workers KV creation, R2 bucket creation, D1 database creation/query/migrations, and Worker route editing in the `vespoli.me` zone. If Cloudflare's generated token lacks a required permission, adjust that credential inside Cloudflare. Never paste it into a terminal, this chat, or the repository.

## 2. Route the shared hostname

The repository uses narrow Worker routes for `/ghcaretaker*` and the two corresponding OAuth metadata paths. It does not take over the entire `mcp.vespoli.me` hostname.

Ensure `vespoli.me` is an active Cloudflare zone and `mcp.vespoli.me` has a proxied DNS record. Reuse the existing record if the hostname already serves other connectors. If it has no origin or record, create a proxied AAAA record named `mcp` with value `100::` for Worker routing. The scoped Worker routes intercept the caretaker and discovery requests.

## 3. Protect only installation

Open https://one.dash.cloudflare.com/ → Access → Applications → Add an application → Self-hosted.

- Name: `ghcaretaker installation`
- Hostname: `mcp.vespoli.me`
- Path: `/ghcaretaker/setup*`
- Allow policy: your own email address only
- Login: an existing identity provider or Cloudflare's email one-time PIN

Do not protect `/ghcaretaker` itself or `/ghcaretaker/auth*` with Access; ChatGPT uses the connector's OAuth flow.

In the Worker's runtime Settings → Variables and Secrets add these **non-secret** variables:

| Variable | Value |
| --- | --- |
| `SETUP_ACCESS_ISSUER` | `https://YOUR-TEAM.cloudflareaccess.com`, with no trailing slash |
| `SETUP_ACCESS_AUD` | Access application's Application Audience (AUD) Tag |
| `SETUP_OWNER_EMAIL` | The email explicitly allowed by the installation policy |

`keep_vars: true` preserves these dashboard-managed variables during deployment. The Worker independently verifies the Access JWT signature, issuer, audience, expiration and owner email. An absent configuration denies installation rather than opening setup to the public.

## 4. Create and install the GitHub App

Open https://mcp.vespoli.me/ghcaretaker/setup.

1. Sign in through the installation-only Access policy.
2. Select **Create GitHub App**.
3. In GitHub, verify you are `susanbeasles`, review the manifest permissions and approve creation.
4. Follow **Install GitHub App**, select your personal account and the repositories you want available.
5. Select **Verify installation** on the setup page.

The manifest is generated from the same exact permission allowlist as the runtime. GitHub's manifest conversion happens server-side. The Worker stores the result in the credential vault, validates the immutable personal owner ID `215839550`, and rejects any broader permission. No App key, OAuth client secret, login token or credential response is sent to the browser or included in audit payloads.

Creation becomes locked after the first conversion attempt. A failed/uncertain exchange requires reconciliation and is not automatically retried. Do not delete the vault or recreate the App to clear a failure. Preserve the audit receipt, inspect the App in GitHub, and recover explicitly. Automatic key rotation/recovery is not implemented in this beta.

Requested permissions:

- Contents, metadata and Actions: read
- Issues and pull requests: write
- No administration, repository contents write, merge, push, workflow dispatch, or arbitrary HTTP tool

## 5. Connect ChatGPT

Add a custom MCP connector with URL:

`https://mcp.vespoli.me/ghcaretaker`

Select OAuth authentication. The Worker publishes authorization-server metadata and a dynamic client registration endpoint. You do not manually create a separate OAuth client in Cloudflare. Cloudflare's official OAuth provider library manages MCP clients and token issuance; the generated GitHub App supplies the upstream GitHub login client.

Review the client and return URL on the consent page. Repository read access is the baseline. Check **Allow issue and PR collaboration** only when you want the issue/comment/review tools enabled. GitHub login must resolve to the pinned personal numeric user ID. Its temporary login token is revoked before an MCP grant is issued. MCP access tokens last five minutes; grants expire after one day.

Official protocol endpoints:

- Resource metadata: `https://mcp.vespoli.me/.well-known/oauth-protected-resource/ghcaretaker`
- Authorization metadata: `https://mcp.vespoli.me/.well-known/oauth-authorization-server/ghcaretaker/auth`
- Authorization: `https://mcp.vespoli.me/ghcaretaker/auth/authorize`
- Token: `https://mcp.vespoli.me/ghcaretaker/auth/token`
- Client registration: `https://mcp.vespoli.me/ghcaretaker/auth/register`
- GitHub callback: `https://mcp.vespoli.me/ghcaretaker/auth/callback`

## Auditing and operational limits

HTTP request/response status, upstream credential operations, provisioning phases, GitHub API calls, and MCP results are audited. Success, errors, credential rejection and policy rejection have separate categories. Credential failures emit critical structured events with audit IDs. Review via `audit_recent` and `audit_record`, or Cloudflare Workers logs and the audit D1 index. OAuth/setup request bodies, callback query strings, cookie headers, tokens, App keys, client secrets, and credential response bodies are deliberately omitted. Audit availability is required before GitHub operations; audit failure after a mutation requires reconciliation.

The audit database prohibits row updates/deletes through triggers, but account administrators can alter or delete infrastructure. Immutable R2 retention, off-account recovery, external alert delivery, and account-wide rate limiting are not provisioned by this beta. Injection detection is heuristic; the enforced tool/permission allowlists provide the actual execution boundary.

## Releases and repository policy

Do not publish the old local beta tag as this updated implementation. This patch does not move or delete tags. After the updated commit is signed, CI passes and the live connector is tested, create the unused signed tag `v0.0.1-beta.2`, package that exact tag with `npm run release:package`, then publish its immutable release. Use the shipped `scripts/apply-repository-policy.mjs` to apply the requested rulesets once initial setup is complete. Owner bypasses do not bypass the separate no-force-push, signature, main-deletion, or tag update/deletion rules.
