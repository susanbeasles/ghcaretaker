# 0.0.1-beta.2

Adds Cloudflare-side GitHub App manifest installation, a private App credential vault, PKCE OAuth for ChatGPT, automatic storage provisioning, and the scoped `mcp.vespoli.me/ghcaretaker` endpoint. GitHub Actions validates; Cloudflare Workers Builds owns deployment credentials.

Requires an owner-only Cloudflare Access policy for installation and proxied DNS for the shared hostname. Existing tags are not moved or deleted. Live provider/account validation is required before publishing.
