# Bootstrap susanbeasles/ghcaretaker and release 0.0.1 beta

These commands run on your Mac. They create a new public repository, push a signed initial commit, apply repository rules, configure automatic Cloudflare deployment, and publish an immutable beta. They do not execute source retrieved from GitHub or materialize GitHub blobs.

Use the updated `ghcaretaker-0.0.1-beta.1-source.zip` from this conversation. Prerequisites: Git, Node 24+, npm, current GitHub CLI, and your existing working Git signing configuration. No Homebrew is required. Public repository visibility does not grant a software license; package metadata is `UNLICENSED` until you choose one.

## 1. Extract the download and initialize the repository

Run this block with Bash so failures stop the block. It refuses to overwrite an existing destination. If your browser changed the zip filename, edit the first path.

```bash
bash <<'BASH'
set -euo pipefail
source_zip="$HOME/Downloads/ghcaretaker-0.0.1-beta.1-source.zip"
repo_dir="$HOME/code/ghcaretaker"
test -f "$source_zip"
test ! -e "$repo_dir" || { echo 'Destination already exists; inspect it before continuing.' >&2; exit 1; }
extract_dir="$(mktemp -d)"
trap 'rm -rf "$extract_dir"' EXIT
/usr/bin/ditto -x -k "$source_zip" "$extract_dir"
mkdir -p "$HOME/code"
cp -R "$extract_dir/ghcaretaker" "$repo_dir"
cd "$repo_dir"

gh auth switch --hostname github.com --user susanbeasles
active_user="$(gh api user --jq .login)"
test "$active_user" = susanbeasles

git init --initial-branch=main
git config user.name 'Anthony Vespoli'
owner_id="$(gh api users/susanbeasles --jq .id)"
git config user.email "$owner_id+susanbeasles@users.noreply.github.com"
git config commit.gpgsign true
git config tag.gpgsign true
# Keep your existing gpg.format and user.signingkey; no signing-key replacement.
git var GIT_AUTHOR_IDENT

gh repo create susanbeasles/ghcaretaker \
  --public \
  --source . \
  --remote origin \
  --description 'Audited personal GitHub MCP connector with read-only code and scoped issue/PR collaboration'
git remote set-url origin git@github-personal:susanbeasles/ghcaretaker.git

# github-personal must be your existing SSH host alias for this account.
# If your ordinary github.com SSH identity authenticates as susanbeasles,
# use git@github.com:susanbeasles/ghcaretaker.git instead.

npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci --ignore-scripts --no-audit --no-fund
npm rebuild esbuild workerd --ignore-scripts=false --foreground-scripts
npm run check
npm test
npm run build

# Initial main push runs validation; deployment remains disabled until provisioning.
gh variable set AUTO_DEPLOY_ENABLED --repo susanbeasles/ghcaretaker --body false

git add --all
git diff --cached --stat
git diff --cached --check
git commit -S -m 'feat: initialize audited personal GitHub caretaker beta'
git log -1 --show-signature
git push --set-upstream origin main

gh repo edit susanbeasles/ghcaretaker \
  --default-branch main \
  --enable-issues \
  --enable-wiki=false \
  --enable-discussions=false \
  --delete-branch-on-merge=false \
  --add-topic mcp \
  --add-topic github-app \
  --add-topic cloudflare-workers \
  --add-topic security

# Verify GitHub recognizes the signature; local verification alone is insufficient.
commit_sha="$(git rev-parse HEAD)"
verification="$(gh api "repos/susanbeasles/ghcaretaker/commits/$commit_sha" --jq '.commit.verification.verified')"
test "$verification" = true || { echo 'Register/fix your signing key on GitHub before protecting main.' >&2; exit 1; }
BASH
```

The initial signed commit must succeed using your existing signing key. SSH authentication and Git signing are separate: a YubiKey SSH key used to push does not automatically make a Git commit verified. The first push deliberately precedes ruleset activation so a missing status check cannot deadlock bootstrap.

The package-lock-only step resolves the full pinned Wrangler dependency tree without running installation scripts. The second install also disables scripts; the rebuild explicitly enables only the `esbuild` and `workerd` binary installers required by Cloudflare tooling. This is not a claim that those dependency installers need no trust.

## 2. Wait for initial validation, then apply repository policy

```bash
cd ~/code/ghcaretaker

gh run list --repo susanbeasles/ghcaretaker --workflow ci-deploy.yml --limit 3
# Watch the run ID printed above; validation must finish successfully.
gh run watch RUN_ID --repo susanbeasles/ghcaretaker --exit-status

node scripts/apply-repository-policy.mjs

gh api repos/susanbeasles/ghcaretaker/immutable-releases
gh api repos/susanbeasles/ghcaretaker/rulesets --jq '.[] | {id,name,target,enforcement}'
gh api repos/susanbeasles/ghcaretaker/rules/branches/main --jq '.[].type'

# Enable private vulnerability reports for the public repository.
gh api --method PUT repos/susanbeasles/ghcaretaker/private-vulnerability-reporting
```

The provisioning script verifies the active account and looks up the numeric User ID live. It upserts only the four named ghcaretaker rulesets, leaves unrelated rulesets alone, reads each applied ruleset back, enables release immutability, requires SHA-pinned actions, limits third-party actions to the exact approved Cloudflare action, and disables workflow-token PR approval. The required `Validate` status is bound to GitHub Actions App ID `15368`.

| Ruleset | Scope | Rules | Bypass |
| --- | --- | --- | --- |
| Main integrity | `main` and default branch | No deletion, no force push, verified signatures | None |
| Main review | `main` and default branch | Restricted create/update; PR; one approval; latest push approved by someone else; stale approvals dismissed; threads resolved; `Validate` passes | `susanbeasles`, `exempt` |
| All branches owner control | Every branch | Restricted create/update/delete | `susanbeasles`, `always` |
| All tags integrity | Every tag | No update/delete/force push | None |

Rulesets accumulate. The exemption in main review does not bypass main integrity or tag integrity. `exempt` means GitHub does not create a bypass audit entry for those skipped rules. The all-branches bypass uses `always` so its bypass is auditable. Only you can update branches, including merge updates; reviewers do not gain branch-update access merely by approving a PR. Fork contributors can still open PRs, but your control rules may also affect maintenance of fork/network workflows depending on their target repository policies.

Required signed commits must be GitHub-verified; unsigned commits anywhere in a proposed protected-branch update can block it. Neither these rules nor release immutability prevent the account/repository administrator from editing applicable settings. Branch deletion rules do not prevent deletion of the entire repository.

Dependabot and coding agents are not bypass actors. Automated dependency PR branches would be blocked, so no nonfunctional Dependabot configuration is installed. Update action pins and Wrangler via your own signed branch until you explicitly authorize a bot.

## 3. Provision the GitHub App, OAuth and Cloudflare resources

This is the remaining live-account setup; it is not performed by repository creation or release publication.

Create/install the private personal GitHub App using the exact permissions in [README.md](README.md). Configure a compatible OAuth authorization server with PKCE S256 and RS256 access tokens. Pin your immutable subject and the `/mcp` resource audience.

```bash
cd ~/code/ghcaretaker
npx --no-install wrangler login
npx --no-install wrangler r2 bucket create ghcaretaker-audit
npx --no-install wrangler d1 create ghcaretaker-audit
```

Use the returned D1 ID and your account/domain/App/OAuth settings to edit `wrangler.jsonc`. Configuration identifiers are not signing credentials, but the public repository will expose those identifiers. Keep private keys and authorization tokens out of the file. Update `github-app-manifest.json` with the public homepage if you use a manifest registration flow.

```bash
cd ~/code/ghcaretaker
node scripts/check-config.mjs --production

# Edit the path to your downloaded GitHub App key.
umask 077
openssl pkcs8 -topk8 -nocrypt \
  -in "$HOME/path/to/github-app.pem" \
  -out /tmp/ghcaretaker-app.pkcs8.pem

# Bootstrap the Worker with narrow local Cloudflare login access.
# Deployment creates the Worker; it does not make unauthenticated GitHub access possible.
npx --no-install wrangler d1 migrations apply ghcaretaker-audit --remote
npx --no-install wrangler deploy
npx --no-install wrangler secret put GITHUB_APP_PRIVATE_KEY < /tmp/ghcaretaker-app.pkcs8.pem

# Keep the original key in your independently protected recovery location.
rm /tmp/ghcaretaker-app.pkcs8.pem
```

The key is uploaded only to Cloudflare Worker secrets. It is never stored in GitHub Actions. Production secret provisioning must happen before enabling automatic deployment. The first local deploy lets the secret command address an existing Worker. Protect this deployment path with your normal owner authentication; the Worker remains denied without client OAuth and working audit storage.

Create a Cloudflare deployment API token scoped to your account with Workers Scripts Edit and D1 Edit for this workflow. Add whatever narrowly required zone permissions are necessary for your chosen custom-domain route. Cloudflare's token model does not necessarily limit Workers Scripts Edit to one Worker: use an appropriately isolated account and treat this token as infrastructure write access. Do not give it GitHub credentials or account-wide administrative permissions. R2 is accessed by the deployed binding; the workflow does not need an R2 object-management token to deploy.

Set the production GitHub environment to allow only `main`, with no required human deployment reviewer so main pushes deploy automatically:

```bash
cd ~/code/ghcaretaker
mkdir -p .bootstrap
cat > .bootstrap/production.json <<'JSON'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api --method PUT \
  repos/susanbeasles/ghcaretaker/environments/production \
  --input .bootstrap/production.json

cat > .bootstrap/main-deployment.json <<'JSON'
{"name":"main","type":"branch"}
JSON
gh api --method POST \
  repos/susanbeasles/ghcaretaker/environments/production/deployment-branch-policies \
  --input .bootstrap/main-deployment.json

# Nonsecret account ID and public Worker origin; gh prompts when --body is omitted.
gh variable set CLOUDFLARE_ACCOUNT_ID --repo susanbeasles/ghcaretaker --env production
gh variable set WORKER_ORIGIN --repo susanbeasles/ghcaretaker --env production

# gh prompts for the token without putting it into shell command arguments/history.
gh secret set CLOUDFLARE_API_TOKEN --repo susanbeasles/ghcaretaker --env production
```

The deployment-branch-policy POST creates a policy. For a retry, list existing policies first and avoid adding a duplicate:

```bash
gh api repos/susanbeasles/ghcaretaker/environments/production/deployment-branch-policies
```

Commit the configured metadata and enable auto-deploy:

```bash
cd ~/code/ghcaretaker
git switch -c setup/production
node scripts/check-config.mjs --production
npm run check
npm test
npm run build
git add wrangler.jsonc github-app-manifest.json
git commit -S -m 'chore: configure personal production connector'
git push --set-upstream origin setup/production
gh pr create --repo susanbeasles/ghcaretaker --base main \
  --title 'Configure production connector' \
  --body 'Pins the personal GitHub installation, OAuth identity and Cloudflare resource identifiers. Signing credentials remain in Worker secrets.'

# Inspect the PR and its validation, then merge as the owner.
gh pr checks --repo susanbeasles/ghcaretaker --watch
gh pr merge --repo susanbeasles/ghcaretaker --squash

gh variable set AUTO_DEPLOY_ENABLED --repo susanbeasles/ghcaretaker --body true
gh workflow run ci-deploy.yml --repo susanbeasles/ghcaretaker --ref main
```

After bootstrap, every push to `main` validates, applies pending D1 migrations and deploys the Worker. Pull requests only validate; they never receive the Cloudflare token. Manual dispatch exists for initial deployment or deliberate reruns of main, and rejects non-main deployment. There is no `pull_request_target` or downstream `workflow_run` execution of untrusted PR code.

The workflow serializes production jobs without cancelling an in-progress migration/deploy, skips a queued commit that has already been superseded on main, and tests resource discovery plus unauthenticated denial afterward. That smoke request intentionally creates one critical credential audit entry: correlate it with the Actions run to distinguish the expected probe from a credential incident. It does not validate a real owner's OAuth grant or GitHub file access.

D1 migrations run before deployment. Make future migrations additive and compatible with both the old and new Worker; a successful database migration is not rolled back if deployment later fails. Preserve schema backups and qualify migration changes independently.

## 4. Publish the immutable 0.0.1 beta

The SemVer beta is **`0.0.1-beta.1`**, with signed tag **`v0.0.1-beta.1`**. Release from the inspected, clean latest main after CI passes. This publishes a source beta; it does not certify live interoperability.

```bash
bash <<'BASH'
set -euo pipefail
cd "$HOME/code/ghcaretaker"
git switch main
git pull --ff-only
test -z "$(git status --porcelain)"
test "$(node -p "require('./package.json').version")" = 0.0.1-beta.1
npm run check
npm test
npm run build

git tag -s v0.0.1-beta.1 -m 'ghcaretaker 0.0.1 beta 1'
git verify-tag v0.0.1-beta.1
git push origin refs/tags/v0.0.1-beta.1
npm run release:package

# Verify release immutability is enabled before publishing.
test "$(gh api repos/susanbeasles/ghcaretaker/immutable-releases --jq .enabled)" = true

# Draft first, upload the complete assets, then publish once.
gh release create v0.0.1-beta.1 \
  --repo susanbeasles/ghcaretaker \
  --verify-tag \
  --draft \
  --prerelease \
  --title 'ghcaretaker 0.0.1 beta 1' \
  --notes-file RELEASE_NOTES.md

gh release upload v0.0.1-beta.1 \
  --repo susanbeasles/ghcaretaker \
  releases/ghcaretaker-0.0.1-beta.1.zip \
  releases/SHA256SUMS

gh release edit v0.0.1-beta.1 \
  --repo susanbeasles/ghcaretaker \
  --draft=false \
  --prerelease

gh api repos/susanbeasles/ghcaretaker/releases/tags/v0.0.1-beta.1 \
  --jq '{tag_name,immutable,draft,prerelease,assets:[.assets[].name]}'
BASH
```

Once published, assets and the release tag cannot be changed under immutable-release protections. If you find a defect, publish a new beta tag such as `v0.0.1-beta.2`; do not force-move or delete the old tag. Even a tag with no published release remains update/delete protected by the all-tags ruleset. Tag creation is permitted for an actor with repository write access; these rules do not reserve tag creation to only the owner.

If a release command stops after creating a draft, inspect that draft and its uploaded assets before continuing. Do not recreate a release blindly or upload duplicate assets. The script packages tracked files with `git archive`, not your working directory, and computes an asset checksum. It never publishes local private keys, ignored files or `node_modules`.

## Action and tooling versions

Verified on October 5, 2026 against official repository releases and resolved Git refs:

| Dependency | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | `v7.0.0` | `820762786026740c76f36085b0efc47a31fe5020` |
| `cloudflare/wrangler-action` | `v4.1.3` | `953926a2e2182532811c01a25e53647d93bf07c0` |
| Wrangler CLI | `4.147.0` | Exact npm version, dependency integrity captured in your generated lockfile |

The Cloudflare pin is the compiled **commit** to which the annotated release tag resolves; it is not the tag-object SHA. Workflow `uses:` entries use full commit SHAs. The action-policy checker and exact Cloudflare allowlist must be updated with a deliberate version upgrade. Node 24 selects the current compatible patch of that LTS line; its runtime version is not a GitHub Action reference.

Official sources:

- https://github.com/actions/checkout/releases
- https://github.com/actions/setup-node/releases
- https://github.com/cloudflare/wrangler-action/releases
- https://github.com/cloudflare/workers-sdk/releases
- https://docs.github.com/en/rest/repos/rules
- https://docs.github.com/en/rest/repos/repos#enable-immutable-releases
- https://docs.github.com/en/rest/actions/permissions

## Remaining qualification and operations

- Complete and test OAuth login, token expiry/revocation and owner authorization in ChatGPT. The Worker is a resource server; it does not implement the authorization server.
- Verify private-repository reads, pagination and a disposable collaboration write against the real personal installation.
- Enable Cloudflare rate limits, credential/audit-failure alerts and independent audit export. The source includes classification and review tools, not a provisioned alert destination.
- Configure R2 bucket retention locks and an independently controlled replica before treating audit retention as durable evidence.
- Exercise D1 migrations and restoration in a separate disposable environment. Confirm a Worker rollback still understands migrated data.
- Decide your public-source license. Visibility alone does not supply one.
- Review repositories' issue/comment/review-triggered workflows before enabling collaboration scope. Those writes can trigger downstream automation despite Actions-read permissions.
- Decide whether future bots need narrow branch-creation bypasses. None are granted now.

Source and unit/security checks are runnable without live credentials. Production build, workflow execution, Cloudflare deployment, ruleset API application and immutable publication require the local setup and live accounts. They were not executed by the assistant in this environment.
