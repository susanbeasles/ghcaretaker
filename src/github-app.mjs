// Read-only GitHub access for the commit ledger through the caretaker App installation.
// Key: OBSERVATORY_APP_KEY (Secrets Store, PKCS8 or PKCS1 PEM). JWT signing reuses appJWT from crypto.mjs.
// Installation tokens are minted per repository with one read permission (contents:read for the commit ledger,
// actions:read for the metrics collector), held in memory, never stored or logged.
import { appJWT } from './crypto.mjs';
import { normalizeKey } from './vault-core.mjs';
import { CodedError, RedirectRefused, fetchNoRedirect, readJson, sha256Hex } from './bytes.mjs';
import { readSecret } from './secrets.mjs';

const API = 'https://api.github.com';
export const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export class GitHubError extends CodedError {}

// The observatory App: a separate, read-only GitHub App (not the MCP App pinned in policy.mjs / AppVault).
// `administration: read` exists only so the App can subscribe to repository_ruleset and branch_protection_rule.
export const OBSERVATORY_APP_PERMISSIONS = Object.freeze({
  contents: 'read', pull_requests: 'read', actions: 'read', checks: 'read', statuses: 'read', deployments: 'read',
  packages: 'read', administration: 'read', metadata: 'read',
});
export const OBSERVATORY_APP_EVENTS = Object.freeze(['push', 'create', 'delete', 'release', 'pull_request', 'pull_request_review',
  'workflow_run', 'workflow_job', 'check_suite', 'status', 'deployment', 'deployment_status', 'repository', 'repository_ruleset',
  'branch_protection_rule', 'package']);
/** GitHub App manifest for the observatory App (data only; the owner registers it). */
export const observatoryAppManifest = () => ({
  name: 'ghcaretaker-observatory', url: 'https://github.com/susanbeasles/ghcaretaker', public: false,
  description: 'Read-only observer: captures webhooks into hash-chained ledgers and workflow metrics. Never writes.',
  hook_attributes: { url: 'https://hooks.vespoli.me/github', active: true },
  default_permissions: { ...OBSERVATORY_APP_PERMISSIONS }, default_events: [...OBSERVATORY_APP_EVENTS],
});

export async function githubRequest(path, { token, method = 'GET', body, fetcher = fetch, limit = 4 * 1024 * 1024 }) {
  let response;
  try {
    response = await fetchNoRedirect(fetcher, API + path, {
      method, signal: AbortSignal.timeout(15_000),
      headers: {
        Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10',
        'User-Agent': 'ghcaretaker-observatory', ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch (e) { throw e instanceof RedirectRefused ? new GitHubError('github_redirect_refused', e.status) : new GitHubError('github_network'); }
  if (response.status === 204) return { status: 204, data: null };
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new GitHubError('github_http_' + response.status, response.status); }
  try { return { status: response.status, data: await readJson(response, limit) }; } catch { throw new GitHubError('github_bad_body'); }
}

export const mintInstallationToken = (env, installationId, repoId, fetcher = fetch) => mintScopedToken(env, installationId, repoId, { contents: 'read' }, fetcher);

// Workflow metrics collector (src/metrics.mjs): run timing and job logs need `actions: read` and nothing else.
export const mintActionsToken = (env, installationId, repoId, fetcher = fetch) => mintScopedToken(env, installationId, repoId, { actions: 'read' }, fetcher);

async function mintScopedToken(env, installationId, repoId, permissions, fetcher) {
  if (Object.entries(permissions).some(([k, v]) => v !== 'read' || OBSERVATORY_APP_PERMISSIONS[k] !== 'read')) throw new GitHubError('permission_not_allowed');
  const allowed = { ...permissions, metadata: 'read' };
  const appId = String(env.OBSERVATORY_APP_ID ?? '');
  if (!/^(?:\d{1,12}|Iv[0-9A-Za-z.]{8,40})$/.test(appId)) throw new GitHubError('app_unconfigured');
  if (!Number.isSafeInteger(installationId) || installationId < 1 || !Number.isSafeInteger(repoId) || repoId < 1) throw new GitHubError('bad_installation');
  let jwt;
  try { jwt = await appJWT({ GITHUB_APP_ID: appId, GITHUB_APP_PRIVATE_KEY: normalizeKey(await readSecret(env.OBSERVATORY_APP_KEY)) }); }
  catch { throw new GitHubError('app_key_unavailable'); }
  const { data } = await githubRequest('/app/installations/' + installationId + '/access_tokens', {
    token: jwt, method: 'POST', body: { repository_ids: [repoId], permissions }, fetcher, limit: 256 * 1024,
  });
  const expires = Date.parse(data?.expires_at);
  if (typeof data?.token !== 'string' || !Number.isFinite(expires)) throw new GitHubError('bad_token_response');
  // Refuse (and revoke) a token broader than the requested read permission plus metadata:read.
  const granted = data.permissions || {};
  if (Object.entries(granted).some(([k, v]) => allowed[k] !== v)) {
    await githubRequest('/installation/token', { token: data.token, method: 'DELETE', fetcher }).catch(() => {});
    throw new GitHubError('token_too_broad');
  }
  return { token: data.token, expires_at: expires };
}

// Fields recorded in a `commit` ledger entry. The message is reduced to its sha256; verification comes from GitHub.
export async function commitDetails(fullName, sha, token, fetcher = fetch) {
  try {
    // per_page=1 bounds the `files` array; only commit metadata is used.
    const { data } = await githubRequest('/repos/' + repoPath(fullName) + '/commits/' + sha + '?per_page=1', { token, fetcher, limit: 8 * 1024 * 1024 });
    const c = data?.commit;
    if (data?.sha !== sha || !c) throw new GitHubError('github_bad_body');
    return {
      sha, tree: c.tree?.sha ?? null, parents: Array.isArray(data.parents) ? data.parents.map(p => p.sha) : null,
      author_name: c.author?.name ?? null, author_date: c.author?.date ?? null,
      committer_name: c.committer?.name ?? null, committer_date: c.committer?.date ?? null,
      message_sha256: typeof c.message === 'string' ? await sha256Hex(c.message) : null,
      verified: c.verification?.verified === true, verification_reason: typeof c.verification?.reason === 'string' ? c.verification.reason : 'unknown',
    };
  } catch (e) {
    // The commit no longer exists upstream (force-pushed away, repository gone): record that fact, fail closed.
    if (e.status === 404 || e.status === 422) return { sha, tree: null, parents: null, author_name: null, author_date: null, committer_name: null, committer_date: null, message_sha256: null, verified: false, verification_reason: 'commit_unavailable_' + e.status };
    throw e;
  }
}

// True when a `promote/pr-<n>-<sha12>` tag exists whose target (dereferenced through an annotated tag) is exactly `sha`.
export async function hasPromotionTag(fullName, sha, token, fetcher = fetch) {
  const { data } = await githubRequest('/repos/' + repoPath(fullName) + '/git/matching-refs/tags/promote/pr-', { token, fetcher });
  const name = new RegExp('^refs/tags/promote/pr-\\d+-' + sha.slice(0, 12) + '$');
  for (const ref of Array.isArray(data) ? data : []) {
    if (!name.test(ref?.ref ?? '')) continue;
    if (ref.object?.type === 'commit' && ref.object.sha === sha) return true;
    if (ref.object?.type === 'tag' && SHA.test(ref.object.sha ?? '')) {
      const tag = (await githubRequest('/repos/' + repoPath(fullName) + '/git/tags/' + ref.object.sha, { token, fetcher })).data;
      if (tag?.object?.type === 'commit' && tag.object.sha === sha) return true;
    }
  }
  return false;
}

export function repoPath(fullName) {
  const m = /^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})$/.exec(fullName ?? '');
  if (!m || m[2] === '.' || m[2] === '..') throw new GitHubError('bad_repo_name');
  return m[1] + '/' + m[2];
}
