// Read-only GitHub access for the commit ledger through the caretaker App installation.
// Key: OBSERVATORY_APP_KEY (Secrets Store, PKCS8 or PKCS1 PEM). JWT signing reuses appJWT from crypto.mjs.
// Installation tokens are minted per repository with one read permission (contents:read for the commit ledger,
// actions:read for the metrics collector), held in memory, never stored or logged.
import { appJWT } from './crypto.mjs';
import { normalizeKey } from './vault-core.mjs';
import { BodyTooLarge, CodedError, RedirectRefused, decodeUtf8, fetchNoRedirect, readBounded, sha256Hex } from './bytes.mjs';
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

// Returns {status, data, link, bytes}. `expectBody: false` accepts any 2xx without reading it (202 Accepted endpoints).
export async function githubRequest(path, { token, method = 'GET', body, fetcher = fetch, limit = 4 * 1024 * 1024, expectBody = true }) {
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
  const link = response.headers.get('link');
  if (response.status === 204) return { status: 204, data: null, link, bytes: 0 };
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new GitHubError('github_http_' + response.status, response.status); }
  if (!expectBody) { await response.body?.cancel().catch(() => {}); return { status: response.status, data: null, link, bytes: 0 }; }
  let raw;
  try { raw = await readBounded(response.body, limit); } catch (e) { throw new GitHubError(e instanceof BodyTooLarge ? 'github_body_too_large' : 'github_bad_body'); }
  try { return { status: response.status, data: JSON.parse(decodeUtf8(raw)), link, bytes: raw.byteLength }; } catch { throw new GitHubError('github_bad_body'); }
}

export const mintInstallationToken = (env, installationId, repoId, fetcher = fetch) => mintScopedToken(env, installationId, repoId, { contents: 'read' }, fetcher);

// Workflow metrics collector (src/metrics.mjs): run timing and job logs need `actions: read` and nothing else.
export const mintActionsToken = (env, installationId, repoId, fetcher = fetch) => mintScopedToken(env, installationId, repoId, { actions: 'read' }, fetcher);

const appIdOf = env => {
  const appId = String(env.OBSERVATORY_APP_ID ?? '');
  if (!/^(?:\d{1,12}|Iv[0-9A-Za-z.]{8,40})$/.test(appId)) throw new GitHubError('app_unconfigured');
  return appId;
};
async function signAppJwt(appId, env) {
  try { return await appJWT({ GITHUB_APP_ID: appId, GITHUB_APP_PRIVATE_KEY: normalizeKey(await readSecret(env.OBSERVATORY_APP_KEY)) }); }
  catch { throw new GitHubError('app_key_unavailable'); }
}

/** App JWT (RS256, at most 10 minutes) for the App-level endpoints (/app/hook/deliveries). Never stored or logged. */
export const appJwt = env => signAppJwt(appIdOf(env), env);

async function mintScopedToken(env, installationId, repoId, permissions, fetcher) {
  if (Object.entries(permissions).some(([k, v]) => v !== 'read' || OBSERVATORY_APP_PERMISSIONS[k] !== 'read')) throw new GitHubError('permission_not_allowed');
  const allowed = { ...permissions, metadata: 'read' };
  const appId = appIdOf(env);
  if (!Number.isSafeInteger(installationId) || installationId < 1 || !Number.isSafeInteger(repoId) || repoId < 1) throw new GitHubError('bad_installation');
  const jwt = await signAppJwt(appId, env);
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

// The commit object shape shared by GET /commits/{sha} and the `commits` array of GET /compare.
async function detailsOf(data, sha) {
  const c = data?.commit;
  if (data?.sha !== sha || !c) throw new GitHubError('github_bad_body');
  return {
    sha, tree: c.tree?.sha ?? null, parents: Array.isArray(data.parents) ? data.parents.map(p => p.sha) : null,
    author_name: c.author?.name ?? null, author_date: c.author?.date ?? null,
    committer_name: c.committer?.name ?? null, committer_date: c.committer?.date ?? null,
    message_sha256: typeof c.message === 'string' ? await sha256Hex(c.message) : null,
    verified: c.verification?.verified === true, verification_reason: typeof c.verification?.reason === 'string' ? c.verification.reason : 'unknown',
  };
}

// Fields recorded in a `commit` ledger entry. The message is reduced to its sha256; verification comes from GitHub.
export async function commitDetails(fullName, sha, token, fetcher = fetch) {
  try {
    // per_page=1 bounds the `files` array; only commit metadata is used.
    const { data } = await githubRequest('/repos/' + repoPath(fullName) + '/commits/' + sha + '?per_page=1', { token, fetcher, limit: 8 * 1024 * 1024 });
    return await detailsOf(data, sha);
  } catch (e) {
    // The commit no longer exists upstream (force-pushed away, repository gone): record that fact, fail closed.
    if (e.status === 404 || e.status === 422) return { sha, tree: null, parents: null, author_name: null, author_date: null, committer_name: null, committer_date: null, message_sha256: null, verified: false, verification_reason: 'commit_unavailable_' + e.status };
    throw e;
  }
}

// Resolve a promotion ref to its exact full commit, including bounded annotated-tag chains.
export async function promotionTagTarget(fullName, ref, token, fetcher = fetch) {
  if (!/^promote\/pr-[1-9]\d{0,9}-[0-9a-f]{12}$/.test(ref ?? '')) return null;
  let object = (await githubRequest('/repos/' + repoPath(fullName) + '/git/ref/tags/' + ref, { token, fetcher })).data?.object;
  const seen = new Set();
  for (let i = 0; i < 8; i++) {
    if (!SHA.test(object?.sha ?? '')) return null;
    if (object.type === 'commit') return object.sha;
    if (object.type !== 'tag' || seen.has(object.sha)) return null;
    seen.add(object.sha);
    object = (await githubRequest('/repos/' + repoPath(fullName) + '/git/tags/' + object.sha, { token, fetcher })).data?.object;
  }
  return null;
}

export function repoPath(fullName) {
  const m = /^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})$/.exec(fullName ?? '');
  if (!m || m[2] === '.' || m[2] === '..') throw new GitHubError('bad_repo_name');
  return m[1] + '/' + m[2];
}

// ---------- Completeness and reconciliation (ADR-0003) ----------
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BRANCH_NAME = /^(?!\/)(?!.*\/\/)(?!.*\.\.)[A-Za-z0-9._\/-]{1,255}$/;
const PER_PAGE = 100;
export const MAX_COMPARE_COMMITS = 1000, MAX_COMPARE_BYTES = 32 * 1024 * 1024;
export const MAX_REF_PAGES = 10;
// Errors that mean "this range cannot be fetched within the bounds": retrying inline does not help.
export const COMPARE_BOUND_ERRORS = new Set(['compare_too_many_commits', 'compare_too_large', 'compare_incomplete', 'github_body_too_large']);
const COMPARE_STATUS = new Set(['ahead', 'behind', 'diverged', 'identical']);

// The per-alarm API budget ({api: n}). Running out is not a failure: the caller resumes on its next run.
function spend(budget) {
  if (!budget) return;
  if (budget.api <= 0) throw new CodedError('deferred');
  budget.api--;
}

// `rel="next"` of a Link header, as the opaque `cursor` query value. A next link that is present but unusable is an
// error, never "no more pages" (that would claim a complete listing).
export function nextCursor(link) {
  for (const part of String(link ?? '').split(',')) {
    const m = /<([^>]+)>\s*;\s*rel="next"/.exec(part);
    if (!m) continue;
    let url;
    try { url = new URL(m[1]); } catch { throw new GitHubError('github_bad_link'); }
    const cursor = url.origin === API ? url.searchParams.get('cursor') : null;
    if (!cursor || !/^[A-Za-z0-9_=:.+/-]{1,512}$/.test(cursor)) throw new GitHubError('github_bad_link');
    return cursor;
  }
  return null;
}

/**
 * GET /repos/{r}/compare/{base}...{head}, every page, bounded by MAX_COMPARE_COMMITS and MAX_COMPARE_BYTES.
 * `base` is a commit sha or a branch name (created refs compare against the default branch); `head` is a sha.
 * Returns {status, total_commits, merge_base, commits: [commit details, oldest first]} only when every commit of the
 * range was returned; otherwise throws (`compare_incomplete` when GitHub returned fewer than total_commits).
 * VERIFY https://docs.github.com/en/rest/commits/commits#compare-two-commits : page/per_page pagination, the
 * 250-commit response limit, `total_commits`, `status`, `merge_base_commit`, oldest-first order, `commit.verification`
 * in each item, and that a branch name with "/" is accepted percent-encoded in the base position.
 */
export async function compareCommits(fullName, base, head, token, fetcher = fetch, budget = null, { maxCommits = MAX_COMPARE_COMMITS, maxBytes = MAX_COMPARE_BYTES } = {}) {
  if (!SHA.test(head ?? '') || !(SHA.test(base ?? '') || BRANCH_NAME.test(base ?? ''))) throw new GitHubError('bad_compare_range');
  const path = '/repos/' + repoPath(fullName) + '/compare/' + encodeURIComponent(base) + '...' + head;
  const commits = [], seen = new Set();
  let bytes = 0, status = null, total = null, mergeBase = null;
  for (let page = 1; ; page++) {
    spend(budget);
    // The first page also carries the `files` list, which can be large.
    const r = await githubRequest(path + '?per_page=' + PER_PAGE + '&page=' + page, { token, fetcher, limit: page === 1 ? 16 * 1024 * 1024 : 8 * 1024 * 1024 });
    bytes += r.bytes;
    if (bytes > maxBytes) throw new GitHubError('compare_too_large');
    const data = r.data;
    if (page === 1) {
      status = COMPARE_STATUS.has(data?.status) ? data.status : null;
      total = Number.isSafeInteger(data?.total_commits) && data.total_commits >= 0 ? data.total_commits : null;
      mergeBase = SHA.test(data?.merge_base_commit?.sha ?? '') ? data.merge_base_commit.sha : null;
      if (status === null || total === null) throw new GitHubError('github_bad_body');
      if (total > maxCommits) throw new GitHubError('compare_too_many_commits');
    }
    const list = Array.isArray(data?.commits) ? data.commits : [];
    for (const item of list) {
      if (!SHA.test(item?.sha ?? '')) throw new GitHubError('github_bad_body');
      if (seen.has(item.sha)) continue;
      seen.add(item.sha); commits.push(await detailsOf(item, item.sha));
    }
    if (commits.length >= total || list.length < PER_PAGE) break;
    if (page * PER_PAGE > maxCommits) throw new GitHubError('compare_too_many_commits');
  }
  if (commits.length < total) throw new GitHubError('compare_incomplete');
  return { status, total_commits: total, merge_base: mergeBase, commits };
}

/**
 * Every ref under refs/heads or refs/tags with the sha it points at (for an annotated tag: the tag object, which is
 * what a push event's `after` carries). `complete` is false when the page cap was hit: absent refs then prove nothing.
 * VERIFY https://docs.github.com/en/rest/git/refs#list-matching-references : contents:read is enough, page/per_page are
 * honoured (if they are ignored the full list arrives on page 1 and page 2 adds nothing, which also ends the loop).
 */
export async function listMatchingRefs(fullName, namespace, token, fetcher = fetch, budget = null, maxPages = MAX_REF_PAGES) {
  if (namespace !== 'heads' && namespace !== 'tags') throw new GitHubError('bad_ref_namespace');
  const refs = new Map(), prefix = 'refs/' + namespace + '/';
  for (let page = 1; page <= maxPages; page++) {
    spend(budget);
    const { data } = await githubRequest('/repos/' + repoPath(fullName) + '/git/matching-refs/' + namespace + '?per_page=' + PER_PAGE + '&page=' + page, { token, fetcher, limit: 8 * 1024 * 1024 });
    if (!Array.isArray(data)) throw new GitHubError('github_bad_body');
    let added = 0;
    for (const r of data) {
      if (typeof r?.ref !== 'string' || !r.ref.startsWith(prefix) || r.ref.length > 1024 || !SHA.test(r.object?.sha ?? '')) continue;
      if (!refs.has(r.ref)) { refs.set(r.ref, r.object.sha); added++; }
    }
    if (data.length < PER_PAGE || added === 0) return { refs, complete: true };
  }
  return { refs, complete: false };
}

/**
 * One page of GET /app/hook/deliveries (App JWT, newest first). Items are reduced to what reconciliation needs;
 * request and response bodies are never fetched. VERIFY https://docs.github.com/en/rest/apps/webhooks#list-deliveries-for-an-app-webhook :
 * JWT auth, cursor pagination through the Link header, item fields (id, guid, delivered_at, redelivery, status_code,
 * event) and newest-first order; GitHub keeps deliveries for a limited time (3 days at the time of writing).
 */
export async function listHookDeliveries(jwt, cursor, fetcher = fetch) {
  const query = '?per_page=' + PER_PAGE + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
  const { data, link } = await githubRequest('/app/hook/deliveries' + query, { token: jwt, fetcher, limit: 4 * 1024 * 1024 });
  if (!Array.isArray(data)) throw new GitHubError('github_bad_body');
  const items = [];
  let invalid = 0;
  for (const d of data) {
    const at = Date.parse(d?.delivered_at), guid = typeof d?.guid === 'string' ? d.guid.toLowerCase() : '';
    if (!Number.isSafeInteger(d?.id) || d.id < 1 || !UUID.test(guid) || !Number.isFinite(at) || !Number.isSafeInteger(d.status_code)) { invalid++; continue; }
    items.push({ id: d.id, guid, delivered_at: at, status_code: d.status_code, redelivery: d.redelivery === true, event: typeof d.event === 'string' && /^[a-z_]{1,64}$/.test(d.event) ? d.event : null });
  }
  return { items, invalid, next_cursor: nextCursor(link) };
}

/** POST /app/hook/deliveries/{id}/attempts (App JWT); GitHub answers 202. VERIFY https://docs.github.com/en/rest/apps/webhooks#redeliver-a-delivery-for-an-app-webhook */
export async function redeliverHookDelivery(jwt, hookDeliveryId, fetcher = fetch) {
  if (!Number.isSafeInteger(hookDeliveryId) || hookDeliveryId < 1) throw new GitHubError('bad_hook_delivery_id');
  await githubRequest('/app/hook/deliveries/' + hookDeliveryId + '/attempts', { token: jwt, method: 'POST', fetcher, expectBody: false });
}
