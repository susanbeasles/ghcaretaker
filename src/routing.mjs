// Maps a verified webhook to downstream outbox work. Pure: no I/O. Only repositories owned by the pinned
// personal account (GITHUB_OWNER_ID) feed the commit ledger, the backup trigger and the metrics sink;
// every delivery is still captured and ledgered regardless of owner.
import { isPlainObject } from './bytes.mjs';
import { SHA } from './github-app.mjs';

export const MAX_PUSH_COMMITS = 2048;
const WORKFLOW_EVENTS = new Set(['workflow_run', 'workflow_job']);

export const repoIdOf = payload => Number.isSafeInteger(payload?.repository?.id) && payload.repository.id > 0 ? payload.repository.id : null;
export const actionOf = payload => typeof payload?.action === 'string' && /^[a-z_]{1,64}$/.test(payload.action) ? payload.action : null;

function owned(payload, ownerId) {
  return repoIdOf(payload) !== null && String(payload.repository.owner?.id) === String(ownerId);
}

function common(payload, deliveryId) {
  const installation = Number.isSafeInteger(payload.installation?.id) ? payload.installation.id : null;
  const fullName = typeof payload.repository.full_name === 'string' ? payload.repository.full_name : null;
  return { repo_id: payload.repository.id, full_name: fullName, installation_id: installation, delivery_id: deliveryId };
}

export function pushSubset(payload, deliveryId) {
  const sha = v => (typeof v === 'string' && (SHA.test(v) || /^0+$/.test(v)) ? v : null);
  const ref = typeof payload.ref === 'string' && payload.ref.length <= 1024 ? payload.ref : null;
  if (!ref || !sha(payload.before) || !sha(payload.after)) return null;
  const commits = (Array.isArray(payload.commits) ? payload.commits : []).map(c => c?.id).filter(id => typeof id === 'string' && SHA.test(id));
  return {
    type: 'push', ...common(payload, deliveryId), ref, before: payload.before, after: payload.after,
    created: payload.created === true, deleted: payload.deleted === true, forced: payload.forced === true,
    pusher: typeof payload.pusher?.name === 'string' ? payload.pusher.name.slice(0, 256) : null,
    commits: commits.slice(0, MAX_PUSH_COMMITS), commits_truncated: commits.length > MAX_PUSH_COMMITS,
  };
}

export function createSubset(payload, deliveryId) {
  if (typeof payload.ref !== 'string' || payload.ref.length > 1024 || !['tag', 'branch'].includes(payload.ref_type)) return null;
  return { type: 'create', ...common(payload, deliveryId), ref: payload.ref, ref_type: payload.ref_type };
}

// Returns [{kind, payload}] for the event ledger outbox. `metrics` payloads are completed by the ledger with
// received_at/object_key/body_sha256 so the sink can read the raw body from R2.
export function downstreamFor(event, payload, deliveryId, ownerId) {
  if (!isPlainObject(payload) || !owned(payload, ownerId)) return [];
  const out = [], repoId = payload.repository.id;
  if (event === 'push' || event === 'create') {
    const subset = event === 'push' ? pushSubset(payload, deliveryId) : createSubset(payload, deliveryId);
    if (subset) out.push({ kind: 'commit_ledger', payload: subset });
    out.push({ kind: 'backup', payload: { repo_id: repoId, reason: event, delivery_id: deliveryId } });
  }
  if (WORKFLOW_EVENTS.has(event)) out.push({ kind: 'metrics', payload: { delivery_id: deliveryId, event, action: actionOf(payload), repo_id: repoId } });
  return out;
}
