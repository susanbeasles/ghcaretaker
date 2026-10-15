// Alert delivery to ALERT_WEBHOOK_URL (a Secrets Store value). The payload carries identifiers and finding
// metadata only: no commit messages, no bodies, no tokens. The URL itself is a secret and is never logged.
import { CodedError, RedirectRefused, fetchNoRedirect } from './bytes.mjs';
import { readSecret } from './secrets.mjs';
import { severityOf } from './integrity.mjs';

export async function deliverAlert(env, payload, fetcher = fetch) {
  let url;
  try { url = new URL(await readSecret(env.ALERT_WEBHOOK_URL)); } catch (e) { throw e instanceof CodedError ? e : new CodedError('alert_url_invalid'); }
  if (url.protocol !== 'https:') throw new CodedError('alert_url_not_https');
  let response;
  try {
    response = await fetchNoRedirect(fetcher, url.href, {
      method: 'POST', signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/json', 'user-agent': 'ghcaretaker-observatory' },
      body: JSON.stringify(payload),
    });
  } catch (e) { throw e instanceof RedirectRefused ? new CodedError('alert_redirect_refused', e.status) : new CodedError('alert_network'); }
  await response.body?.cancel().catch(() => {});
  if (!response.ok) throw new CodedError('alert_http_' + response.status, response.status);
}

export function findingAlert(finding, repo) {
  return {
    schema: 'ghcaretaker-alert/v1', type: 'integrity_finding', code: finding.kind, severity: severityOf(finding.kind),
    repo_id: repo.repo_id, repo: repo.full_name ?? null, ref: finding.ref ?? null, sha: finding.sha ?? null,
    delivery_id: finding.delivery_id ?? null, entry_seq: finding.entry_seq ?? null, finding_id: finding.id,
    detail: finding.detail ?? null, detected_at: finding.detected_at,
  };
}
