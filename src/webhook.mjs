// GitHub webhook ingress: POST https://hooks.vespoli.me/github (ADR-0001 section 2).
// Authentication is X-Hub-Signature-256 (HMAC-SHA256 over the raw body bytes) against GITHUB_WEBHOOK_SECRET and,
// during rotation, GITHUB_WEBHOOK_SECRET_PREVIOUS. Unsigned or malformed: 401, empty body, nothing stored.
// Order of effects: reserve in the event ledger, write R2 (never rewrite), append the ledger entry, then 202.
import { CodedError, BodyTooLarge, constantTimeEqual, decodeUtf8, hexToBytes, isPlainObject, readBounded, sha256Hex, utf8 } from './bytes.mjs';
import { readSecret, readOptionalSecret } from './secrets.mjs';
import { downstreamFor, repoIdOf, actionOf } from './routing.mjs';
import { log, errorCode } from './log.mjs';

export const WEBHOOK_PATH = '/github';
export const MAX_BODY_BYTES = 25 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT = /^[a-z_]{1,64}$/;
const NUMERIC = /^[1-9][0-9]{0,19}$/;
const SIGNATURE = /^sha256=([0-9a-f]{64})$/;

const empty = status => new Response(null, { status, headers: { 'cache-control': 'no-store' } });

export async function hmacSha256(secret, bytes) {
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

// Every configured secret is always computed and compared so timing does not reveal which one matched.
export async function signatureValid(header, bytes, secrets) {
  const m = SIGNATURE.exec(header ?? '');
  if (!m) return false;
  const provided = hexToBytes(m[1]);
  let ok = false;
  for (const secret of secrets) ok = constantTimeEqual(await hmacSha256(secret, bytes), provided) || ok;
  return ok;
}

export function deliveryHeaders(headers) {
  const event = headers.get('x-github-event'), delivery = headers.get('x-github-delivery');
  const hook = headers.get('x-github-hook-id'), target = headers.get('x-github-hook-installation-target-id');
  if (!EVENT.test(event ?? '') || !UUID.test(delivery ?? '')) return null;
  if ((hook !== null && !NUMERIC.test(hook)) || (target !== null && !NUMERIC.test(target))) return null;
  return { event, delivery_id: delivery.toLowerCase(), hook_id: hook, installation_target_id: target };
}

// Returns {status} for refusals, or {delivery, bytes, text, payload} for an authenticated, well-formed delivery.
export async function authenticate(request, env) {
  const headers = deliveryHeaders(request.headers);
  if (!headers) return { status: 401, reason: 'missing_or_malformed_headers' };
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d{1,12}$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) return { status: 401, reason: 'body_too_large' };
  let bytes;
  try { bytes = await readBounded(request.body, MAX_BODY_BYTES); }
  catch (e) { return { status: 401, reason: e instanceof BodyTooLarge ? 'body_too_large' : 'body_unreadable' }; }
  let secrets;
  try { secrets = [await readSecret(env.GITHUB_WEBHOOK_SECRET)]; }
  catch (e) { return { status: 500, reason: 'webhook_secret_unavailable', severity: 'critical', error: errorCode(e) }; }
  const previous = await readOptionalSecret(env.GITHUB_WEBHOOK_SECRET_PREVIOUS);
  if (previous) secrets.push(previous);
  if (!await signatureValid(request.headers.get('x-hub-signature-256'), bytes, secrets)) return { status: 401, reason: 'bad_signature' };
  let text, payload;
  try { text = decodeUtf8(bytes); payload = JSON.parse(text); } catch { return { status: 401, reason: 'malformed_body' }; }
  if (!isPlainObject(payload)) return { status: 401, reason: 'malformed_body' };
  return { delivery: headers, bytes, text, payload };
}

export function eventLedger(env) { return env.EVENT_LEDGER.get(env.EVENT_LEDGER.idFromName('global')); }

export async function handleWebhook(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== WEBHOOK_PATH) return empty(404);
  const auth = await authenticate(request, env);
  if (auth.status) {
    log(auth.severity ?? 'warning', 'webhook_refused', { status: auth.status, reason: auth.reason, ...(auth.error ? { error: auth.error } : {}) });
    return empty(auth.status);
  }
  const { delivery, bytes, text, payload } = auth;
  try {
    const body_sha256 = await sha256Hex(bytes), ledger = eventLedger(env);
    const reservation = await ledger.begin({ delivery_id: delivery.delivery_id, body_sha256 });
    if (reservation.state === 'duplicate') { log('info', 'webhook_duplicate', { delivery_id: delivery.delivery_id, seq: reservation.entry.seq }); return empty(202); }
    if (reservation.state !== 'reserved') { log('warning', 'webhook_' + reservation.state, { delivery_id: delivery.delivery_id }); return empty(409); }
    const { object_key, received_at, token } = reservation;
    let result;
    try {
      await storeDelivery(env, { ...delivery, received_at, body_sha256, text, object_key });
      result = await ledger.commit({
        delivery_id: delivery.delivery_id, token, event: delivery.event, action: actionOf(payload), repo_id: repoIdOf(payload),
        repo_full_name: typeof payload.repository?.full_name === 'string' ? payload.repository.full_name : null, body_sha256,
        downstream: downstreamFor(delivery.event, payload, delivery.delivery_id, env.GITHUB_OWNER_ID),
      });
    } catch (error) {
      await Promise.resolve().then(() => ledger.release({ delivery_id: delivery.delivery_id, token })).catch(() => {});
      throw error;
    }
    log('info', 'webhook_accepted', { delivery_id: delivery.delivery_id, event: delivery.event, seq: result.entry.seq, state: result.state });
    return empty(202);
  } catch (error) {
    // GitHub shows the failure and the delivery can be redelivered; the reservation makes the retry idempotent.
    log('error', 'webhook_capture_failed', { delivery_id: delivery.delivery_id, error: errorCode(error) });
    return empty(500);
  }
}

// Raw capture. `body` is the raw JSON text; `sha256` metadata is the digest of the stored object bytes.
// If-None-Match: * makes the write create-only; an existing object is adopted only if it holds the same body.
export async function storeDelivery(env, d) {
  const object = utf8(JSON.stringify({ v: 1, delivery_id: d.delivery_id, event: d.event, hook_id: d.hook_id, installation_target_id: d.installation_target_id,
    received_at: d.received_at, body_sha256: d.body_sha256, body: d.text }));
  const digest = await sha256Hex(object);
  const put = await env.EVENTS.put(d.object_key, object, {
    onlyIf: new Headers({ 'if-none-match': '*' }), sha256: digest,
    httpMetadata: { contentType: 'application/json' }, customMetadata: { sha256: digest, body_sha256: d.body_sha256, event: d.event },
  });
  if (put !== null) return;
  const existing = await env.EVENTS.head(d.object_key);
  if (existing?.customMetadata?.body_sha256 !== d.body_sha256) throw new CodedError('object_conflict');
}
