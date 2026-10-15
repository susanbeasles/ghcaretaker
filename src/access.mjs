// Cloudflare Access assertion check for the caretaker dashboard (infra-root ADR-0001 section 3).
// Access (IdP + MFA, owner only) sits in front of caretaker.vespoli.me; the Worker still verifies every request's
// Cf-Access-Jwt-Assertion itself so a missing or mis-scoped Access application can never expose the dashboard:
//   RS256 only, key from `${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs` (cached 1 h, refreshed on an unknown kid at
//   most once per 30 s), iss == team domain, aud contains ACCESS_AUD, exp/nbf with 30 s skew, email == OWNER_EMAIL.
// Any failure is a reason code for the log; the caller answers 403 with no detail. Tokens are never logged.
import { CodedError, decodeUtf8, fetchNoRedirect, readBounded } from './bytes.mjs';
import { unb64 } from './crypto.mjs';

export const JWKS_TTL_MS = 3_600_000;
export const KID_MISS_REFRESH_MS = 30_000;
export const CLOCK_SKEW_S = 30;
const MAX_ASSERTION = 8192;
const TEAM_DOMAIN = /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/;
const AUD = /^[0-9a-f]{64}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

const caches = new Map(); // certs URL -> {keys: Map(kid -> CryptoKey), fetched_at, last_miss_refresh}
export const _resetAccessCache = () => caches.clear();

class AccessDenied extends CodedError {}
const deny = code => { throw new AccessDenied(code); };

function json(part) {
  if (!B64URL.test(part)) deny('malformed');
  let value;
  try { value = JSON.parse(decodeUtf8(unb64(part))); } catch { deny('malformed'); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) deny('malformed');
  return value;
}

export function accessConfig(env) {
  const team = String(env.ACCESS_TEAM_DOMAIN ?? ''), aud = String(env.ACCESS_AUD ?? ''), email = String(env.OWNER_EMAIL ?? '');
  if (!TEAM_DOMAIN.test(team) || !AUD.test(aud) || !EMAIL.test(email)) return null;
  return { team, aud, email: email.toLowerCase(), certs: team + '/cdn-cgi/access/certs' };
}

async function fetchKeys(certsUrl, fetcher) {
  let response;
  try { response = await fetchNoRedirect(fetcher, certsUrl, { signal: AbortSignal.timeout(5_000), headers: { accept: 'application/json' } }); }
  catch { deny('jwks_unavailable'); }
  if (response.status !== 200) { await response.body?.cancel().catch(() => {}); deny('jwks_unavailable'); }
  let body;
  try { body = JSON.parse(decodeUtf8(await readBounded(response.body, 64 * 1024))); } catch { deny('jwks_malformed'); }
  const keys = new Map();
  for (const jwk of Array.isArray(body?.keys) ? body.keys.slice(0, 16) : []) {
    if (jwk?.kty !== 'RSA' || typeof jwk.kid !== 'string' || jwk.kid.length > 128 || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue;
    if (jwk.alg !== undefined && jwk.alg !== 'RS256') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') continue;
    try {
      keys.set(jwk.kid, await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']));
    } catch { /* skip unusable key */ }
  }
  if (keys.size === 0) deny('jwks_empty');
  return keys;
}

async function keyFor(cfg, kid, fetcher, nowMs) {
  let cache = caches.get(cfg.certs);
  if (!cache || nowMs - cache.fetched_at >= JWKS_TTL_MS) {
    cache = { keys: await fetchKeys(cfg.certs, fetcher), fetched_at: nowMs, last_miss_refresh: cache?.last_miss_refresh ?? 0 };
    caches.set(cfg.certs, cache);
  }
  if (cache.keys.has(kid)) return cache.keys.get(kid);
  // Unknown kid: a rotation may have happened. Refresh once, rate limited so junk kids cannot drive fetches.
  if (nowMs - cache.last_miss_refresh < KID_MISS_REFRESH_MS || nowMs - cache.fetched_at < 1_000) deny('unknown_kid');
  cache.last_miss_refresh = nowMs;
  const keys = await fetchKeys(cfg.certs, fetcher);
  caches.set(cfg.certs, { keys, fetched_at: nowMs, last_miss_refresh: nowMs });
  return keys.get(kid) ?? deny('unknown_kid');
}

/**
 * Verifies the request's Access assertion. Returns {email, sub} or throws a CodedError whose code is a reason
 * (`no_assertion`, `unconfigured`, `malformed`, `bad_alg`, `unknown_kid`, `bad_signature`, `bad_issuer`, `bad_audience`,
 * `expired`, `not_yet_valid`, `wrong_identity`, `jwks_*`).
 */
export async function verifyAccess(request, env, { fetcher = fetch, now = Date.now } = {}) {
  const assertion = request.headers.get('cf-access-jwt-assertion');
  if (!assertion) deny('no_assertion');
  const cfg = accessConfig(env);
  if (!cfg) deny('unconfigured');
  if (assertion.length > MAX_ASSERTION) deny('malformed');
  const parts = assertion.split('.');
  if (parts.length !== 3) deny('malformed');
  const header = json(parts[0]), claims = json(parts[1]);
  if (header.alg !== 'RS256' || (header.typ !== undefined && header.typ !== 'JWT') || header.crit !== undefined) deny('bad_alg');
  if (typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 128) deny('malformed');
  if (!B64URL.test(parts[2])) deny('malformed');
  const nowMs = now();
  const key = await keyFor(cfg, header.kid, fetcher, nowMs);
  let valid = false;
  try { valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1])); } catch { valid = false; }
  if (!valid) deny('bad_signature');
  if (claims.iss !== cfg.team) deny('bad_issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.some(a => a === cfg.aud)) deny('bad_audience');
  const t = Math.floor(nowMs / 1000);
  if (!Number.isSafeInteger(claims.exp) || claims.exp + CLOCK_SKEW_S <= t) deny('expired');
  if (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf - CLOCK_SKEW_S > t)) deny('not_yet_valid');
  if (claims.iat !== undefined && (!Number.isSafeInteger(claims.iat) || claims.iat - CLOCK_SKEW_S > t)) deny('not_yet_valid');
  if (typeof claims.email !== 'string' || claims.email.toLowerCase() !== cfg.email) deny('wrong_identity');
  return { email: claims.email, sub: typeof claims.sub === 'string' ? claims.sub : null };
}
