// Caretaker dashboard: https://caretaker.vespoli.me/ (DASHBOARD_ORIGIN), read only, owner only.
// Order: Access assertion first for EVERY request (pages, /api, /style.css, unknown paths) -> 403 with an empty
// body on any failure; then GET/HEAD only; then exact routes. Never a 3xx. Strict CSP, no scripts, no external
// resources. JSON twins live under /api/.
import { verifyAccess } from './access.mjs';
import { CodedError } from './bytes.mjs';
import { log, errorCode } from './log.mjs';
import { actionsData, commitsData, eventsData, overviewData, promotionsData, verifyData } from './dashboard-data.mjs';
import { CSS, actionsPage, commitsPage, eventsPage, messagePage, overviewPage, promotionsPage, verifyPage } from './dashboard-html.mjs';

export const CSP = "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const BASE_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'strict-transport-security': 'max-age=31536000',
};

function respond(request, status, body, type, extra = {}) {
  const headers = { ...BASE_HEADERS, 'cache-control': 'no-store', ...(type ? { 'content-type': type } : {}), ...extra };
  return new Response(request.method === 'HEAD' || body === null ? null : body, { status, headers });
}
const plain = (request, status, text) => respond(request, status, text, 'text/plain; charset=utf-8');

const POSITIVE = /^[1-9]\d{0,15}$/;
function intParam(url, name, { min = 1, max = Number.MAX_SAFE_INTEGER, fallback = null } = {}) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return fallback;
  if (!POSITIVE.test(raw)) throw new CodedError('bad_param');
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new CodedError('bad_param');
  return n;
}
const repoParam = raw => { if (!POSITIVE.test(raw)) throw new CodedError('bad_param'); const n = Number(raw); if (!Number.isSafeInteger(n)) throw new CodedError('bad_param'); return n; };

// [pattern, data(env, url, match, deps), render]
const ROUTES = [
  [/^\/(?:overview)?$/, (env, url, m, deps) => overviewData(env, deps), overviewPage],
  [/^\/events$/, (env, url) => eventsData(env, { limit: intParam(url, 'limit', { max: 100, fallback: 50 }), cursor: intParam(url, 'cursor') }), eventsPage],
  [/^\/repos\/([^/]+)\/commits$/, (env, url, m) => commitsData(env, repoParam(m[1]), { limit: intParam(url, 'limit', { max: 100, fallback: 50 }), cursor: intParam(url, 'cursor') }), commitsPage],
  [/^\/repos\/([^/]+)\/verify$/, (env, url, m) => verifyData(env, repoParam(m[1])), verifyPage],
  [/^\/promotions$/, (env, url) => promotionsData(env, { repoId: intParam(url, 'repo') }), promotionsPage],
  [/^\/actions$/, (env, url, m, deps) => {
    const days = intParam(url, 'days', { max: 30, fallback: 7 });
    if (days !== 7 && days !== 30) throw new CodedError('bad_param');
    return actionsData(env, { days, now: deps.now });
  }, actionsPage],
];

export async function handleDashboard(request, env, deps = {}) {
  try { await verifyAccess(request, env, deps); }
  catch (e) {
    log('warning', 'dashboard_access_denied', { reason: errorCode(e) });
    return respond(request, 403, null, null);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return respond(request, 405, null, null, { allow: 'GET, HEAD' });
  const url = new URL(request.url);
  if (url.pathname === '/style.css') return respond(request, 200, CSS, 'text/css; charset=utf-8', { 'cache-control': 'private, max-age=3600' });
  const api = url.pathname.startsWith('/api/');
  const path = api ? url.pathname.slice(4) : url.pathname;
  if (api && path === '/') return plain(request, 404, 'Not found');
  for (const [pattern, load, render] of ROUTES) {
    const m = pattern.exec(path);
    if (!m) continue;
    if (!api && path === '/overview') break; // the HTML overview lives at "/"
    let data;
    try { data = await load(env, url, m, { now: deps.now ?? Date.now }); }
    catch (e) {
      const code = errorCode(e);
      if (code.startsWith('bad_')) return api ? respond(request, 400, JSON.stringify({ error: code }), 'application/json; charset=utf-8') : respond(request, 400, messagePage('Bad request', 'The request parameters are not valid.'), 'text/html; charset=utf-8');
      log('error', 'dashboard_failed', { path: path.replace(/\d+/g, ':n').slice(0, 80), error: code });
      return api ? respond(request, 500, JSON.stringify({ error: 'unavailable' }), 'application/json; charset=utf-8') : respond(request, 500, messagePage('Unavailable', 'This view could not be loaded. See the Worker logs.'), 'text/html; charset=utf-8');
    }
    return api ? respond(request, 200, JSON.stringify(data), 'application/json; charset=utf-8') : respond(request, 200, render(data), 'text/html; charset=utf-8');
  }
  return plain(request, 404, 'Not found');
}
