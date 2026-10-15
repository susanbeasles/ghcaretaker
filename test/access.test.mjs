// Authorization only: the Cf-Access-Jwt-Assertion gate (src/access.mjs) and the fact that every dashboard route,
// including /api/* and the stylesheet, sits behind it. Presentation is tested in dashboard-render.test.mjs.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAccess, _resetAccessCache, JWKS_TTL_MS, KID_MISS_REFRESH_MS } from '../src/access.mjs';
import { handleDashboard } from '../src/dashboard.mjs';
import { accessKit, ACCESS_TEAM } from './fakes.mjs';

beforeEach(() => _resetAccessCache());

const req = (token, path = '/', method = 'GET') => new Request('https://caretaker.vespoli.me' + path, { method, headers: token === undefined ? {} : { 'cf-access-jwt-assertion': token } });
const reason = async promise => { try { await promise; return 'accepted'; } catch (e) { return e.code; } };

test('a valid owner assertion is accepted; JWKS fetched once without following redirects and cached', async () => {
  const kit = await accessKit();
  const token = await kit.sign();
  const who = await verifyAccess(req(token), kit.env, { fetcher: kit.fetcher });
  assert.equal(who.email, 'owner@vespoli.test');
  await verifyAccess(req(token), kit.env, { fetcher: kit.fetcher });
  assert.equal(kit.certFetches, 1);
  // Email comparison is case-insensitive (Access may normalise case).
  assert.equal((await verifyAccess(req(await kit.sign(kit.claims({ email: 'Owner@Vespoli.TEST' }))), kit.env, { fetcher: kit.fetcher })).email, 'Owner@Vespoli.TEST');
});

test('every refusal case has its own reason', async () => {
  const kit = await accessKit(), other = await accessKit({ kid: kit.kid });
  const t = Math.floor(Date.now() / 1000), o = { fetcher: kit.fetcher };
  const cases = [
    ['no_assertion', undefined],
    ['no_assertion', ''],
    ['malformed', 'not-a-jwt'],
    ['malformed', 'a.b'],
    ['malformed', 'x'.repeat(9000)],
    ['malformed', '!!!.???.***'],
    ['bad_alg', await kit.sign(kit.claims(), { alg: 'HS256' })],
    ['bad_alg', await kit.sign(kit.claims(), { alg: 'none' })],
    ['bad_alg', await kit.sign(kit.claims(), { crit: ['exp'] })],
    ['malformed', await kit.sign(kit.claims(), { kid: undefined })],
    ['bad_signature', await other.sign()],
    ['bad_signature', (await kit.sign()).replace(/\.[^.]+$/, '.' + Buffer.from('forged').toString('base64url'))],
    ['bad_audience', await kit.sign(kit.claims({ aud: ['c'.repeat(64)] }))],
    ['bad_audience', await kit.sign(kit.claims({ aud: [] }))],
    ['bad_issuer', await kit.sign(kit.claims({ iss: 'https://evil.cloudflareaccess.com' }))],
    ['bad_issuer', await kit.sign(kit.claims({ iss: ACCESS_TEAM + '/' }))],
    ['expired', await kit.sign(kit.claims({ exp: t - 120 }))],
    ['expired', await kit.sign(kit.claims({ exp: undefined }))],
    ['not_yet_valid', await kit.sign(kit.claims({ nbf: t + 600 }))],
    ['not_yet_valid', await kit.sign(kit.claims({ iat: t + 600 }))],
    ['wrong_identity', await kit.sign(kit.claims({ email: 'someone@else.test' }))],
    ['wrong_identity', await kit.sign(kit.claims({ email: undefined }))],
    ['unknown_kid', await kit.sign(kit.claims(), { kid: 'rotated-away' })],
  ];
  for (const [expected, token] of cases) assert.equal(await reason(verifyAccess(req(token), kit.env, o)), expected, expected + ' for ' + String(token).slice(0, 40));
  // A token that tampers its claims after signing.
  const [h, , s] = (await kit.sign()).split('.');
  const forgedClaims = Buffer.from(JSON.stringify(kit.claims({ email: 'owner@vespoli.test', aud: ['c'.repeat(64)] }))).toString('base64url');
  assert.equal(await reason(verifyAccess(req(h + '.' + forgedClaims + '.' + s), kit.env, o)), 'bad_signature');
});

test('missing or malformed configuration denies everyone (fail closed)', async () => {
  const kit = await accessKit(), token = await kit.sign();
  for (const patch of [{ ACCESS_AUD: '' }, { OWNER_EMAIL: '' }, { ACCESS_TEAM_DOMAIN: 'https://evil.example' }, { ACCESS_TEAM_DOMAIN: 'http://vespoli.cloudflareaccess.com' }, { ACCESS_AUD: 'short' }]) {
    assert.equal(await reason(verifyAccess(req(token), { ...kit.env, ...patch }, { fetcher: kit.fetcher })), 'unconfigured', JSON.stringify(patch));
  }
  assert.equal(kit.certFetches, 0, 'nothing fetched while unconfigured');
});

test('JWKS: unknown kid refreshes once (rate limited); 1 h TTL; a rotated key is picked up; certs outage denies', async () => {
  let now = Date.parse('2026-10-15T12:00:00Z');
  const kit = await accessKit(), o = { fetcher: kit.fetcher, now: () => now };
  const signAt = (over = {}, header) => kit.sign(kit.claims({ exp: Math.floor(now / 1000) + 600, iat: Math.floor(now / 1000), nbf: Math.floor(now / 1000), ...over }), header);
  await verifyAccess(req(await signAt()), kit.env, o);
  assert.equal(kit.certFetches, 1);
  now += 5_000;
  assert.equal(await reason(verifyAccess(req(await signAt({}, { kid: 'junk-1' })), kit.env, o)), 'unknown_kid');
  assert.equal(kit.certFetches, 2, 'one refresh on a kid miss');
  now += 1_000;
  assert.equal(await reason(verifyAccess(req(await signAt({}, { kid: 'junk-2' })), kit.env, o)), 'unknown_kid');
  assert.equal(kit.certFetches, 2, 'junk kids cannot drive fetches');
  // Rotation: Access publishes a new kid; after the rate-limit window the miss refresh finds it.
  const rotated = await accessKit({ kid: 'kid-new' });
  kit.keys.push(...rotated.keys);
  now += KID_MISS_REFRESH_MS;
  assert.equal((await verifyAccess(req(await rotated.sign(rotated.claims({ exp: Math.floor(now / 1000) + 600, iat: Math.floor(now / 1000), nbf: Math.floor(now / 1000) }))), kit.env, o)).email, 'owner@vespoli.test');
  assert.equal(kit.certFetches, 3);
  now += JWKS_TTL_MS;
  await verifyAccess(req(await signAt()), kit.env, o);
  assert.equal(kit.certFetches, 4, 'TTL expiry refetches');
  _resetAccessCache();
  for (const down of [async () => { throw new Error('offline'); }, async () => new Response(null, { status: 302, headers: { location: 'https://evil.example' } }), async () => new Response('{"keys":[]}'), async () => new Response('\xff\xfe')]) {
    assert.match(await reason(verifyAccess(req(await signAt()), kit.env, { fetcher: down, now: () => now })), /^jwks_/);
  }
});

test('every dashboard route, /api/* twin, the stylesheet, unknown paths and every method are behind the gate: 403, empty, never 3xx', async () => {
  const kit = await accessKit();
  const bad = [undefined, 'garbage', await kit.sign(kit.claims({ aud: ['c'.repeat(64)] })), await kit.sign(kit.claims({ email: 'x@y.test' })), await kit.sign(kit.claims({ exp: 1 }))];
  const env = { ...kit.env }; // no data bindings at all: the gate must answer before anything is read
  const paths = ['/', '/events', '/events?cursor=5', '/repos/42/commits', '/repos/42/verify', '/promotions', '/actions', '/actions?days=30', '/style.css',
    '/api/overview', '/api/events', '/api/repos/42/commits', '/api/repos/42/verify', '/api/promotions', '/api/actions', '/nope', '/favicon.ico', '/api/', '/../etc'];
  for (const token of bad) for (const path of paths) for (const method of ['GET', 'HEAD', 'POST']) {
    const r = await handleDashboard(req(token, path, method), env, { fetcher: kit.fetcher });
    assert.equal(r.status, 403, `${method} ${path}`);
    assert.equal(await r.text(), '', 'no detail');
    assert.equal(r.headers.get('location'), null);
    assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  }
  // With a valid assertion the same paths are never redirects either.
  const good = await kit.sign();
  for (const path of paths) {
    const r = await handleDashboard(req(good, path), env, { fetcher: kit.fetcher });
    assert.ok(r.status < 300 || r.status >= 400, path + ' ' + r.status);
    await r.arrayBuffer();
  }
  assert.equal((await handleDashboard(req(good, '/style.css'), env, { fetcher: kit.fetcher })).status, 200);
  assert.equal((await handleDashboard(req(good, '/', 'POST'), env, { fetcher: kit.fetcher })).status, 405);
});
