import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintInstallationToken, commitDetails, promotionTagTarget } from '../src/github-app.mjs';
import { unb64 } from '../src/crypto.mjs';
import { secret, pkcs8Pem, sha } from './fakes.mjs';

async function appEnv() {
  const { pem, publicKey } = await pkcs8Pem();
  return { env: { OBSERVATORY_APP_ID: '123456', OBSERVATORY_APP_KEY: secret(pem) }, publicKey };
}

test('installation token: RS256 App JWT, single repository, contents:read only, redirects refused', async () => {
  const { env, publicKey } = await appEnv(), calls = [];
  const token = await mintInstallationToken(env, 7, 42, async (url, init) => {
    calls.push({ url, init });
    return Response.json({ token: 'short-lived', expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: { contents: 'read', metadata: 'read' } }, { status: 201 });
  });
  assert.equal(token.token, 'short-lived');
  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, 'https://api.github.com/app/installations/7/access_tokens');
  assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'manual'); assert.ok(init.signal);
  assert.deepEqual(JSON.parse(init.body), { repository_ids: [42], permissions: { contents: 'read' } });
  const jwt = init.headers.Authorization.replace('Bearer ', ''), [h, p, s] = jwt.split('.');
  assert.deepEqual(JSON.parse(new TextDecoder().decode(unb64(h))), { alg: 'RS256', typ: 'JWT' });
  const claims = JSON.parse(new TextDecoder().decode(unb64(p)));
  assert.equal(claims.iss, '123456'); assert.ok(claims.exp - claims.iat <= 600);
  assert.ok(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, unb64(s), new TextEncoder().encode(h + '.' + p)));
});

test('a broader-than-requested token is revoked and refused; missing App id or key fails closed', async () => {
  const { env } = await appEnv(), seen = [];
  await assert.rejects(mintInstallationToken(env, 7, 42, async (url, init) => {
    seen.push([init.method, url]);
    if (url.endsWith('/access_tokens')) return Response.json({ token: 'too-broad', expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: { contents: 'write' } }, { status: 201 });
    return new Response(null, { status: 204 });
  }), /token_too_broad/);
  assert.deepEqual(seen.at(-1), ['DELETE', 'https://api.github.com/installation/token']);
  let called = false;
  const never = async () => { called = true; return new Response(null, { status: 500 }); };
  await assert.rejects(mintInstallationToken({ ...env, OBSERVATORY_APP_ID: '' }, 7, 42, never), /app_unconfigured/);
  await assert.rejects(mintInstallationToken({ ...env, OBSERVATORY_APP_KEY: 'not-a-binding' }, 7, 42, never), /app_key_unavailable/);
  await assert.rejects(mintInstallationToken(env, 0, 42, never), /bad_installation/);
  assert.equal(called, false);
});

test('commit details: bounded files list, message reduced to sha256, verification copied, 404 recorded fail-closed', async () => {
  const s = sha(2), urls = [];
  const fetcher = async (url, init) => {
    urls.push(url); assert.equal(init.redirect, 'manual');
    if (url.includes(sha(3))) return new Response('{"message":"Not Found"}', { status: 404 });
    return Response.json({ sha: s, parents: [{ sha: sha(1) }], commit: { tree: { sha: sha(100) }, message: 'feat: hello',
      author: { name: 'A', email: 'a@users.noreply.github.com', date: '2026-10-15T10:00:00Z' }, committer: { name: 'GitHub', date: '2026-10-15T10:01:00Z' },
      verification: { verified: true, reason: 'valid', signature: '-----BEGIN PGP SIGNATURE-----', payload: 'tree ...' } }, files: [] });
  };
  const d = await commitDetails('susanbeasles/demo', s, 'tok', fetcher);
  assert.equal(urls[0], `https://api.github.com/repos/susanbeasles/demo/commits/${s}?per_page=1`);
  const { createHash } = await import('node:crypto');
  assert.deepEqual(d, { sha: s, tree: sha(100), parents: [sha(1)], author_name: 'A', author_date: '2026-10-15T10:00:00Z', committer_name: 'GitHub', committer_date: '2026-10-15T10:01:00Z',
    message_sha256: createHash('sha256').update('feat: hello').digest('hex'), verified: true, verification_reason: 'valid' });
  assert.ok(!JSON.stringify(d).includes('PGP') && !JSON.stringify(d).includes('noreply'));
  assert.deepEqual((await commitDetails('susanbeasles/demo', sha(3), 'tok', fetcher)).verification_reason, 'commit_unavailable_404');
  await assert.rejects(commitDetails('susanbeasles/demo', s, 'tok', async () => new Response('x', { status: 502 })), /github_http_502/);
  await assert.rejects(commitDetails('susanbeasles/demo', s, 'tok', async () => { throw TypeError('redirect'); }), /github_network/);
  await assert.rejects(commitDetails('../../x', s, 'tok', fetcher), /bad_repo_name/);
});

test('promotion targets resolve exact refs and nested annotated tags, refusing loops and malformed names', async () => {
 const target=sha(5), tag=sha(500), nested=sha(501), ref='promote/pr-7-'+target.slice(0,12);let calls=0;
 const fetcher=async url=>{calls++;return Response.json({object:url.includes('/git/ref/')?{type:'tag',sha:tag}:url.endsWith(tag)?{type:'tag',sha:nested}:{type:'commit',sha:target}});};
 assert.equal(await promotionTagTarget('susanbeasles/demo',ref,'tok',fetcher),target);assert.equal(calls,3);
 assert.equal(await promotionTagTarget('susanbeasles/demo',ref+'x','tok',fetcher),null);assert.equal(calls,3);
 assert.equal(await promotionTagTarget('susanbeasles/demo',ref,'tok',async()=>Response.json({object:{type:'tag',sha:tag}})),null);
 assert.equal(await promotionTagTarget('susanbeasles/demo',ref,'tok',async()=>Response.json({object:{type:'commit',sha:sha(6)}})),sha(6),'full target returned; core must compare exact expected SHA');
});

test('promotion target charges each request and defers before the next annotated tag fetch', async () => {
 const target=sha(5), ref='promote/pr-7-'+target.slice(0,12), budget={api:2};let calls=0;
 const fetcher=async()=>Response.json({object:++calls<3?{type:'tag',sha:sha(500+calls)}:{type:'commit',sha:target}});
 await assert.rejects(promotionTagTarget('susanbeasles/demo',ref,'tok',fetcher,budget),{code:'deferred'});
 assert.equal(calls,2);assert.equal(budget.api,0);
 await assert.rejects(promotionTagTarget('susanbeasles/demo',ref,'tok',fetcher,budget),{code:'deferred'});
 assert.equal(calls,2);
 const fresh={api:3};calls=0;
 assert.equal(await promotionTagTarget('susanbeasles/demo',ref,'tok',fetcher,fresh),target);
 assert.equal(calls,3);assert.equal(fresh.api,0);
});
