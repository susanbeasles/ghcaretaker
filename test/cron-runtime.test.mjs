// Cron and anchor path in the real Workers runtime (workerd via Miniflare): the scheduled handler, Durable Object
// alarms doing the flagged work, R2 `observatory-anchors` create-only writes and `list({startAfter})`, the anchor read
// method over RPC, the App JWT (WebCrypto RS256 in workerd) for GitHub's hook delivery log and redelivery, and ref
// reconciliation with an installation token. GitHub is a local outbound stub; nothing leaves the machine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'esbuild';
import { sign, randomSecret, pkcs8Pem } from './fakes.mjs';
import { CRON_HOURLY, CRON_REFS } from '../src/cron.mjs';
import { parseAnchor, anchorKey } from '../src/anchors.mjs';

const STORE = 'b6504fe2d5f64352954629bc7185fb79';
const backupScript = `import {WorkerEntrypoint} from 'cloudflare:workers';
export class BackupIngest extends WorkerEntrypoint { async capture(){ return {ok:true, job_id:'x', duplicate:false}; } }
export default {fetch(){return new Response(null,{status:404});}};`;

async function waitFor(fn, ms = 15_000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return v; await new Promise(r => setTimeout(r, 100)); }
}

test('real runtime: cron writes and verifies anchors for both ledgers, reconciles hook deliveries and refs', async () => {
  const output = await build({ entryPoints: ['src/index.mjs'], bundle: true, write: false, format: 'esm', platform: 'browser', external: ['cloudflare:workers'] });
  const id = crypto.randomUUID(), missing = crypto.randomUUID(), outbound = [], alerts = [];
  const github = async request => {
    const u = new URL(request.url), auth = request.headers.get('authorization') ?? '';
    outbound.push({ method: request.method, host: u.host, path: u.pathname, jwt: auth.split('.').length === 3 });
    if (u.host === 'alerts.invalid') { alerts.push(await request.json()); return new Response(null, { status: 204 }); }
    if (u.host !== 'api.github.com') return new Response(null, { status: 599 });
    if (u.pathname === '/app/installations/7/access_tokens') return Response.json({ token: 'installation-token', expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: { contents: 'read', metadata: 'read' } }, { status: 201 });
    if (u.pathname === '/app/hook/deliveries') {
      const when = new Date(Date.now() - 60_000).toISOString();
      return Response.json([{ id: 1, guid: id, delivered_at: when, status_code: 202, redelivery: false, event: 'push' }, { id: 2, guid: missing, delivered_at: when, status_code: 500, redelivery: false, event: 'push' }]);
    }
    if (u.pathname === '/app/hook/deliveries/2/attempts' && request.method === 'POST') return new Response(null, { status: 202 });
    if (u.pathname.startsWith('/repos/susanbeasles/demo/git/matching-refs/')) return Response.json([]);
    return new Response(null, { status: 404 });
  };
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [
    { name: 'ghcaretaker', modules: true, script: output.outputFiles[0].text, compatibilityDate: '2026-10-05', compatibilityFlags: ['global_fetch_strictly_public'],
      bindings: { AUTH_ORIGIN: 'https://control.vespoli.me', PUBLIC_ORIGIN: 'https://mcp.vespoli.me', MCP_PATH: '/ghcaretaker', HOOKS_ORIGIN: 'https://hooks.vespoli.me',
        GITHUB_OWNER: 'susanbeasles', GITHUB_OWNER_ID: '215839550', OBSERVATORY_APP_ID: '123456' },
      secretsStoreSecrets: {
        OBSERVATORY_WEBHOOK_SECRET: { store_id: STORE, secret_name: 'OBSERVATORY_WEBHOOK_SECRET' },
        OBSERVATORY_APP_KEY: { store_id: STORE, secret_name: 'OBSERVATORY_APP_KEY' },
        ALERT_WEBHOOK_URL: { store_id: STORE, secret_name: 'ALERT_WEBHOOK_URL' } },
      serviceBindings: { AUTH_GATEWAY: async () => new Response('gateway'), BACKUP: { name: 'backup', entrypoint: 'BackupIngest' } },
      durableObjects: { APP_VAULT: { className: 'AppVault', useSQLite: true }, EVENT_LEDGER: { className: 'EventLedger', useSQLite: true }, COMMIT_LEDGER: { className: 'CommitLedger', useSQLite: true } },
      r2Buckets: ['AUDIT_BUCKET', 'EVENTS', 'ANCHORS'], d1Databases: ['AUDIT_DB'], outboundService: github },
    { name: 'backup', modules: true, script: backupScript, compatibilityDate: '2026-10-05' },
  ] }));
  try {
    const key = randomSecret(), secrets = async name => (await mf.getSecretsStoreSecretAPI(name, 'ghcaretaker'))();
    await (await secrets('OBSERVATORY_WEBHOOK_SECRET')).create(key);
    await (await secrets('OBSERVATORY_APP_KEY')).create((await pkcs8Pem()).pem);
    await (await secrets('ALERT_WEBHOOK_URL')).create('https://alerts.invalid/hook');
    const text = JSON.stringify({ ref: 'refs/heads/main', before: 'a'.repeat(40), after: '0'.repeat(40), created: false, deleted: true, forced: false, pusher: { name: 'x' }, commits: [],
      repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: 215839550 }, default_branch: 'main' }, installation: { id: 7 } });
    const r = await mf.dispatchFetch('https://hooks.vespoli.me/github', { method: 'POST', redirect: 'manual', body: text,
      headers: { 'content-type': 'application/json', 'x-github-event': 'push', 'x-github-delivery': id, 'x-hub-signature-256': await sign(key, text) } });
    assert.equal(r.status, 202); await r.arrayBuffer();

    const ledgerNs = await mf.getDurableObjectNamespace('EVENT_LEDGER', 'ghcaretaker'), ledger = ledgerNs.get(ledgerNs.idFromName('global'));
    const commitNs = await mf.getDurableObjectNamespace('COMMIT_LEDGER', 'ghcaretaker'), commitLedger = commitNs.get(commitNs.idFromName('42'));
    assert.ok(await waitFor(async () => (await commitLedger.head()).seq === 1), 'commit ledger received the push');
    assert.deepEqual(await ledger.ledgeredRepos(), [42]);

    const worker = await mf.getWorker('ghcaretaker');
    await worker.scheduled({ cron: CRON_HOURLY, scheduledTime: new Date() });
    const anchors = await mf.getR2Bucket('ANCHORS');
    const listed = await waitFor(async () => { const l = (await anchors.list({ prefix: 'anchors/' })).objects.map(o => o.key).sort(); return l.length === 2 ? l : null; });
    assert.deepEqual(listed, [anchorKey('commit-42', 1), anchorKey('event', 1)]);
    for (const k of listed) {
      const record = parseAnchor(await (await anchors.get(k)).text(), k);
      assert.equal(record.seq, 1); assert.equal(record.entry_count, 1); assert.equal(record.prev_anchor_hash, '0'.repeat(64));
    }
    assert.equal(parseAnchor(await (await anchors.get(anchorKey('event', 1))).text(), anchorKey('event', 1)).head_hash, (await ledger.head()).entry_hash);
    const verified = await ledger.verifyAnchor();
    assert.equal(verified.ok, true); assert.equal(verified.anchor.seq, 1);
    assert.equal((await commitLedger.verifyAnchor()).ok, true);

    const hook = await waitFor(async () => (await ledger.head()).hook_reconcile);
    assert.equal(hook.ok, true, JSON.stringify(hook)); assert.equal(hook.missing, 1); assert.equal(hook.redelivered, 1);
    const redeliveries = outbound.filter(o => o.path.endsWith('/attempts'));
    assert.deepEqual(redeliveries.map(o => [o.method, o.path, o.jwt]), [['POST', '/app/hook/deliveries/2/attempts', true]], 'only the missing guid, with the App JWT');

    // A second hourly run with no new entries writes no new anchor and still verifies.
    await worker.scheduled({ cron: CRON_HOURLY, scheduledTime: new Date() });
    await new Promise(r => setTimeout(r, 500));
    assert.equal((await anchors.list({ prefix: 'anchors/' })).objects.length, 2);

    await worker.scheduled({ cron: CRON_REFS, scheduledTime: new Date() });
    const refs = await waitFor(async () => (await commitLedger.head()).refs_last_run);
    assert.equal(refs.ok, true, JSON.stringify(refs)); assert.equal(refs.listing_complete, true); assert.equal(refs.in_sync, 1, 'main: deleted in the ledger and absent on GitHub');
    assert.ok(outbound.some(o => o.path === '/repos/susanbeasles/demo/git/matching-refs/heads'));
    assert.ok(await waitFor(async () => alerts.some(a => a.code === 'main_deleted' && a.severity === 'critical')), 'alerts leave through the outbound fetch');
  } finally { await mf.dispose(); }
});
