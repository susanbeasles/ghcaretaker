// End-to-end in the real Workers runtime (workerd via Miniflare): host dispatch, WebCrypto HMAC, Secrets Store
// binding, R2 conditional put, SQLite Durable Objects (triggers, RETURNING, transactionSync), alarms and the
// BackupIngest service-binding RPC. No network: the GitHub App id is unset, so GitHub lookups fail closed locally.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'esbuild';
import { sign, randomSecret, sha } from './fakes.mjs';

const STORE = 'b6504fe2d5f64352954629bc7185fb79';
const backupScript = `import {WorkerEntrypoint} from 'cloudflare:workers';
export class BackupIngest extends WorkerEntrypoint { async capture(job){ await this.env.CAPTURES.put(job.delivery_id, JSON.stringify(job)); return {accepted:true}; } }
export default {fetch(){return new Response(null,{status:404});}};`;

async function waitFor(fn, ms = 10_000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return v; await new Promise(r => setTimeout(r, 100)); }
}

test('real runtime: webhook capture, dedupe, refusal, host isolation, ledgers and backup RPC', async () => {
  const output = await build({ entryPoints: ['src/index.mjs'], bundle: true, write: false, format: 'esm', platform: 'browser', external: ['cloudflare:workers'] });
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [
    { name: 'ghcaretaker', modules: true, script: output.outputFiles[0].text, compatibilityDate: '2026-10-05', compatibilityFlags: ['global_fetch_strictly_public'],
      bindings: { AUTH_ORIGIN: 'https://control.vespoli.me', PUBLIC_ORIGIN: 'https://mcp.vespoli.me', MCP_PATH: '/ghcaretaker', HOOKS_ORIGIN: 'https://hooks.vespoli.me',
        GITHUB_OWNER: 'susanbeasles', GITHUB_OWNER_ID: '215839550', OBSERVATORY_APP_ID: '' },
      secretsStoreSecrets: { OBSERVATORY_WEBHOOK_SECRET: { store_id: STORE, secret_name: 'OBSERVATORY_WEBHOOK_SECRET' } },
      serviceBindings: { AUTH_GATEWAY: async () => new Response('gateway'), BACKUP: { name: 'backup', entrypoint: 'BackupIngest' } },
      durableObjects: { APP_VAULT: { className: 'AppVault', useSQLite: true }, EVENT_LEDGER: { className: 'EventLedger', useSQLite: true }, COMMIT_LEDGER: { className: 'CommitLedger', useSQLite: true } },
      r2Buckets: ['AUDIT_BUCKET', 'EVENTS'], d1Databases: ['AUDIT_DB'] },
    { name: 'backup', modules: true, script: backupScript, compatibilityDate: '2026-10-05', kvNamespaces: ['CAPTURES'] },
  ] }));
  try {
    const key = randomSecret();
    await (await mf.getSecretsStoreSecretAPI('OBSERVATORY_WEBHOOK_SECRET', 'ghcaretaker'))().create(key);
    const payload = { ref: 'refs/heads/main', before: sha(1), after: '0'.repeat(40), created: false, deleted: true, forced: false, pusher: { name: 'x' }, commits: [],
      repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: 215839550 } }, installation: { id: 7 } };
    const text = JSON.stringify(payload), id = crypto.randomUUID();
    const post = async (signature, deliveryId = id, url = 'https://hooks.vespoli.me/github') => mf.dispatchFetch(url, { method: 'POST', redirect: 'manual', body: text,
      headers: { 'content-type': 'application/json', 'x-github-event': 'push', 'x-github-delivery': deliveryId, 'x-hub-signature-256': signature } });

    let r = await mf.dispatchFetch('https://hooks.vespoli.me/github', { redirect: 'manual' });
    assert.equal(r.status, 404); await r.arrayBuffer();
    r = await post(await sign(randomSecret(), text)); assert.equal(r.status, 401); assert.equal(await r.text(), '');
    r = await mf.dispatchFetch('https://hooks.vespoli.me/ghcaretaker/setup', { redirect: 'manual' }); assert.equal(r.status, 404, 'MCP paths do not exist on the hooks host'); await r.arrayBuffer();
    r = await post(await sign(key, text), id, 'https://mcp.vespoli.me/github'); assert.equal(r.status, 404, 'webhook path does not exist on the MCP host'); await r.arrayBuffer();

    const events = await mf.getR2Bucket('EVENTS');
    assert.equal((await events.list()).objects.length, 0, 'nothing stored before an authenticated delivery');
    r = await post(await sign(key, text)); assert.equal(r.status, 202); assert.equal(await r.text(), '');
    const listed = (await events.list({ prefix: 'deliveries/', include: ['customMetadata'] })).objects;
    assert.equal(listed.length, 1); assert.match(listed[0].key, new RegExp(`^deliveries/\\d{4}/\\d{2}/\\d{2}/${id}\\.json$`));
    const object = await events.get(listed[0].key), stored = JSON.parse(await object.text());
    assert.equal(stored.body, text); assert.match(object.customMetadata.sha256, /^[0-9a-f]{64}$/);
    r = await post(await sign(key, text)); assert.equal(r.status, 202, 'duplicate acknowledged'); await r.arrayBuffer();
    assert.equal((await events.head(listed[0].key)).etag, object.etag, 'duplicate did not rewrite');

    const ledgerNs = await mf.getDurableObjectNamespace('EVENT_LEDGER', 'ghcaretaker');
    const ledger = ledgerNs.get(ledgerNs.idFromName('global'));
    assert.equal((await ledger.head()).seq, 1);
    assert.equal((await ledger.verify()).ok, true);

    const captures = await mf.getKVNamespace('CAPTURES', 'backup');
    const job = await waitFor(async () => captures.get(id, 'json'));
    assert.deepEqual(job, { repo_id: 42, reason: 'push', delivery_id: id });

    const commitNs = await mf.getDurableObjectNamespace('COMMIT_LEDGER', 'ghcaretaker');
    const commitLedger = commitNs.get(commitNs.idFromName('42'));
    const found = await waitFor(async () => (await commitLedger.findings()).items.length ? (await commitLedger.findings()).items : null);
    assert.deepEqual(found.map(f => f.kind), ['main_deleted']);
    assert.equal((await commitLedger.verify()).ok, true);
    const mirror = await waitFor(async () => events.get('commits/42/1.json'));
    assert.equal(JSON.parse(await mirror.text()).kind, 'ref_update');
  } finally { await mf.dispose(); }
});
