// End to end in workerd (Miniflare): host dispatch to the dashboard, the Access gate with WebCrypto JWK import,
// the D1 migration, a signed workflow_job webhook flowing through the event ledger outbox into D1, the dashboard
// reading it back, and the BackupStatus service-binding RPC. No network: outbound fetches go to a local stub that
// serves only the Access certs; the GitHub App id is unset so enrichment is skipped (fail closed, stored as null).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'esbuild';
import { sign, randomSecret, accessKit, ACCESS_TEAM } from './fakes.mjs';

const STORE = 'b6504fe2d5f64352954629bc7185fb79';
const backupScript = `import {WorkerEntrypoint} from 'cloudflare:workers';
export class BackupIngest extends WorkerEntrypoint { async capture(){ return {accepted:true}; } }
export class BackupStatus extends WorkerEntrypoint { async summary(){ return {last_success_at:'2026-10-15T03:20:00Z', note:'<b>hi</b>'}; } }
export default {fetch(){return new Response(null,{status:404});}};`;

async function waitFor(fn, ms = 10_000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return v; await new Promise(r => setTimeout(r, 100)); }
}

test('real runtime: Access-gated dashboard host, D1 metrics from a webhook, backup status RPC', async () => {
  const kit = await accessKit();
  const output = await build({ entryPoints: ['src/index.mjs'], bundle: true, write: false, format: 'esm', platform: 'browser', external: ['cloudflare:workers'] });
  const outbound = [];
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [
    { name: 'ghcaretaker', modules: true, script: output.outputFiles[0].text, compatibilityDate: '2026-10-05', compatibilityFlags: ['global_fetch_strictly_public'],
      bindings: { AUTH_ORIGIN: 'https://control.vespoli.me', PUBLIC_ORIGIN: 'https://mcp.vespoli.me', MCP_PATH: '/ghcaretaker', HOOKS_ORIGIN: 'https://hooks.vespoli.me',
        DASHBOARD_ORIGIN: 'https://caretaker.vespoli.me', ACCESS_TEAM_DOMAIN: ACCESS_TEAM, ACCESS_AUD: kit.env.ACCESS_AUD, OWNER_EMAIL: kit.env.OWNER_EMAIL,
        GITHUB_OWNER: 'susanbeasles', GITHUB_OWNER_ID: '215839550', OBSERVATORY_APP_ID: '' },
      secretsStoreSecrets: { OBSERVATORY_WEBHOOK_SECRET: { store_id: STORE, secret_name: 'OBSERVATORY_WEBHOOK_SECRET' } },
      serviceBindings: { AUTH_GATEWAY: async () => new Response('gateway'), BACKUP: { name: 'backup', entrypoint: 'BackupIngest' }, BACKUP_STATUS: { name: 'backup', entrypoint: 'BackupStatus' } },
      durableObjects: { APP_VAULT: { className: 'AppVault', useSQLite: true }, EVENT_LEDGER: { className: 'EventLedger', useSQLite: true }, COMMIT_LEDGER: { className: 'CommitLedger', useSQLite: true } },
      r2Buckets: ['AUDIT_BUCKET', 'EVENTS'], d1Databases: ['AUDIT_DB', 'METRICS_DB'],
      outboundService: async request => { outbound.push(request.url); return kit.fetcher(request.url, { redirect: 'manual' }); } },
    { name: 'backup', modules: true, script: backupScript, compatibilityDate: '2026-10-05' },
  ] }));
  try {
    const db = await mf.getD1Database('METRICS_DB', 'ghcaretaker');
    for (const migration of ['0001_metrics.sql', '0002_reported_telemetry.sql']) {
      await db.exec((await readFile('migrations-observatory/' + migration, 'utf8')).replace(/--[^\n]*/g, '').replaceAll('\n', ' '));
    }
    const dash = async (path, token) => mf.dispatchFetch('https://caretaker.vespoli.me' + path, { redirect: 'manual', headers: token ? { 'cf-access-jwt-assertion': token } : {} });

    let r = await dash('/');
    assert.equal(r.status, 403); assert.equal(await r.text(), '');
    r = await dash('/api/actions', await kit.sign(kit.claims({ aud: ['c'.repeat(64)] })));
    assert.equal(r.status, 403); await r.arrayBuffer();
    const token = await kit.sign();
    r = await dash('/', token);
    assert.equal(r.status, 200); assert.match(r.headers.get('content-security-policy'), /default-src 'none'; style-src 'self'/);
    assert.match(await r.text(), /<title>Overview · caretaker<\/title>/);
    assert.deepEqual(outbound, [ACCESS_TEAM + '/cdn-cgi/access/certs'], 'only the Access certs were fetched');
    r = await mf.dispatchFetch('https://mcp.vespoli.me/actions', { redirect: 'manual' }); assert.equal(r.status, 404, 'dashboard paths do not exist on the MCP host'); await r.arrayBuffer();
    r = await mf.dispatchFetch('https://hooks.vespoli.me/', { redirect: 'manual' }); assert.equal(r.status, 404, 'nor on the hooks host'); await r.arrayBuffer();

    const key = randomSecret();
    await (await mf.getSecretsStoreSecretAPI('OBSERVATORY_WEBHOOK_SECRET', 'ghcaretaker'))().create(key);
    const payload = { action: 'completed', installation: { id: 7 }, repository: { id: 42, full_name: 'susanbeasles/demo', owner: { id: 215839550 } },
      workflow_job: { id: 777, run_id: 9001, run_attempt: 1, name: '<img src=x onerror=alert(1)>', workflow_name: 'pipeline', status: 'completed', conclusion: 'success',
        labels: ['ubuntu-24.04'], runner_group_name: 'GitHub Actions', created_at: '2026-10-15T11:50:06Z', started_at: '2026-10-15T11:50:20Z', completed_at: '2026-10-15T11:57:50Z', steps: [] } };
    const text = JSON.stringify(payload);
    r = await mf.dispatchFetch('https://hooks.vespoli.me/github', { method: 'POST', redirect: 'manual', body: text,
      headers: { 'content-type': 'application/json', 'x-github-event': 'workflow_job', 'x-github-delivery': crypto.randomUUID(), 'x-hub-signature-256': await sign(key, text) } });
    assert.equal(r.status, 202); await r.arrayBuffer();
    const job = await waitFor(async () => (await db.prepare('SELECT job_id, status, telemetry FROM jobs').first()));
    assert.deepEqual(job, { job_id: 777, status: 'completed', telemetry: null });
    assert.ok(await waitFor(async () => (await db.prepare('SELECT COUNT(*) AS n FROM deliveries_seen').first('n')) === 1));

    const actions = await (await dash('/api/actions', token)).json();
    assert.equal(actions.total.jobs.value, 1); assert.equal(actions.by_job[0].job, '<img src=x onerror=alert(1)>');
    const page = await (await dash('/actions', token)).text();
    assert.ok(!page.includes('<img src=x'), 'hostile job name escaped'); assert.ok(page.includes('&lt;img src=x onerror=alert(1)&gt;'));
    const overview = await (await dash('/api/overview', token)).json();
    assert.deepEqual(overview.backup, { available: true, summary: { last_success_at: '2026-10-15T03:20:00Z', note: '<b>hi</b>' } });
    assert.ok(!(await (await dash('/', token)).text()).includes('<b>hi</b>'));
    r = await dash('/style.css', token); assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /text\/css/); await r.arrayBuffer();
  } finally { await mf.dispose(); }
});
