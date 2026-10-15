// Configuration contract for the observatory additions: the dashboard host, Access vars, the metrics database,
// the backup status binding, and the OBSERVATORY_* credential names (old MCP-like names refused).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, config, RETIRED_OBSERVATORY_NAMES } from '../scripts/check-config.mjs';
import { OBSERVATORY_APP_PERMISSIONS, OBSERVATORY_APP_EVENTS, observatoryAppManifest } from '../src/github-app.mjs';
import { permissions as mcpPermissions } from '../src/policy.mjs';

const mutate = fn => { const c = config(); fn(c); return c; };

test('the checked-in configuration passes, including production', () => {
  assert.doesNotThrow(() => check(config()));
  assert.doesNotThrow(() => check(config(), true));
});

test('retired credential names are refused anywhere in the configuration', () => {
  for (const fn of [c => { c.vars.CARETAKER_APP_ID = ''; }, c => { c.secrets_store_secrets[0].binding = 'GITHUB_WEBHOOK_SECRET'; },
    c => { c.secrets_store_secrets[1].secret_name = 'GITHUB_WEBHOOK_SECRET_PREVIOUS'; }, c => { c.secrets_store_secrets[2].binding = 'CARETAKER_APP_KEY'; }]) {
    assert.throws(() => check(mutate(fn)), /Retired observatory credential name|Secrets Store binding required/);
  }
  for (const name of ['OBSERVATORY_WEBHOOK_SECRET', 'OBSERVATORY_WEBHOOK_SECRET_PREVIOUS', 'OBSERVATORY_APP_KEY']) {
    assert.throws(() => check(mutate(c => { c.secrets_store_secrets = c.secrets_store_secrets.filter(x => x.binding !== name); })), /Secrets Store binding required/);
    assert.throws(() => check(mutate(c => { c.vars[name] = 'x'; })), /plain var/);
  }
  assert.throws(() => check(mutate(c => { delete c.vars.OBSERVATORY_APP_ID; })), /OBSERVATORY_APP_ID/);
  assert.throws(() => check(mutate(c => { c.vars.OBSERVATORY_APP_ID = '1; drop'; })), /OBSERVATORY_APP_ID/);
  assert.ok(!RETIRED_OBSERVATORY_NAMES.test('OBSERVATORY_WEBHOOK_SECRET OBSERVATORY_APP_KEY OBSERVATORY_APP_ID'));
});

test('dashboard configuration is pinned: origin, route, Access team, AUD/email format, D1 and backup binding', () => {
  const bad = [
    c => { c.vars.DASHBOARD_ORIGIN = 'https://mcp.vespoli.me'; }, c => { c.vars.ACCESS_TEAM_DOMAIN = 'https://evil.cloudflareaccess.com'; },
    c => { c.vars.ACCESS_AUD = 'not-hex'; }, c => { c.vars.OWNER_EMAIL = 'two@a.test, three@b.test'; },
    c => { c.d1_databases[1].database_name = 'other'; }, c => { c.d1_databases[1].migrations_dir = 'migrations'; }, c => { c.d1_databases[1].database_id = 'xyz'; },
    c => { c.d1_databases.pop(); }, c => { c.services = c.services.filter(x => x.binding !== 'BACKUP_STATUS'); },
    c => { c.secrets_store_secrets.push({ binding: 'ACCESS_AUD', store_id: 'b6504fe2d5f64352954629bc7185fb79', secret_name: 'ACCESS_AUD' }); },
  ];
  for (const fn of bad) assert.throws(() => check(mutate(fn)), String(fn));
  for (const fn of [c => { c.routes = c.routes.filter(r => !r.pattern.startsWith('caretaker.')); }, c => { c.routes.push({ pattern: 'caretaker.vespoli.me/api/*', zone_name: 'vespoli.me' }); },
    c => { c.routes.find(r => r.pattern === 'caretaker.vespoli.me/*').pattern = 'caretaker.vespoli.me/'; }]) assert.throws(() => check(mutate(fn), true), String(fn));
  assert.doesNotThrow(() => check(mutate(c => { c.vars.ACCESS_AUD = 'f'.repeat(64); c.vars.OWNER_EMAIL = 'owner@example.org'; c.d1_databases[1].database_id = '01234567-89ab-cdef-0123-456789abcdef'; })));
});

test('observatory App: read-only, exactly the agreed events, separate from the MCP App', () => {
  assert.deepEqual(Object.keys(OBSERVATORY_APP_PERMISSIONS).sort(), ['actions', 'administration', 'checks', 'contents', 'deployments', 'metadata', 'packages', 'pull_requests', 'statuses']);
  assert.ok(Object.values(OBSERVATORY_APP_PERMISSIONS).every(v => v === 'read'));
  assert.deepEqual([...OBSERVATORY_APP_EVENTS].sort(), ['branch_protection_rule', 'check_suite', 'create', 'delete', 'deployment', 'deployment_status', 'package', 'pull_request',
    'pull_request_review', 'push', 'release', 'repository', 'repository_ruleset', 'status', 'workflow_job', 'workflow_run']);
  const m = observatoryAppManifest();
  assert.equal(m.hook_attributes.url, 'https://hooks.vespoli.me/github'); assert.equal(m.public, false);
  assert.notDeepEqual(m.default_permissions, mcpPermissions);
  assert.deepEqual(mcpPermissions, { contents: 'read', metadata: 'read', actions: 'read', issues: 'write', pull_requests: 'write' }, 'MCP App pin unchanged');
});
