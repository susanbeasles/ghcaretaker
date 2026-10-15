// Regression tests for two suspected defects from code review (owner acceptance item 8).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CommitLedgerCore } from '../src/commit-ledger-core.mjs';
import { sqlStorage, memoryR2, secret, clock, sha } from './fakes.mjs';

const REPO = 42;
function details(n) {
  return { sha: sha(n), tree: sha(1000 + n), parents: [sha(n - 1)], author_name: 'Author', author_date: '2026-10-15T11:00:00Z', committer_name: 'GitHub',
    committer_date: '2026-10-15T11:00:00Z', message_sha256: 'c'.repeat(64), verified: true, verification_reason: 'valid' };
}
function setup() {
  const now = clock(), storage = sqlStorage(), EVENTS = memoryR2();
  const core = new CommitLedgerCore(storage, { EVENTS, ALERT_WEBHOOK_URL: secret('https://alerts.invalid/caretaker') }, {
    now,
    fetcher: async () => new Response(null, { status: 204 }),
    mintToken: async () => ({ token: 'token-for-tests', expires_at: now() + 3_600_000 }),
    commitDetails: async (_f, s) => details([...Array(200).keys()].find(i => sha(i) === s)),
    hasPromotionTag: async () => true,
  });
  return { core, storage, now };
}
const push = (o = {}) => ({ type: 'push', repo_id: REPO, full_name: 'susanbeasles/demo', installation_id: 7, delivery_id: '7b1c2a7e-0000-4000-8000-000000000001',
  ref: 'refs/heads/feature', before: sha(1), after: sha(2), created: false, deleted: false, forced: false, pusher: 'susanbeasles', commits: [sha(2)], commits_truncated: false, ...o });

test('commit ledger: the same delivery ingested again after its inbox row was processed is not appended twice', async () => {
  const { core } = setup();
  await core.ingest(push());
  await core.alarm();
  const before = core.entries(50).items.length;
  const findingsBefore = core.findings().items.length;
  // The event ledger outbox is at-least-once: an ack lost after ingest() succeeded re-sends the same item.
  const again = await core.ingest(push());
  assert.equal(again.accepted, true, 'a duplicate is acknowledged (so the sender stops retrying)');
  await core.alarm();
  assert.equal(core.entries(50).items.length, before, 'no second ref_update / commit entries');
  assert.equal(core.findings().items.length, findingsBefore, 'no spurious ref_gap from re-applying an old push');
  assert.equal((await core.verify()).ok, true);
});
