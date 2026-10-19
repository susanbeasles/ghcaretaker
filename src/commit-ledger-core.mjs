// CommitLedger: one SQLite Durable Object per repository (idFromName(String(repo_id))).
// `push` events append a `ref_update` entry plus one `commit` entry per commit new to this ledger, hash chained,
// mirrored to R2 `commits/<repo_id>/<seq>.json`. Integrity findings (integrity.mjs) are stored and alerted.
// Work arrives through an inbox processed in order by the alarm, so GitHub API outages delay but never reorder
// or drop entries.
// Completeness (ADR-0003): a possibly truncated push is completed through the compare API (every commit carries its
// `source`); a push whose `before` is not the recorded head is a `ref_gap` and schedules a ref reconciliation against
// GitHub; a range that cannot be fetched is recorded as `incomplete_push` and retried through the outbox. The ledger
// is anchored externally (src/anchors.mjs) on the cron and every ANCHOR_EVERY entries.
import { GENESIS, canonical, link, verifyEntries, verifyRange, mutex } from './chain.mjs';
import { OUTBOX_SCHEMA, enqueue, drain, nextDue, pendingCounts, prune, backoff, ESCALATE_AT } from './outbox.mjs';
import { MAIN, refFindings, mainCommitFindings, mainCommits, promotionTagPrefix, PROMOTION_GRACE_MS, refGap, forcePushFinding, severityOf } from './integrity.mjs';
import { mintInstallationToken, commitDetails, promotionTagTarget, compareCommits, listMatchingRefs, COMPARE_BOUND_ERRORS, SHA } from './github-app.mjs';
import { deliverAlert, findingAlert } from './alerts.mjs';
import { CodedError, sha256Hex } from './bytes.mjs';
import { boundedLimit, optionalCursor } from './event-ledger-core.mjs';
import { ANCHOR_EVERY, ANCHOR_SCHEMA, anchorFindingDetail, sendBackupAnchor, verifyAnchors, writeAnchor } from './anchors.mjs';
import { log, errorCode } from './log.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ZERO_OR_SHA = v => typeof v === 'string' && (SHA.test(v) || /^0+$/.test(v));
const ZERO40 = '0'.repeat(40), isZero = v => /^0+$/.test(v), isBranch = ref => ref.startsWith('refs/heads/'), isTag = ref => ref.startsWith('refs/tags/');
const API_BUDGET = 40, RETRY_MS = 300_000, MIRROR_BATCH = 50, KEEP_DONE_MS = 30 * 86_400_000;
export const COMPARE_INLINE_ATTEMPTS = 3;  // transient compare failures retried in place before falling back to the outbox
export const REF_GRACE_MS = 10 * 60_000;   // refs updated more recently than this are left to their in-flight webhooks
export const CRON_TASKS = Object.freeze(['anchor', 'refs']);
export const commitMirrorKey = (repoId, seq) => `commits/${repoId}/${seq}.json`;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('ref_update', 'commit', 'reconcile')),
    delivery_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)`,
  "CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END",
  "CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END",
  'CREATE TABLE IF NOT EXISTS commits (sha TEXT PRIMARY KEY, seq INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS refs (ref TEXT PRIMARY KEY, sha TEXT NOT NULL, deleted INTEGER NOT NULL, seq INTEGER NOT NULL)',
  `CREATE TABLE IF NOT EXISTS inbox (id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error TEXT, queued_at INTEGER NOT NULL)`,
  // Every delivery the inbox has applied, written in the same transaction that removes its inbox row: the inbox is
  // transient, and the event ledger's outbox is at-least-once, so a re-sent delivery must be recognised forever.
  'CREATE TABLE IF NOT EXISTS applied_deliveries (delivery_id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS commit_details (sha TEXT PRIMARY KEY, details TEXT NOT NULL)',
  `CREATE TABLE IF NOT EXISTS promotions (sha TEXT PRIMARY KEY, entry_seq INTEGER, delivery_id TEXT NOT NULL, due_at INTEGER NOT NULL,
    next_check_at INTEGER NOT NULL, status TEXT NOT NULL CHECK (status IN ('pending', 'satisfied', 'flagged')),
    resolved_by TEXT, resolved_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)`,
  'CREATE TABLE IF NOT EXISTS promote_tags (tag TEXT PRIMARY KEY, prefix TEXT NOT NULL, delivery_id TEXT NOT NULL, seen_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS promote_tags_prefix ON promote_tags(prefix)',
  'CREATE TABLE IF NOT EXISTS verified_promote_tags (tag TEXT PRIMARY KEY, sha TEXT NOT NULL, actor_id INTEGER NOT NULL, delivery_id TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS verified_promote_tags_sha_actor ON verified_promote_tags(sha, actor_id)',
  'CREATE INDEX IF NOT EXISTS verified_promote_tags_sha_actor_tag ON verified_promote_tags(sha, actor_id, tag)',
  'CREATE TABLE IF NOT EXISTS promotion_check_progress (sha TEXT NOT NULL, actor_id INTEGER NOT NULL, last_tag TEXT NOT NULL, PRIMARY KEY (sha, actor_id))',
  `CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, ref TEXT, sha TEXT NOT NULL, entry_seq INTEGER,
    delivery_id TEXT NOT NULL, detail TEXT NOT NULL, detected_at TEXT NOT NULL, UNIQUE (kind, sha, delivery_id))`,
  'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  // Compare result of a truncated push, kept until the push is applied so an interrupted alarm does not refetch it.
  'CREATE TABLE IF NOT EXISTS push_compare (delivery_id TEXT PRIMARY KEY, result TEXT NOT NULL)',
  ...ANCHOR_SCHEMA,
  ...OUTBOX_SCHEMA,
];

const entryOf = (r, repoId) => ({ seq: r.seq, repo_id: repoId, kind: r.kind, delivery_id: r.delivery_id, recorded_at: r.recorded_at,
  data: JSON.parse(r.data), prev_hash: r.prev_hash, entry_hash: r.entry_hash });
const findingOf = r => ({ id: r.id, kind: r.kind, ref: r.ref, sha: r.sha, entry_seq: r.entry_seq, delivery_id: r.delivery_id, detail: JSON.parse(r.detail), detected_at: r.detected_at });

function validItem(item) {
  if (!item || !['push', 'create'].includes(item.type) || !Number.isSafeInteger(item.repo_id) || item.repo_id < 1 || !UUID.test(item.delivery_id ?? '')) return false;
  if (typeof item.ref !== 'string' || item.ref.length > 1024) return false;
  if (item.type === 'create') return ['tag', 'branch'].includes(item.ref_type);
  const optCount = v => v === undefined || v === null || (Number.isSafeInteger(v) && v >= 0);
  if (!optCount(item.size) || !optCount(item.distinct_size) || (item.truncated !== undefined && typeof item.truncated !== 'boolean')) return false;
  if (item.default_branch !== undefined && item.default_branch !== null && (typeof item.default_branch !== 'string' || item.default_branch.length > 255)) return false;
  return ZERO_OR_SHA(item.before) && ZERO_OR_SHA(item.after) && Array.isArray(item.commits) && item.commits.every(s => SHA.test(s));
}

const union = (...lists) => [...new Set(lists.flat())];

export class CommitLedgerCore {
  constructor(storage, env, deps = {}) {
    this.storage = storage; this.sql = storage.sql; this.env = env; this.deps = deps;
    this.now = deps.now || Date.now; this.fetcher = deps.fetcher || fetch; this.lock = mutex(); this.cachedToken = null;
    for (const statement of SCHEMA) this.sql.exec(statement);
    this.storage.transactionSync(() => {
      const marker = 'migration:exact-promotion-evidence:v1';
      if (this.meta(marker) !== null) return;
      // Legacy create_event and api resolutions both accepted prefix-only evidence.
      // Recheck every pre-marker satisfied row; never infer trust from resolved_by.
      // Keep the append-only ledger, findings, and original grace deadline intact.
      this.sql.exec("DELETE FROM promotion_check_progress WHERE sha IN (SELECT sha FROM promotions WHERE status = 'satisfied')");
      this.sql.exec("UPDATE promotions SET status = 'pending', resolved_by = NULL, resolved_at = NULL, attempts = 0, last_error = NULL, next_check_at = ? WHERE status = 'satisfied'", this.now());
      this.setMeta(marker, this.iso(this.now()));
    });
  }

  // Awaited by the Durable Object initialization gate, including after an alarm-write
  // failure: the migration marker does not imply pending work has been scheduled.
  async initialize() { await this.schedule({ api: API_BUDGET }); }

  meta(key) { return this.sql.exec('SELECT value FROM meta WHERE key = ?', key).toArray()[0]?.value ?? null; }
  setMeta(key, value) { this.sql.exec('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, String(value)); }
  repoId() { const v = this.meta('repo_id'); return v === null ? null : Number(v); }
  headRow() { return this.sql.exec('SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1').toArray()[0] ?? null; }
  iso(ms) { return new Date(ms).toISOString(); }

  async wake(at) {
    const current = await this.storage.getAlarm();
    if (current === null || current === undefined || current > at) await this.storage.setAlarm(at);
  }

  // Called by the event ledger outbox. Idempotent on delivery_id.
  async ingest(item) {
    if (!validItem(item)) throw new CodedError('bad_request');
    const repo = this.repoId();
    if (repo !== null && repo !== item.repo_id) throw new CodedError('repo_mismatch');
    const now = this.now();
    this.storage.transactionSync(() => {
      if (repo === null) this.setMeta('repo_id', item.repo_id);
      if (typeof item.full_name === 'string') this.setMeta('full_name', item.full_name);
      if (Number.isSafeInteger(item.installation_id)) this.setMeta('installation_id', item.installation_id);
      if (this.sql.exec('SELECT 1 FROM applied_deliveries WHERE delivery_id = ?', item.delivery_id).toArray().length) return;
      this.sql.exec('INSERT INTO inbox (delivery_id, payload, next_attempt_at, queued_at) VALUES (?, ?, ?, ?) ON CONFLICT(delivery_id) DO NOTHING',
        item.delivery_id, JSON.stringify(item), now, now);
    });
    await this.wake(now);
    return { accepted: true };
  }

  async token(budget = null) {
    const now = this.now();
    if (this.cachedToken && this.cachedToken.expires_at - now > 300_000) return this.cachedToken.token;
    if (budget) {
      if (budget.api <= 0) throw new CodedError('deferred');
      budget.api--;
    }
    const installation = Number(this.meta('installation_id'));
    this.cachedToken = await (this.deps.mintToken ?? mintInstallationToken)(this.env, installation, this.repoId(), this.fetcher);
    return this.cachedToken.token;
  }

  async alarm() {
    const budget = { api: API_BUDGET };
    await this.processInbox(budget);
    await this.checkPromotions(budget);
    await this.reconcileRefsIfDue(budget);
    await this.anchorIfDue();
    await this.mirror();
    await drain(this.sql, {
      alert: p => deliverAlert(this.env, p, this.fetcher),
      backfill: p => this.backfill(p, budget),
      anchor_backup: p => sendBackupAnchor(this.env, p),
    }, { now: this.now, source: 'commit_ledger' });
    prune(this.sql, this.now() - KEEP_DONE_MS);
    await this.schedule(budget);
  }

  async schedule(budget) {
    const now = this.now(), times = [];
    const inbox = this.sql.exec('SELECT next_attempt_at FROM inbox ORDER BY id LIMIT 1').toArray()[0];
    if (inbox) times.push(budget.api <= 0 ? now : inbox.next_attempt_at);
    const promo = this.sql.exec("SELECT MIN(MAX(due_at, next_check_at)) AS t FROM promotions WHERE status = 'pending'").toArray()[0]?.t;
    if (promo !== null && promo !== undefined) times.push(promo);
    const due = nextDue(this.sql); if (due !== null) times.push(due);
    const head = this.headRow(), mirrored = Number(this.meta('mirrored_through') ?? 0);
    if (head && head.seq > mirrored) times.push(Number(this.meta('mirror_retry_at') ?? now));
    // Ref reconciliation waits for an empty inbox (pending deliveries may explain a difference).
    const refs = this.meta('refs_reconcile_due_at');
    if (refs !== null && !inbox) times.push(budget.api <= 0 ? now : Number(refs));
    const anchor = this.meta('anchor_due_at'); if (anchor !== null) times.push(Number(anchor));
    if (times.length) await this.storage.setAlarm(Math.max(Math.min(...times), now + 1000));
  }

  // ---- Inbox: strictly in arrival order; a failing head item blocks later ones (ordering is part of the ledger). ----
  async processInbox(budget) {
    for (;;) {
      const row = this.sql.exec('SELECT * FROM inbox ORDER BY id LIMIT 1').toArray()[0];
      if (!row || row.next_attempt_at > this.now()) return;
      const item = JSON.parse(row.payload);
      try {
        if (item.type === 'create') { await this.applyCreate(row, item, budget); continue; }
        const plan = await this.pushPlan(row, item, budget);
        if (!plan || !await this.fetchDetails(item, plan.shas, budget)) return;
        await this.applyPush(row, item, plan);
      } catch (error) {
        if (error?.code === 'deferred') return; // API budget spent mid-request: resume next run, not a failure
        const attempts = row.attempts + 1, code = errorCode(error), now = this.now();
        this.sql.exec('UPDATE inbox SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE id = ?', attempts, now + backoff(attempts), code, row.id);
        log('warning', 'commit_ledger_inbox_retry', { repo_id: item.repo_id, delivery_id: item.delivery_id, attempts, error: code });
        if (attempts === ESCALATE_AT) this.operationalAlert('commit_ledger_stalled', 'inbox:' + item.delivery_id, { delivery_id: item.delivery_id, attempts, last_error: code });
        return;
      }
    }
  }

  knownDetails(sha) {
    const pending = this.sql.exec('SELECT details FROM commit_details WHERE sha = ?', sha).toArray()[0];
    if (pending) return JSON.parse(pending.details);
    const known = this.sql.exec('SELECT e.data FROM commits c JOIN entries e ON e.seq = c.seq WHERE c.sha = ?', sha).toArray()[0];
    return known ? JSON.parse(known.data) : null;
  }

  shasFor(item) { return [...new Set([...item.commits, ...mainCommits(item)])]; }

  storeDetails(list) {
    for (const d of list) this.sql.exec('INSERT INTO commit_details (sha, details) VALUES (?, ?) ON CONFLICT(sha) DO NOTHING', d.sha, JSON.stringify(d));
  }

  compare(base, head, budget) {
    return this.token().then(token => (this.deps.compareCommits ?? compareCommits)(this.meta('full_name'), base, head, token, this.fetcher, budget));
  }

  // Which commits this push brought, and where each was learned. Not truncated: the payload's list (source
  // `webhook`). Possibly truncated: the whole range from GET /compare (commits only found there: `api_compare`).
  // When the range cannot be fetched, the listed commits are recorded with complete: false, an incomplete_push
  // finding is raised; only transient failures enqueue a bounded backfill. Returns null when the API budget ran out.
  async pushPlan(row, item, budget) {
    const listed = union(item.commits), tip = mainCommits(item).filter(s => !listed.includes(s));
    const sources = new Map([...listed, ...tip].map(s => [s, 'webhook']));
    const plain = { shas: union(listed, tip), sources, complete: true, compare: null, incomplete: null };
    if (!item.truncated || item.deleted) return plain;
    const partial = (reason, retry, base = null) => ({ ...plain, complete: false, incomplete: { reason, retry, base } });
    if (!isBranch(item.ref)) return partial('not_a_branch', false);
    const base = item.created ? item.default_branch ?? null : item.before;
    if (!base || (item.created && item.ref === 'refs/heads/' + item.default_branch)) return partial('no_compare_base', false);
    let result = JSON.parse(this.sql.exec('SELECT result FROM push_compare WHERE delivery_id = ?', item.delivery_id).toArray()[0]?.result ?? 'null');
    if (!result) {
      try {
        const cmp = await this.compare(base, item.after, budget);
        this.storeDetails(cmp.commits);
        result = { ok: true, status: cmp.status, total_commits: cmp.total_commits, shas: cmp.commits.map(c => c.sha) };
      } catch (error) {
        if (error?.code === 'deferred') return null;
        const code = errorCode(error);
        if (!COMPARE_BOUND_ERRORS.has(code) && row.attempts + 1 < COMPARE_INLINE_ATTEMPTS) throw error;
        result = { ok: false, reason: code };
      }
      this.sql.exec('INSERT INTO push_compare (delivery_id, result) VALUES (?, ?) ON CONFLICT(delivery_id) DO NOTHING', item.delivery_id, JSON.stringify(result));
    }
    if (!result.ok) return partial(result.reason, !COMPARE_BOUND_ERRORS.has(result.reason), base);
    const shas = union(result.shas, listed, tip);
    for (const s of shas) if (!sources.has(s)) sources.set(s, 'api_compare');
    return { shas, sources, complete: true, compare: { status: result.status, total_commits: result.total_commits }, incomplete: null };
  }

  // Returns false when the API budget for this alarm run is spent (resumes on the next run).
  async fetchDetails(item, shas, budget) {
    const fullName = item.full_name ?? this.meta('full_name');
    for (const sha of shas) {
      if (this.knownDetails(sha)) continue;
      if (budget.api <= 0) return false;
      budget.api--;
      const details = await (this.deps.commitDetails ?? commitDetails)(fullName, sha, await this.token(), this.fetcher);
      this.sql.exec('INSERT INTO commit_details (sha, details) VALUES (?, ?) ON CONFLICT(sha) DO NOTHING', sha, JSON.stringify(details));
    }
    return true;
  }

  // Links `bodies` after the head and inserts them in one transaction with `inTx(entries)`. Caller holds the lock.
  async append(bodies, inTx) {
    const head = this.headRow(), entries = await link(head, bodies);
    this.storage.transactionSync(() => {
      if ((this.headRow()?.seq ?? 0) !== (head?.seq ?? 0)) throw new CodedError('head_moved');
      for (const e of entries) {
        this.sql.exec('INSERT INTO entries (seq, kind, delivery_id, recorded_at, data, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
          e.seq, e.kind, e.delivery_id, e.recorded_at, canonical(e.data), e.prev_hash, e.entry_hash);
        if (e.kind === 'commit') this.sql.exec('INSERT INTO commits (sha, seq) VALUES (?, ?)', e.data.sha, e.seq);
      }
      inTx(entries);
      if (this.anchorBacklog() >= ANCHOR_EVERY && !this.meta('anchor_blocked') && this.meta('anchor_due_at') === null) this.setMeta('anchor_due_at', this.now());
    });
    return entries;
  }

  // Commit bodies for the shas not yet in this ledger, in order. Returns {bodies, fresh}.
  commitBodies(shas, ref, sourceOf, delivery_id, recorded_at, detailsOf = sha => this.knownDetails(sha)) {
    const bodies = [], fresh = [];
    for (const sha of shas) {
      if (this.sql.exec('SELECT 1 FROM commits WHERE sha = ?', sha).toArray().length) continue;
      fresh.push(sha);
      bodies.push({ repo_id: this.repoId(), kind: 'commit', delivery_id, recorded_at, data: { ...detailsOf(sha), sha, ref, source: sourceOf(sha) } });
    }
    return { bodies, fresh };
  }

  // Main-branch rules and promotion checks for commits that reached main (inside a transaction).
  judgeMain(shas, detailsOf, seqOf, delivery_id, now) {
    for (const sha of shas) {
      for (const f of mainCommitFindings({ ...detailsOf(sha), sha })) this.recordFinding({ ...f, entry_seq: seqOf(sha), delivery_id }, now);
      const tagged = this.sql.exec('SELECT tag FROM verified_promote_tags WHERE sha = ? AND actor_id = ? LIMIT 1', sha, this.promoterId()).toArray()[0];
      this.sql.exec('INSERT INTO promotions (sha, entry_seq, delivery_id, due_at, next_check_at, status, resolved_by, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sha) DO NOTHING',
        sha, seqOf(sha), delivery_id, now + PROMOTION_GRACE_MS, now + PROMOTION_GRACE_MS,
        tagged ? 'satisfied' : 'pending', tagged ? 'create_event:' + tagged.tag : null, tagged ? this.iso(now) : null);
    }
  }

  setRef(ref, sha, deleted, seq) {
    this.sql.exec('INSERT INTO refs (ref, sha, deleted, seq) VALUES (?, ?, ?, ?) ON CONFLICT(ref) DO UPDATE SET sha = excluded.sha, deleted = excluded.deleted, seq = excluded.seq',
      ref, sha, deleted ? 1 : 0, seq);
  }

  scheduleRefReconcile(at) {
    const current = this.meta('refs_reconcile_due_at');
    if (current === null || Number(current) > at) this.setMeta('refs_reconcile_due_at', at);
  }

  applyPush(row, item, plan) {
    return this.lock(async () => {
      const now = this.now(), recorded_at = this.iso(now);
      const recorded = this.sql.exec('SELECT sha, deleted FROM refs WHERE ref = ?', item.ref).toArray()[0] ?? null;
      const previous = recorded?.sha ?? null, gap = refGap(recorded, item);
      const update = { ref: item.ref, before: item.before, after: item.after, created: item.created, deleted: item.deleted, forced: item.forced, pusher: item.pusher ?? null, delivery_id: item.delivery_id,
        size: item.size ?? null, listed: item.commits.length, truncated: item.truncated === true, complete: plan.complete, gap: gap !== null };
      const { bodies, fresh } = this.commitBodies(plan.shas, item.ref, sha => plan.sources.get(sha) ?? 'webhook', item.delivery_id, recorded_at);
      bodies.unshift({ repo_id: this.repoId(), kind: 'ref_update', delivery_id: item.delivery_id, recorded_at, data: update });
      const onMain = item.ref === MAIN && !item.deleted ? plan.shas : [];
      let findings = [];
      await this.append(bodies, entries => {
        const refSeq = entries[0].seq, seqOf = new Map(fresh.map((sha, i) => [sha, entries[i + 1].seq]));
        const existingSeq = sha => seqOf.get(sha) ?? this.sql.exec('SELECT seq FROM commits WHERE sha = ?', sha).toArray()[0]?.seq ?? null;
        findings = [...refFindings(update, previous), ...forcePushFinding(update)];
        if (gap) findings.push({ kind: 'ref_gap', ref: item.ref, sha: item.after, detail: { ...gap, before: item.before, after: item.after } });
        if (plan.incomplete) findings.push({ kind: 'incomplete_push', ref: item.ref, sha: item.after, detail: { reason: plan.incomplete.reason, before: item.before, after: item.after, listed: item.commits.length, size: item.size ?? null, retrying: plan.incomplete.retry } });
        for (const f of findings) this.recordFinding({ ...f, entry_seq: refSeq, delivery_id: item.delivery_id }, now);
        this.setRef(item.ref, item.deleted ? item.before : item.after, item.deleted, refSeq);
        this.judgeMain(onMain, sha => this.knownDetails(sha), existingSeq, item.delivery_id, now);
        // A gap is settled against GitHub's refs once in-flight deliveries had time to arrive, and the range between
        // the recorded head and this push's `before` (a missed push, or nothing for a late one) is backfilled.
        if (gap) this.scheduleRefReconcile(now + REF_GRACE_MS);
        if (gap?.recorded_head && !isZero(item.before) && isBranch(item.ref)) enqueue(this.sql, { kind: 'backfill', dedupe_key: 'gap:' + item.delivery_id, payload: {
          ref: item.ref, base: gap.recorded_head, head: item.before, delivery_id: item.delivery_id, reason: 'ref_gap' } }, now);
        if (plan.incomplete?.retry) enqueue(this.sql, { kind: 'backfill', dedupe_key: 'backfill:' + item.delivery_id, payload: {
          ref: item.ref, base: plan.incomplete.base, head: item.after, delivery_id: item.delivery_id, reason: 'push_backfill' } }, now);
        this.sql.exec('DELETE FROM inbox WHERE id = ?', row.id);
        this.markApplied(item.delivery_id, now);
        this.sql.exec('DELETE FROM push_compare WHERE delivery_id = ?', item.delivery_id);
        for (const sha of plan.shas) this.sql.exec('DELETE FROM commit_details WHERE sha = ?', sha);
      });
      if (item.commits_truncated) log('warning', 'push_commits_truncated', { repo_id: this.repoId(), delivery_id: item.delivery_id, complete: plan.complete });
      if (findings.length) log('warning', 'integrity_findings', { repo_id: this.repoId(), delivery_id: item.delivery_id, kinds: findings.map(f => f.kind) });
    });
  }

  // Outbox `backfill`: the commit range of a push (or a reconciled ref move) that could not be fetched before. Throws
  // to be retried with bounded backoff; terminal failures remain explicitly incomplete.
  async backfill(p, budget) {
    if (!p || typeof p.ref !== 'string' || !SHA.test(p.head ?? '') || typeof p.base !== 'string' || typeof p.delivery_id !== 'string') throw new CodedError('bad_backfill');
    const cmp = await this.compare(p.base, p.head, budget);
    const details = new Map(cmp.commits.map(c => [c.sha, c])), shas = cmp.commits.map(c => c.sha);
    await this.lock(async () => {
      const now = this.now(), recorded_at = this.iso(now);
      const { bodies, fresh } = this.commitBodies(shas, p.ref, () => 'api_compare', p.delivery_id, recorded_at, sha => details.get(sha));
      bodies.unshift({ repo_id: this.repoId(), kind: 'reconcile', delivery_id: p.delivery_id, recorded_at, data: {
        ref: p.ref, reason: p.reason ?? 'push_backfill', from: p.base, to: p.head, deleted: false, compare_status: cmp.status, commits: fresh.length, complete: true, delivery_id: p.delivery_id } });
      await this.append(bodies, entries => {
        const seqOf = new Map(fresh.map((sha, i) => [sha, entries[i + 1].seq]));
        const existingSeq = sha => seqOf.get(sha) ?? this.sql.exec('SELECT seq FROM commits WHERE sha = ?', sha).toArray()[0]?.seq ?? null;
        if (p.ref === MAIN) this.judgeMain(shas, sha => details.get(sha), existingSeq, p.delivery_id, now);
      });
      log('info', 'commit_range_backfilled', { repo_id: this.repoId(), delivery_id: p.delivery_id, commits: fresh.length });
    });
  }

  // No configured promoter identity means no promotion evidence is trusted.
  promoterId() {
    const id = Number(this.env.PROMOTER_ACTOR_ID);
    return Number.isSafeInteger(id) && id > 0 ? id : 0;
  }

  async applyCreate(row, item, budget) {
    const prefix = item.ref_type === 'tag' ? promotionTagPrefix(item.ref) : null, at = this.iso(this.now());
    let target = null, unavailable = null;
    if (prefix && this.promoterId() && item.actor_id === this.promoterId()) {
      try {
        target = await (this.deps.promotionTagTarget ?? promotionTagTarget)(this.meta('full_name'), item.ref, await this.token(budget), this.fetcher, budget);
      } catch (error) {
        if (error?.code === 'deferred') throw error;
        if (![404, 422].includes(error?.status) && row.attempts + 1 < 12 && this.now() - row.queued_at < 24 * 60 * 60_000) throw error;
        unavailable = errorCode(error);
      }
      if (!SHA.test(target ?? '') || !target.startsWith(prefix)) target = null;
    }
    this.storage.transactionSync(() => {
      if (target) {
        this.sql.exec('INSERT INTO verified_promote_tags (tag, sha, actor_id, delivery_id) VALUES (?, ?, ?, ?) ON CONFLICT(tag) DO NOTHING', item.ref, target, item.actor_id, item.delivery_id);
        this.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = ?, resolved_at = ? WHERE status = 'pending' AND sha = ?",
          'verified_create:' + item.ref, at, target);
        this.sql.exec('DELETE FROM promotion_check_progress WHERE sha = ?', target);
      }
      if (unavailable) this.operationalAlert('promotion_evidence_unavailable', 'promotion-create:' + item.delivery_id, { ref: item.ref, error: unavailable });
      this.sql.exec('DELETE FROM inbox WHERE id = ?', row.id);
      this.markApplied(item.delivery_id, this.now());
    });
  }

  markApplied(deliveryId, now) {
    this.sql.exec('INSERT INTO applied_deliveries (delivery_id, applied_at) VALUES (?, ?) ON CONFLICT(delivery_id) DO NOTHING', deliveryId, now);
  }

  recordFinding(f, now) {
    const detected_at = this.iso(now);
    const row = this.sql.exec('INSERT INTO findings (kind, ref, sha, entry_seq, delivery_id, detail, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING id',
      f.kind, f.ref ?? null, f.sha, f.entry_seq ?? null, f.delivery_id, JSON.stringify(f.detail ?? {}), detected_at).toArray()[0];
    if (!row) return;
    if (severityOf(f.kind) === 'critical') log('critical', 'ledger_finding', { ledger: 'commit', repo_id: this.repoId(), kind: f.kind, finding_id: row.id });
    const repo = { repo_id: this.repoId(), full_name: this.meta('full_name') };
    enqueue(this.sql, { kind: 'alert', dedupe_key: 'finding:' + this.repoId() + ':' + row.id, payload: findingAlert({ ...f, id: row.id, detected_at }, repo) }, now);
  }

  operationalAlert(code, key, detail) {
    const now = this.now();
    enqueue(this.sql, { kind: 'alert', dedupe_key: code + ':' + this.repoId() + ':' + key, payload: {
      schema: 'ghcaretaker-alert/v1', type: 'operational', code, repo_id: this.repoId(), repo: this.meta('full_name'), ...detail, detected_at: this.iso(now),
    } }, now);
  }

  // ---- Cron (src/cron.mjs): flagged due, run by the alarm ----
  async requestCron(tasks) {
    if (!Array.isArray(tasks) || tasks.some(t => !CRON_TASKS.includes(t))) throw new CodedError('bad_request');
    if (this.repoId() === null) return { accepted: false, reason: 'empty_ledger' };
    const now = this.now();
    if (tasks.includes('anchor')) this.setMeta('anchor_due_at', now);
    if (tasks.includes('refs')) this.scheduleRefReconcile(now);
    await this.wake(now);
    return { accepted: true, tasks };
  }

  // ---- Ref reconciliation against GitHub (cron, and REF_GRACE_MS after a ref_gap) ----
  async reconcileRefsIfDue(budget) {
    const due = this.meta('refs_reconcile_due_at'), now = this.now();
    if (due === null || Number(due) > now) return;
    if (this.sql.exec('SELECT 1 FROM inbox LIMIT 1').toArray().length) return; // pending deliveries first
    if (!this.meta('full_name') || !Number(this.meta('installation_id'))) {
      this.sql.exec("DELETE FROM meta WHERE key = 'refs_reconcile_due_at'");
      this.setMeta('refs_last_run', JSON.stringify({ at: this.iso(now), ok: false, error: 'repo_unknown' }));
      return;
    }
    try {
      const stats = await this.reconcileRefs(budget);
      this.sql.exec("DELETE FROM meta WHERE key IN ('refs_reconcile_due_at', 'refs_reconcile_attempts')");
      this.setMeta('refs_last_run', JSON.stringify({ at: this.iso(now), ok: true, ...stats }));
    } catch (error) {
      if (error?.code === 'deferred') return; // budget spent: refs already settled stay settled; the rest next run
      const code = errorCode(error), attempts = Number(this.meta('refs_reconcile_attempts') ?? 0) + 1;
      this.setMeta('refs_reconcile_attempts', attempts);
      this.setMeta('refs_reconcile_due_at', now + Math.max(RETRY_MS, backoff(attempts)));
      this.setMeta('refs_last_run', JSON.stringify({ at: this.iso(now), ok: false, error: code, attempts }));
      log('warning', 'ref_reconcile_retry', { repo_id: this.repoId(), attempts, error: code });
      if (attempts === ESCALATE_AT) this.operationalAlert('ref_reconcile_failing', 'refs', { attempts, last_error: code });
    }
  }

  // Lists heads and tags (contents:read), compares each with this ledger's recorded head and settles every
  // difference with a `reconcile` entry. Fast-forwards are backfilled through compare; anything the ledger cannot
  // explain (an unobserved deletion, creation, tag move or history rewrite) is a `ref_drift` finding, plus the
  // ref rules (main_deleted, main_forced_update, tag_moved, ...) applied to the synthetic update.
  async reconcileRefs(budget) {
    const token = await this.token(), full = this.meta('full_name'), list = this.deps.listRefs ?? listMatchingRefs;
    const heads = await list(full, 'heads', token, this.fetcher, budget), tags = await list(full, 'tags', token, this.fetcher, budget);
    const live = new Map([...heads.refs, ...tags.refs]), complete = heads.complete && tags.complete;
    const baselined = this.meta('refs_baselined') === '1', now = this.now(), runId = crypto.randomUUID();
    const stats = { refs_live: live.size, listing_complete: complete, in_sync: 0, baseline: 0, backfilled: 0, drift: 0, incomplete: 0, deferred_recent: 0 };
    const recorded = new Map(this.sql.exec('SELECT r.ref, r.sha, r.deleted, e.recorded_at FROM refs r JOIN entries e ON e.seq = r.seq').toArray().map(r => [r.ref, r]));
    for (const ref of union([...recorded.keys()], [...live.keys()])) {
      const row = recorded.get(ref) ?? null, liveSha = live.get(ref) ?? null;
      const ledgerSha = row && !row.deleted ? row.sha : null;
      if (ledgerSha === liveSha) { stats.in_sync++; continue; }
      if (row && Date.parse(row.recorded_at) > now - REF_GRACE_MS) { stats.deferred_recent++; continue; }
      if (liveSha === null && !complete) continue; // absent from a capped listing proves nothing
      await this.settleRef(ref, ledgerSha, liveSha, { baseline: !row && !baselined, previous: row?.sha ?? null, runId, budget, stats });
    }
    if (complete) this.setMeta('refs_baselined', '1');
    return stats;
  }

  async settleRef(ref, from, to, { baseline, previous, runId, budget, stats }) {
    const delivery_id = 'reconcile:' + runId;
    const entry = (data, commits = [], extra = []) => ({ data: { ref, from, to, deleted: to === null, compare_status: null, commits: 0, complete: true, delivery_id: null, ...data }, commits, extra });
    let plan;
    // First observation of a ref that predates this ledger: its history before `to` is not recorded (complete: false).
    if (baseline) { plan = entry({ reason: 'baseline', complete: false }); stats.baseline++; }
    else if (to === null || from === null || isTag(ref)) {
      // Unobserved deletion or creation, or a tag that now points elsewhere: nothing to compare, nothing to explain it.
      const update = { ref, before: from ?? ZERO40, after: to ?? ZERO40, created: from === null, deleted: to === null, forced: false };
      const reason = to === null ? 'deleted_unobserved' : from === null ? 'created_unobserved' : 'tag_target_changed';
      plan = entry({ reason: 'ref_reconcile', complete: !(from === null && isBranch(ref)) }, [], [{ kind: 'ref_drift', sha: to ?? from, detail: { reason, ledger_head: from, github_head: to } }, ...refFindings(update, previous)]);
      stats.drift++;
    } else {
      let cmp = null, failure = null;
      try { cmp = await this.compare(from, to, budget); }
      catch (error) {
        if (error?.code === 'deferred') throw error;
        failure = errorCode(error);
        if (!COMPARE_BOUND_ERRORS.has(failure) && error?.status !== 404 && error?.status !== 422) throw error; // transient: retry the run
      }
      if (failure) {
        const bounded = COMPARE_BOUND_ERRORS.has(failure);
        plan = entry({ reason: 'ref_reconcile', complete: false }, [], [bounded
          ? { kind: 'incomplete_push', sha: to, detail: { reason: failure, before: from, after: to, source: 'ref_reconcile', retrying: false } }
          : { kind: 'ref_drift', sha: to, detail: { reason: 'compare_unavailable', ledger_head: from, github_head: to, error: failure } }]);
        plan.backfill = false;
        stats[bounded ? 'incomplete' : 'drift']++;
      } else if (cmp.status === 'ahead' || cmp.status === 'identical') {
        plan = entry({ reason: 'ref_reconcile', compare_status: cmp.status }, cmp.commits);
        stats.backfilled++;
      } else {
        // behind or diverged: history was rewritten without a push this ledger saw.
        const update = { ref, before: from, after: to, created: false, deleted: false, forced: true };
        plan = entry({ reason: 'ref_reconcile', compare_status: cmp.status }, cmp.commits, [
          { kind: 'ref_drift', sha: to, detail: { reason: 'history_rewritten', ledger_head: from, github_head: to, compare_status: cmp.status, merge_base: cmp.merge_base } },
          ...refFindings(update, from), ...forcePushFinding(update)]);
        stats.drift++;
      }
    }
    await this.lock(async () => {
      const now = this.now(), recorded_at = this.iso(now), details = new Map(plan.commits.map(c => [c.sha, c])), shas = plan.commits.map(c => c.sha);
      const { bodies, fresh } = this.commitBodies(shas, ref, () => 'api_compare', delivery_id, recorded_at, sha => details.get(sha));
      bodies.unshift({ repo_id: this.repoId(), kind: 'reconcile', delivery_id, recorded_at, data: { ...plan.data, commits: fresh.length } });
      await this.append(bodies, entries => {
        const seq = entries[0].seq, seqOf = new Map(fresh.map((sha, i) => [sha, entries[i + 1].seq]));
        const existingSeq = sha => seqOf.get(sha) ?? this.sql.exec('SELECT seq FROM commits WHERE sha = ?', sha).toArray()[0]?.seq ?? null;
        // ref_drift dedupes per ref and head; the rule findings per reconciliation run.
        for (const f of plan.extra) this.recordFinding({ ...f, ref, entry_seq: seq, delivery_id: f.kind === 'ref_drift' ? 'ref_reconcile:' + ref : delivery_id }, now);
        this.setRef(ref, to ?? from, to === null, seq);
        if (ref === MAIN && to !== null) this.judgeMain(shas, sha => details.get(sha), existingSeq, delivery_id, now);
        if (plan.backfill) enqueue(this.sql, { kind: 'backfill', dedupe_key: 'backfill:' + delivery_id + ':' + ref, payload: { ref, base: from, head: to, delivery_id, reason: 'ref_reconcile' } }, now);
      });
    });
    if (plan.extra.length) log('warning', 'ref_reconciled', { repo_id: this.repoId(), reason: plan.data.reason, kinds: plan.extra.map(f => f.kind) });
  }

  // ---- External anchors (src/anchors.mjs) ----
  anchorAdapter() {
    const sql = this.sql, one = (q, ...b) => sql.exec(q, ...b).toArray()[0], repoId = this.repoId();
    return {
      ledger: 'commit-' + repoId,
      headRow: () => this.headRow(),
      count: () => one('SELECT COUNT(*) AS n FROM entries').n,
      countThrough: seq => one('SELECT COUNT(*) AS n FROM entries WHERE seq <= ?', seq).n,
      entryAt: seq => { const r = one('SELECT * FROM entries WHERE seq = ?', seq); return r ? entryOf(r, repoId) : null; },
      entriesBetween: (a, b) => sql.exec('SELECT * FROM entries WHERE seq BETWEEN ? AND ? ORDER BY seq', a, b).toArray().map(r => entryOf(r, repoId)),
      localLatest: () => one('SELECT * FROM anchors ORDER BY seq DESC LIMIT 1') ?? null,
      recordLocal: a => sql.exec('INSERT INTO anchors (seq, object_key, anchor_hash, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(seq) DO NOTHING', a.seq, a.object_key, a.anchor_hash, a.created_at),
      meta: k => this.meta(k), setMeta: (k, v) => this.setMeta(k, v),
    };
  }

  anchorBacklog() {
    const head = this.headRow(), last = this.sql.exec('SELECT MAX(seq) AS s FROM anchors').toArray()[0]?.s ?? 0;
    return (head?.seq ?? 0) - last;
  }

  async anchorIfDue() {
    const due = this.meta('anchor_due_at'), now = this.now();
    if (due === null || Number(due) > now) return;
    if (this.repoId() === null) { this.sql.exec("DELETE FROM meta WHERE key = 'anchor_due_at'"); return; }
    try {
      await this.anchorCycle();
      this.sql.exec("DELETE FROM meta WHERE key = 'anchor_due_at'");
      if (this.anchorBacklog() >= ANCHOR_EVERY && !this.meta('anchor_blocked')) this.setMeta('anchor_due_at', now);
    } catch (error) {
      log('error', 'anchor_failed', { ledger: 'commit', repo_id: this.repoId(), error: errorCode(error) });
      this.setMeta('anchor_due_at', now + RETRY_MS);
    }
  }

  // Verify against the latest external anchor; on success write the next one. A failed verification raises critical
  // findings and stops anchoring this ledger (a new anchor must never bless a truncated or rewritten ledger).
  async anchorCycle() {
    const adapter = this.anchorAdapter(), bucket = this.env.ANCHORS, now = this.now();
    const verified = await verifyAnchors(adapter, bucket, { advance: true });
    const { latest: _internal, ...result } = verified;
    if (!verified.ok) { this.anchorProblems(verified.problems, now); return { ...result, written: null }; }
    if (this.meta('anchor_blocked')) return { ...result, written: null };
    const { written, problem } = await writeAnchor(adapter, bucket, verified.latest, now);
    if (problem) { this.anchorProblems([problem], now); return { ...result, written: null }; }
    if (written && this.env.BACKUP_ANCHOR) enqueue(this.sql, { kind: 'anchor_backup', dedupe_key: 'anchor_backup:' + written.key, payload: written }, now);
    return { ...result, written };
  }

  anchorProblems(problems, now) {
    const ledger = 'commit-' + this.repoId();
    this.storage.transactionSync(() => {
      for (const p of problems) this.recordFinding({ kind: p.code, ref: null, sha: p.anchor_hash ?? GENESIS, entry_seq: p.anchor_seq ?? null, delivery_id: 'anchor:' + (p.anchor_seq ?? 0) + ':' + p.reason, detail: anchorFindingDetail(ledger, p) }, now);
      if (!this.meta('anchor_blocked')) this.setMeta('anchor_blocked', JSON.stringify({ at: this.iso(now), codes: problems.map(p => p.code + ':' + p.reason) }));
    });
    log('critical', 'ledger_anchor_problem', { ledger, codes: problems.map(p => p.code + ':' + p.reason) });
  }

  /** Read method: verification only (no findings, no anchor written). */
  async verifyAnchor() {
    if (this.repoId() === null) return { ok: true, ledger: null, head_seq: 0, entry_count: 0, problems: [], chain: null, anchor: null, blocked: null };
    const { latest: _internal, ...result } = await verifyAnchors(this.anchorAdapter(), this.env.ANCHORS);
    return { ...result, blocked: this.meta('anchor_blocked') ? JSON.parse(this.meta('anchor_blocked')) : null };
  }

  // ---- Provenance: a main commit needs a promote/* tag within 15 minutes ----
  async checkPromotions(budget) {
    const now = this.now();
    const rows = this.sql.exec("SELECT * FROM promotions WHERE status = 'pending' AND due_at <= ? AND next_check_at <= ? ORDER BY due_at LIMIT 10", now, now).toArray();
    for (const row of rows) {
      if (budget.api <= 0) return;
      try {
        const actorId = this.promoterId();
        let lastTag = this.sql.exec('SELECT last_tag FROM promotion_check_progress WHERE sha = ? AND actor_id = ?', row.sha, actorId).toArray()[0]?.last_tag ?? '';
        let tagged = false;
        for (;;) {
          // Keyset pagination bounds both materialization and lookup work. Only completed
          // negative lookups advance the cursor; a deferred tag chain retries next alarm.
          const e = this.sql.exec('SELECT tag FROM verified_promote_tags WHERE sha = ? AND actor_id = ? AND tag > ? ORDER BY tag LIMIT 1', row.sha, actorId, lastTag).toArray()[0];
          if (!e) break;
          const target = await (this.deps.promotionTagTarget ?? promotionTagTarget)(this.meta('full_name'), e.tag, await this.token(budget), this.fetcher, budget);
          if (target === row.sha) { tagged = true; break; }
          lastTag = e.tag;
          this.sql.exec('INSERT INTO promotion_check_progress (sha, actor_id, last_tag) VALUES (?, ?, ?) ON CONFLICT(sha, actor_id) DO UPDATE SET last_tag = excluded.last_tag', row.sha, actorId, lastTag);
        }
        const t = this.now();
        this.storage.transactionSync(() => {
          const current = this.sql.exec('SELECT status FROM promotions WHERE sha = ?', row.sha).toArray()[0];
          this.sql.exec('DELETE FROM promotion_check_progress WHERE sha = ?', row.sha);
          if (current?.status !== 'pending') return; // cleared by a create event meanwhile
          if (tagged) { this.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = 'api', resolved_at = ? WHERE sha = ?", this.iso(t), row.sha); return; }
          this.sql.exec("UPDATE promotions SET status = 'flagged', resolved_by = 'api', resolved_at = ? WHERE sha = ?", this.iso(t), row.sha);
          this.recordFinding({ kind: 'main_commit_missing_promotion_tag', ref: 'refs/heads/main', sha: row.sha, entry_seq: row.entry_seq, delivery_id: row.delivery_id, detail: { due_at: this.iso(row.due_at) } }, t);
        });
      } catch (error) {
        if (error?.code === 'deferred') return;
        const attempts = row.attempts + 1, code = errorCode(error);
        this.sql.exec('UPDATE promotions SET attempts = ?, next_check_at = ?, last_error = ? WHERE sha = ?', attempts, this.now() + RETRY_MS, code, row.sha);
        log('warning', 'promotion_check_retry', { repo_id: this.repoId(), sha: row.sha, attempts, error: code });
        if (attempts === ESCALATE_AT) this.operationalAlert('promotion_check_failing', 'promotion:' + row.sha, { sha: row.sha, attempts, last_error: code });
      }
    }
  }

  // ---- R2 mirror: commits/<repo_id>/<seq>.json, written once (If-None-Match: *), never rewritten ----
  async mirror() {
    const repoId = this.repoId(), from = Number(this.meta('mirrored_through') ?? 0);
    const rows = this.sql.exec('SELECT * FROM entries WHERE seq > ? ORDER BY seq LIMIT ?', from, MIRROR_BATCH).toArray();
    for (const row of rows) {
      const entry = entryOf(row, repoId), key = commitMirrorKey(repoId, entry.seq), body = canonical(entry);
      try {
        const put = await this.env.EVENTS.put(key, body, {
          onlyIf: new Headers({ 'if-none-match': '*' }), httpMetadata: { contentType: 'application/json' }, customMetadata: { sha256: await sha256Hex(body), entry_hash: entry.entry_hash },
        });
        if (put === null) {
          const existing = await this.env.EVENTS.head(key);
          if (existing?.customMetadata?.entry_hash !== entry.entry_hash) this.operationalAlert('mirror_conflict', 'mirror:' + entry.seq, { seq: entry.seq });
        }
        this.setMeta('mirrored_through', entry.seq);
      } catch (error) {
        log('warning', 'commit_mirror_retry', { repo_id: repoId, seq: entry.seq, error: errorCode(error) });
        this.setMeta('mirror_retry_at', this.now() + 60_000);
        return;
      }
    }
    this.sql.exec("DELETE FROM meta WHERE key = 'mirror_retry_at'");
  }

  // ---- Read side ----
  head() {
    const head = this.headRow(), inbox = this.sql.exec('SELECT COUNT(*) AS n, MAX(attempts) AS max_attempts FROM inbox').toArray()[0];
    const promo = this.sql.exec("SELECT COUNT(*) AS n FROM promotions WHERE status = 'pending'").toArray()[0];
    const anchor = this.sql.exec('SELECT seq, object_key, anchor_hash, created_at FROM anchors ORDER BY seq DESC LIMIT 1').toArray()[0];
    const json = k => { const v = this.meta(k); return v === null ? null : JSON.parse(v); };
    return { repo_id: this.repoId(), full_name: this.meta('full_name'), seq: head?.seq ?? 0, entry_hash: head?.entry_hash ?? GENESIS,
      mirrored_through: Number(this.meta('mirrored_through') ?? 0), inbox: { pending: inbox.n, max_attempts: inbox.max_attempts ?? 0 },
      promotions_pending: promo.n, outbox: pendingCounts(this.sql),
      last_anchor: anchor ? { ...anchor } : null, anchor_blocked: json('anchor_blocked'), refs_last_run: json('refs_last_run') };
  }

  entries(limit, cursor) {
    const n = boundedLimit(limit), before = optionalCursor(cursor), repoId = this.repoId();
    const rows = this.sql.exec('SELECT * FROM entries WHERE seq < ? ORDER BY seq DESC LIMIT ?', before ?? Number.MAX_SAFE_INTEGER, n).toArray().map(r => entryOf(r, repoId));
    return { items: rows, next_cursor: rows.length === n && rows.at(-1).seq > 1 ? rows.at(-1).seq : null };
  }

  findings(limit, cursor) {
    const n = boundedLimit(limit, 500, 100), before = optionalCursor(cursor);
    const rows = this.sql.exec('SELECT * FROM findings WHERE id < ? ORDER BY id DESC LIMIT ?', before ?? Number.MAX_SAFE_INTEGER, n).toArray().map(findingOf);
    return { repo_id: this.repoId(), items: rows, next_cursor: rows.length === n && rows.at(-1).id > 1 ? rows.at(-1).id : null };
  }

  async verify(fromSeq, toSeq) {
    const head = this.headRow(), repoId = this.repoId();
    if (!head) return { ok: true, checked: 0, first_break: null, from: 0, to: 0, head_seq: 0 };
    const { from, to } = verifyRange(fromSeq, toSeq, head.seq);
    if (to < from) return { ok: true, checked: 0, first_break: null, from, to, head_seq: head.seq };
    let expectedPrev = GENESIS;
    if (from > 1) {
      const before = this.sql.exec('SELECT entry_hash FROM entries WHERE seq = ?', from - 1).toArray()[0];
      if (!before) return { ok: false, checked: 0, first_break: { seq: from - 1, reason: 'missing_entry' }, from, to, head_seq: head.seq };
      expectedPrev = before.entry_hash;
    }
    let rows;
    try { rows = this.sql.exec('SELECT * FROM entries WHERE seq BETWEEN ? AND ? ORDER BY seq', from, to).toArray().map(r => entryOf(r, repoId)); }
    catch { return { ok: false, checked: 0, first_break: { seq: from, reason: 'unparseable_entry' }, from, to, head_seq: head.seq }; }
    const result = await verifyEntries(rows, expectedPrev, from);
    if (result.ok && result.checked !== to - from + 1) return { ...result, ok: false, first_break: { seq: from + result.checked, reason: 'missing_entry' }, from, to, head_seq: head.seq };
    return { ...result, from, to, head_seq: head.seq };
  }
}
