// CommitLedger: one SQLite Durable Object per repository (idFromName(String(repo_id))).
// `push` events append a `ref_update` entry plus one `commit` entry per commit new to this ledger, hash chained,
// mirrored to R2 `commits/<repo_id>/<seq>.json`. Integrity findings (integrity.mjs) are stored and alerted.
// Work arrives through an inbox processed in order by the alarm, so GitHub API outages delay but never reorder
// or drop entries.
import { GENESIS, canonical, link, verifyEntries, verifyRange, mutex } from './chain.mjs';
import { OUTBOX_SCHEMA, enqueue, drain, nextDue, pendingCounts, prune, backoff, ESCALATE_AT } from './outbox.mjs';
import { refFindings, mainCommitFindings, mainCommits, promotionTagPrefix, PROMOTION_GRACE_MS } from './integrity.mjs';
import { mintInstallationToken, commitDetails, hasPromotionTag, SHA } from './github-app.mjs';
import { deliverAlert, findingAlert } from './alerts.mjs';
import { CodedError, sha256Hex } from './bytes.mjs';
import { boundedLimit, optionalCursor } from './event-ledger-core.mjs';
import { log, errorCode } from './log.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ZERO_OR_SHA = v => typeof v === 'string' && (SHA.test(v) || /^0+$/.test(v));
const API_BUDGET = 40, RETRY_MS = 300_000, MIRROR_BATCH = 50, KEEP_DONE_MS = 30 * 86_400_000;
export const commitMirrorKey = (repoId, seq) => `commits/${repoId}/${seq}.json`;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('ref_update', 'commit')),
    delivery_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)`,
  "CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END",
  "CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END",
  'CREATE TABLE IF NOT EXISTS commits (sha TEXT PRIMARY KEY, seq INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS refs (ref TEXT PRIMARY KEY, sha TEXT NOT NULL, deleted INTEGER NOT NULL, seq INTEGER NOT NULL)',
  `CREATE TABLE IF NOT EXISTS inbox (id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error TEXT, queued_at INTEGER NOT NULL)`,
  'CREATE TABLE IF NOT EXISTS commit_details (sha TEXT PRIMARY KEY, details TEXT NOT NULL)',
  `CREATE TABLE IF NOT EXISTS promotions (sha TEXT PRIMARY KEY, entry_seq INTEGER, delivery_id TEXT NOT NULL, due_at INTEGER NOT NULL,
    next_check_at INTEGER NOT NULL, status TEXT NOT NULL CHECK (status IN ('pending', 'satisfied', 'flagged')),
    resolved_by TEXT, resolved_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)`,
  'CREATE TABLE IF NOT EXISTS promote_tags (tag TEXT PRIMARY KEY, prefix TEXT NOT NULL, delivery_id TEXT NOT NULL, seen_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS promote_tags_prefix ON promote_tags(prefix)',
  `CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, ref TEXT, sha TEXT NOT NULL, entry_seq INTEGER,
    delivery_id TEXT NOT NULL, detail TEXT NOT NULL, detected_at TEXT NOT NULL, UNIQUE (kind, sha, delivery_id))`,
  'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  ...OUTBOX_SCHEMA,
];

const entryOf = (r, repoId) => ({ seq: r.seq, repo_id: repoId, kind: r.kind, delivery_id: r.delivery_id, recorded_at: r.recorded_at,
  data: JSON.parse(r.data), prev_hash: r.prev_hash, entry_hash: r.entry_hash });
const findingOf = r => ({ id: r.id, kind: r.kind, ref: r.ref, sha: r.sha, entry_seq: r.entry_seq, delivery_id: r.delivery_id, detail: JSON.parse(r.detail), detected_at: r.detected_at });

function validItem(item) {
  if (!item || !['push', 'create'].includes(item.type) || !Number.isSafeInteger(item.repo_id) || item.repo_id < 1 || !UUID.test(item.delivery_id ?? '')) return false;
  if (typeof item.ref !== 'string' || item.ref.length > 1024) return false;
  if (item.type === 'create') return ['tag', 'branch'].includes(item.ref_type);
  return ZERO_OR_SHA(item.before) && ZERO_OR_SHA(item.after) && Array.isArray(item.commits) && item.commits.every(s => SHA.test(s));
}

export class CommitLedgerCore {
  constructor(storage, env, deps = {}) {
    this.storage = storage; this.sql = storage.sql; this.env = env; this.deps = deps;
    this.now = deps.now || Date.now; this.fetcher = deps.fetcher || fetch; this.lock = mutex(); this.cachedToken = null;
    for (const statement of SCHEMA) this.sql.exec(statement);
  }

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
      this.sql.exec('INSERT INTO inbox (delivery_id, payload, next_attempt_at, queued_at) VALUES (?, ?, ?, ?) ON CONFLICT(delivery_id) DO NOTHING',
        item.delivery_id, JSON.stringify(item), now, now);
    });
    await this.wake(now);
    return { accepted: true };
  }

  async token() {
    const now = this.now();
    if (this.cachedToken && this.cachedToken.expires_at - now > 300_000) return this.cachedToken.token;
    const installation = Number(this.meta('installation_id'));
    this.cachedToken = await (this.deps.mintToken ?? mintInstallationToken)(this.env, installation, this.repoId(), this.fetcher);
    return this.cachedToken.token;
  }

  async alarm() {
    const budget = { api: API_BUDGET };
    await this.processInbox(budget);
    await this.checkPromotions(budget);
    await this.mirror();
    await drain(this.sql, { alert: p => deliverAlert(this.env, p, this.fetcher) }, { now: this.now, source: 'commit_ledger' });
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
    if (times.length) await this.storage.setAlarm(Math.max(Math.min(...times), now + 1000));
  }

  // ---- Inbox: strictly in arrival order; a failing head item blocks later ones (ordering is part of the ledger). ----
  async processInbox(budget) {
    for (;;) {
      const row = this.sql.exec('SELECT * FROM inbox ORDER BY id LIMIT 1').toArray()[0];
      if (!row || row.next_attempt_at > this.now()) return;
      const item = JSON.parse(row.payload);
      try {
        if (item.type === 'create') { this.applyCreate(row, item); continue; }
        if (!await this.fetchDetails(item, budget)) return;
        await this.applyPush(row, item);
      } catch (error) {
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

  // Returns false when the API budget for this alarm run is spent (resumes on the next run).
  async fetchDetails(item, budget) {
    const fullName = item.full_name ?? this.meta('full_name');
    for (const sha of this.shasFor(item)) {
      if (this.knownDetails(sha)) continue;
      if (budget.api <= 0) return false;
      budget.api--;
      const details = await (this.deps.commitDetails ?? commitDetails)(fullName, sha, await this.token(), this.fetcher);
      this.sql.exec('INSERT INTO commit_details (sha, details) VALUES (?, ?) ON CONFLICT(sha) DO NOTHING', sha, JSON.stringify(details));
    }
    return true;
  }

  applyPush(row, item) {
    return this.lock(async () => {
      const now = this.now(), recorded_at = this.iso(now), repoId = this.repoId();
      const update = { ref: item.ref, before: item.before, after: item.after, created: item.created, deleted: item.deleted, forced: item.forced, pusher: item.pusher ?? null, delivery_id: item.delivery_id };
      const previous = this.sql.exec('SELECT sha FROM refs WHERE ref = ?', item.ref).toArray()[0]?.sha ?? null;
      const bodies = [{ repo_id: repoId, kind: 'ref_update', delivery_id: item.delivery_id, recorded_at, data: update }];
      const fresh = [];
      for (const sha of this.shasFor(item)) {
        if (this.sql.exec('SELECT 1 FROM commits WHERE sha = ?', sha).toArray().length) continue;
        fresh.push(sha);
        const details = this.knownDetails(sha);
        bodies.push({ repo_id: repoId, kind: 'commit', delivery_id: item.delivery_id, recorded_at, data: { ...details, sha, ref: item.ref } });
      }
      const head = this.headRow(), entries = await link(head, bodies), refSeq = entries[0].seq;
      const seqOf = new Map(fresh.map((sha, i) => [sha, entries[i + 1].seq]));
      const existingSeq = sha => seqOf.get(sha) ?? this.sql.exec('SELECT seq FROM commits WHERE sha = ?', sha).toArray()[0]?.seq ?? null;
      const findings = refFindings(update, previous).map(f => ({ ...f, entry_seq: refSeq }));
      const onMain = mainCommits(item);
      for (const sha of onMain) findings.push(...mainCommitFindings({ ...this.knownDetails(sha), sha }).map(f => ({ ...f, entry_seq: existingSeq(sha) })));
      this.storage.transactionSync(() => {
        if ((this.headRow()?.seq ?? 0) !== (head?.seq ?? 0)) throw new CodedError('head_moved');
        for (const e of entries) {
          this.sql.exec('INSERT INTO entries (seq, kind, delivery_id, recorded_at, data, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
            e.seq, e.kind, e.delivery_id, e.recorded_at, canonical(e.data), e.prev_hash, e.entry_hash);
          if (e.kind === 'commit') this.sql.exec('INSERT INTO commits (sha, seq) VALUES (?, ?)', e.data.sha, e.seq);
        }
        const target = item.deleted ? item.before : item.after;
        this.sql.exec('INSERT INTO refs (ref, sha, deleted, seq) VALUES (?, ?, ?, ?) ON CONFLICT(ref) DO UPDATE SET sha = excluded.sha, deleted = excluded.deleted, seq = excluded.seq',
          item.ref, target, item.deleted ? 1 : 0, refSeq);
        for (const f of findings) this.recordFinding({ ...f, delivery_id: item.delivery_id }, now);
        for (const sha of onMain) {
          const tagged = this.sql.exec('SELECT tag FROM promote_tags WHERE prefix = ? LIMIT 1', sha.slice(0, 12)).toArray()[0];
          this.sql.exec('INSERT INTO promotions (sha, entry_seq, delivery_id, due_at, next_check_at, status, resolved_by, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sha) DO NOTHING',
            sha, existingSeq(sha), item.delivery_id, now + PROMOTION_GRACE_MS, now + PROMOTION_GRACE_MS,
            tagged ? 'satisfied' : 'pending', tagged ? 'create_event:' + tagged.tag : null, tagged ? recorded_at : null);
        }
        this.sql.exec('DELETE FROM inbox WHERE id = ?', row.id);
        for (const sha of this.shasFor(item)) this.sql.exec('DELETE FROM commit_details WHERE sha = ?', sha);
      });
      if (item.commits_truncated) log('warning', 'push_commits_truncated', { repo_id: repoId, delivery_id: item.delivery_id });
      if (findings.length) log('warning', 'integrity_findings', { repo_id: repoId, delivery_id: item.delivery_id, kinds: findings.map(f => f.kind) });
    });
  }

  // A `create` of `promote/pr-<n>-<sha12>` clears the pending provenance check for the matching main commit.
  // The name is authoritative here because the tag ruleset lets only the promoter create promote/* tags;
  // the alarm path (hasPromotionTag) additionally dereferences the tag to the full commit sha.
  applyCreate(row, item) {
    const prefix = item.ref_type === 'tag' ? promotionTagPrefix(item.ref) : null, at = this.iso(this.now());
    this.storage.transactionSync(() => {
      if (prefix) {
        this.sql.exec('INSERT INTO promote_tags (tag, prefix, delivery_id, seen_at) VALUES (?, ?, ?, ?) ON CONFLICT(tag) DO NOTHING', item.ref, prefix, item.delivery_id, at);
        this.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = ?, resolved_at = ? WHERE status = 'pending' AND substr(sha, 1, 12) = ?",
          'create_event:' + item.ref, at, prefix);
      }
      this.sql.exec('DELETE FROM inbox WHERE id = ?', row.id);
    });
  }

  recordFinding(f, now) {
    const detected_at = this.iso(now);
    const row = this.sql.exec('INSERT INTO findings (kind, ref, sha, entry_seq, delivery_id, detail, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING id',
      f.kind, f.ref ?? null, f.sha, f.entry_seq ?? null, f.delivery_id, JSON.stringify(f.detail ?? {}), detected_at).toArray()[0];
    if (!row) return;
    const repo = { repo_id: this.repoId(), full_name: this.meta('full_name') };
    enqueue(this.sql, { kind: 'alert', dedupe_key: 'finding:' + this.repoId() + ':' + row.id, payload: findingAlert({ ...f, id: row.id, detected_at }, repo) }, now);
  }

  operationalAlert(code, key, detail) {
    const now = this.now();
    enqueue(this.sql, { kind: 'alert', dedupe_key: code + ':' + this.repoId() + ':' + key, payload: {
      schema: 'ghcaretaker-alert/v1', type: 'operational', code, repo_id: this.repoId(), repo: this.meta('full_name'), ...detail, detected_at: this.iso(now),
    } }, now);
  }

  // ---- Provenance: a main commit needs a promote/* tag within 15 minutes ----
  async checkPromotions(budget) {
    const now = this.now();
    const rows = this.sql.exec("SELECT * FROM promotions WHERE status = 'pending' AND due_at <= ? AND next_check_at <= ? ORDER BY due_at LIMIT 10", now, now).toArray();
    for (const row of rows) {
      if (budget.api <= 0) return;
      budget.api--;
      try {
        const tagged = await (this.deps.hasPromotionTag ?? hasPromotionTag)(this.meta('full_name'), row.sha, await this.token(), this.fetcher);
        const t = this.now();
        this.storage.transactionSync(() => {
          const current = this.sql.exec('SELECT status FROM promotions WHERE sha = ?', row.sha).toArray()[0];
          if (current?.status !== 'pending') return; // cleared by a create event meanwhile
          if (tagged) { this.sql.exec("UPDATE promotions SET status = 'satisfied', resolved_by = 'api', resolved_at = ? WHERE sha = ?", this.iso(t), row.sha); return; }
          this.sql.exec("UPDATE promotions SET status = 'flagged', resolved_by = 'api', resolved_at = ? WHERE sha = ?", this.iso(t), row.sha);
          this.recordFinding({ kind: 'main_commit_missing_promotion_tag', ref: 'refs/heads/main', sha: row.sha, entry_seq: row.entry_seq, delivery_id: row.delivery_id, detail: { due_at: this.iso(row.due_at) } }, t);
        });
      } catch (error) {
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
    return { repo_id: this.repoId(), full_name: this.meta('full_name'), seq: head?.seq ?? 0, entry_hash: head?.entry_hash ?? GENESIS,
      mirrored_through: Number(this.meta('mirrored_through') ?? 0), inbox: { pending: inbox.n, max_attempts: inbox.max_attempts ?? 0 },
      promotions_pending: promo.n, outbox: pendingCounts(this.sql) };
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
