// Durable Object classes. Thin RPC shells over the runtime-independent cores; no HTTP interface.
import { DurableObject } from 'cloudflare:workers';
import { EventLedgerCore } from './event-ledger-core.mjs';
import { CommitLedgerCore } from './commit-ledger-core.mjs';

const notFound = () => new Response(null, { status: 404 });

export class EventLedger extends DurableObject {
  constructor(ctx, env) { super(ctx, env); this.core = new EventLedgerCore(ctx.storage, env); }
  fetch() { return notFound(); }
  begin(input) { return this.core.begin(input); }
  commit(input) { return this.core.commit(input); }
  release(input) { return this.core.release(input); }
  head() { return this.core.head(); }
  recent(limit, cursor) { return this.core.recent(limit, cursor); }
  repos() { return this.core.repos(); }
  verify(fromSeq, toSeq) { return this.core.verify(fromSeq, toSeq); }
  verifyAnchor() { return this.core.verifyAnchor(); }
  findings(limit, cursor) { return this.core.findings(limit, cursor); }
  requestCron(tasks) { return this.core.requestCron(tasks); }
  ledgeredRepos() { return this.core.ledgeredRepos(); }
  alarm() { return this.core.alarm(); }
}

export class CommitLedger extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = new CommitLedgerCore(ctx.storage, env);
    ctx.blockConcurrencyWhile(() => this.core.initialize());
  }
  fetch() { return notFound(); }
  ingest(item) { return this.core.ingest(item); }
  head() { return this.core.head(); }
  entries(limit, cursor) { return this.core.entries(limit, cursor); }
  findings(limit, cursor) { return this.core.findings(limit, cursor); }
  verify(fromSeq, toSeq) { return this.core.verify(fromSeq, toSeq); }
  verifyAnchor() { return this.core.verifyAnchor(); }
  requestCron(tasks) { return this.core.requestCron(tasks); }
  alarm() { return this.core.alarm(); }
}
