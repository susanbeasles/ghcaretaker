// Server-rendered HTML for the caretaker dashboard. No scripts, no external resources: one stylesheet served by the
// Worker (/style.css, CSP style-src 'self'). Every interpolated value goes through `html`, which escapes by default;
// only fragments produced by `html` itself are inserted unescaped. Inline SVG uses attributes and classes only
// (no style attributes), so the CSP needs no 'unsafe-inline'.

class Safe { constructor(text) { this.text = text; } toString() { return this.text; } }
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ESC[c]);
const render = v => (v instanceof Safe ? v.text : Array.isArray(v) ? v.map(render).join('') : v === null || v === undefined || v === false ? '' : escapeHtml(v));
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1];
  return new Safe(out);
}

export const CSS = `:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1d1f21;--muted:#5f6368;--line:#dcdcd8;--card:#fff;--accent:#2f6fb3;--ok:#1d7a3a;--bad:#b3261e;--warn:#8a5a00;--track:#e6e6e2}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#e6e6e3;--muted:#a0a4a8;--line:#2e3134;--card:#1b1d20;--accent:#7fb0e6;--ok:#6cc58a;--bad:#f2867d;--warn:#e0b25a;--track:#2a2d30}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{border-bottom:1px solid var(--line);background:var(--card)}
nav{max-width:1200px;margin:0 auto;padding:.6rem 1rem;display:flex;flex-wrap:wrap;gap:.25rem 1rem;align-items:baseline}
nav a{color:var(--fg);text-decoration:none;padding:.15rem 0}nav a[aria-current=page]{border-bottom:2px solid var(--accent)}
nav .brand{font-weight:600;margin-right:.5rem}
main{max-width:1200px;margin:0 auto;padding:1rem}
h1{font-size:1.35rem;margin:.2rem 0 1rem}h2{font-size:1.05rem;margin:1.6rem 0 .6rem}
a{color:var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(10.5rem,1fr));gap:.6rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.6rem .75rem}
.card .v{font-size:1.35rem;font-variant-numeric:tabular-nums;font-weight:600}.card .k{color:var(--muted);font-size:.8rem}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line);border-radius:6px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{padding:.35rem .55rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}
th{color:var(--muted);font-weight:600;background:var(--bg);position:sticky;top:0}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.wrap{white-space:normal;word-break:break-word;min-width:12rem}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}
.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 .45rem;font-size:.78rem}
.button{display:inline-block;border:1px solid var(--accent);border-radius:6px;padding:.3rem .7rem;text-decoration:none}
.pager{margin:.8rem 0;display:flex;gap:1rem;flex-wrap:wrap}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:.2rem .9rem;margin:0}dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;word-break:break-word}
svg.bar{vertical-align:middle}svg.bar .track{fill:var(--track)}svg.bar .fill{fill:var(--accent)}svg.bar .fill.bad{fill:var(--bad)}
.missing{color:var(--muted);font-style:italic}.est{color:var(--warn)}abbr.badge{text-decoration:none;cursor:help}
footer{max-width:1200px;margin:0 auto;padding:1rem;color:var(--muted);font-size:.8rem}
@media (max-width:600px){body{font-size:14px}main{padding:.75rem}th,td{padding:.3rem .4rem}}
`;

// ---------- formatting ----------
export const fmtInt = v => (Number.isFinite(v) ? Math.round(v).toLocaleString('en-US') : 'missing');
export const fmtPct = v => (Number.isFinite(v) ? (v * 100).toFixed(v >= 0.1 || v === 0 ? 0 : 1) + '%' : 'missing');
export const fmtFraction = v => (Number.isFinite(v) ? (v * 100).toFixed(0) + '%' : 'missing');
export function fmtMs(ms) {
  if (!Number.isFinite(ms)) return 'missing';
  const s = Math.round(ms / 1000);
  if (s < 1) return '<1s';
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's';
  return Math.floor(s / 3600) + 'h ' + String(Math.floor((s % 3600) / 60)).padStart(2, '0') + 'm';
}
export function fmtBytes(b) {
  if (!Number.isFinite(b)) return 'missing';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = b, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? String(v) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + units[i];
}
export const fmtMinutes = v => (Number.isFinite(v) ? v.toFixed(v >= 100 ? 0 : 1) : 'missing');

const MISSING = () => html`<span class="missing">missing</span>`;
const FORMAT = { ms: fmtMs, ratio: fmtPct, fraction: fmtFraction, bytes: fmtBytes, min: fmtMinutes, count: fmtInt };
/**
 * One provenance-labelled figure ({value, kind, unit}). Missing is the word "missing", never 0 or a dash that reads
 * as zero. Estimates are prefixed with "≈" and carry an "est." badge whose title states the basis.
 */
export function figure(f) {
  if (!f || f.value === null || f.value === undefined) return MISSING();
  const text = (FORMAT[f.unit] ?? fmtInt)(f.value);
  if (f.kind === 'estimated') return html`<span class="est">≈ ${text}</span> <abbr class="badge est" title="${'estimated: ' + (f.basis ?? 'derived value')}">est.</abbr>`;
  return html`${text}`;
}
const short = (hex, n = 12) => (typeof hex === 'string' ? hex.slice(0, n) : '—');
const when = iso => (typeof iso === 'string' ? iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '—');

/** Inline bar for a 0..1 value; width is a computed number, never text. */
function bar(fraction, bad = false) {
  if (fraction && typeof fraction === 'object') fraction = fraction.value;
  if (!Number.isFinite(fraction)) return '';
  const w = Math.max(0, Math.min(100, Math.round(fraction * 100)));
  return html`<svg class="bar" width="60" height="8" viewBox="0 0 100 10" aria-hidden="true" focusable="false"><rect class="track" width="100" height="10"/><rect class="fill${bad ? ' bad' : ''}" width="${w}" height="10"/></svg>`;
}

const repoLink = (id, name) => (Number.isSafeInteger(id) ? html`<a href="/repos/${id}/commits">${name ?? 'repo ' + id}</a>` : html`<span class="muted">—</span>`);

// ---------- layout ----------
const NAV = [['/', 'Overview'], ['/events', 'Events'], ['/promotions', 'Promotions'], ['/actions', 'Actions']];

export function page({ title, active, api, body }) {
  return html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer">
<title>${title} · caretaker</title><link rel="stylesheet" href="/style.css"></head>
<body><header><nav aria-label="Main"><a class="brand" href="/">caretaker</a>${NAV.map(([href, label]) => html` <a href="${href}"${active === href ? html` aria-current="page"` : ''}>${label}</a>`)}</nav></header>
<main><h1>${title}</h1>${body}</main>
<footer>Read only. JSON: <a href="${api}">${api}</a></footer></body></html>`.text;
}

const table = (head, rows, empty = 'Nothing yet.') => rows.length
  ? html`<div class="scroll"><table><thead><tr>${head.map(([label, num]) => html`<th${num ? html` class="num"` : ''} scope="col">${label}</th>`)}</tr></thead><tbody>${rows}</tbody></table></div>`
  : html`<p class="muted">${empty}</p>`;
const card = (k, v, cls = '') => html`<div class="card"><div class="v${cls ? ' ' + cls : ''}">${v}</div><div class="k">${k}</div></div>`;
const status = ok => (ok ? html`<span class="badge ok">intact</span>` : html`<span class="badge bad">broken</span>`);

// ---------- pages ----------
export function overviewPage(d) {
  const { head, chain } = d.ledger, r = d.runs_24h, f = d.findings, names = new Map(d.repos.map(x => [x.repo_id, x.full_name]));
  const backup = d.backup.available
    ? (d.backup.summary !== null && typeof d.backup.summary === 'object' && !Array.isArray(d.backup.summary)
      ? html`<dl class="kv">${Object.entries(d.backup.summary).slice(0, 30).map(([k, v]) => html`<dt>${k}</dt><dd>${v !== null && typeof v === 'object' ? JSON.stringify(v).slice(0, 300) : String(v)}</dd>`)}</dl>`
      : html`<p>${JSON.stringify(d.backup.summary).slice(0, 300)}</p>`)
    : html`<p class="muted">Backup status unavailable (${d.backup.reason}).</p>`;
  const body = html`
<h2>Event ledger</h2>
<div class="cards">${card('head seq', fmtInt(head.seq))}${card('chain, last ' + fmtInt(chain.checked) + ' entries', chain.ok ? 'intact' : 'broken at ' + chain.first_break?.seq, chain.ok ? 'ok' : 'bad')}${card('last checkpoint', head.last_checkpoint ? fmtInt(head.last_checkpoint.seq) : '—')}${card('outbox pending', fmtInt(Object.values(head.outbox ?? {}).reduce((a, o) => a + (o.pending ?? 0), 0)))}</div>
<p class="muted mono">head ${short(head.entry_hash, 64)}${chain.ok ? '' : html` · first break: ${chain.first_break?.reason}`}</p>
<h2>Integrity findings</h2>
${f === null ? html`<p class="muted">Findings unavailable.</p>` : html`<div class="cards">${card('all findings', fmtInt(f.total), f.total ? 'bad' : 'ok')}${card('last 7 days', fmtInt(f.last_7d), f.last_7d ? 'bad' : '')}</div>
${table([['Detected'], ['Repository'], ['Kind'], ['Ref'], ['Commit']], f.latest.map(x => html`<tr><td>${when(x.detected_at)}</td><td>${repoLink(x.repo_id, names.get(x.repo_id))}</td><td class="bad">${x.kind}</td><td>${x.ref ?? '—'}</td><td class="mono">${short(x.sha)}</td></tr>`), 'No findings.')}`}
<h2>Workflow runs, last 24 h</h2>
${r === null ? html`<p class="muted">Metrics database not bound.</p>` : html`<div class="cards">${card('runs', figure(r.runs))}${card('failure rate', figure(r.failure_rate), r.failures.value ? 'bad' : '')}${card('duration p50', figure(r.run_duration_p50))}${card('duration p95', figure(r.run_duration_p95))}${card('queue p95', figure(r.queue_p95))}${card('billable minutes (reported)', figure(r.billable_minutes))}${card('minutes without billing data (estimated)', figure(r.estimated_minutes))}</div>${r.truncated ? html`<p class="warn">Row limit reached; figures cover the newest rows only.</p>` : ''}`}
<h2>Backups</h2>
${backup}
<h2>Repositories</h2>
${table([['Repository'], ['Id', true]], d.repos.map(x => html`<tr><td>${repoLink(x.repo_id, x.full_name)}</td><td class="num">${x.repo_id}</td></tr>`), 'No repositories seen yet.')}`;
  return page({ title: 'Overview', active: '/', api: '/api/overview', body });
}

export function eventsPage(d) {
  const rows = d.items.map(e => html`<tr><td class="num">${e.seq}</td><td>${when(e.received_at)}</td><td>${e.event}</td><td>${e.action ?? '—'}</td><td>${e.repo_id === null ? '—' : repoLink(e.repo_id, e.repo)}</td><td class="mono">${e.delivery_id}</td><td class="mono">${short(e.entry_hash)}</td></tr>`);
  const more = d.next_cursor ? html`<div class="pager"><a href="/events?cursor=${d.next_cursor}&amp;limit=${d.limit}">Older →</a></div>` : '';
  const body = html`${table([['Seq', true], ['Received'], ['Event'], ['Action'], ['Repository'], ['Delivery'], ['Entry hash']], rows, 'No events yet.')}${more}`;
  return page({ title: 'Events', active: '/events', api: '/api/events', body });
}

function entrySummary(e) {
  const x = e.data ?? {};
  if (e.kind === 'ref_update') return html`<code>${x.ref}</code> ${short(x.before)} → ${short(x.after)}${x.forced ? html` <span class="badge bad">forced</span>` : ''}${x.deleted ? html` <span class="badge bad">deleted</span>` : ''}${x.pusher ? html` <span class="muted">by ${x.pusher}</span>` : ''}`;
  return html`<span class="mono">${short(x.sha)}</span> ${x.verified ? html`<span class="badge ok">verified</span>` : html`<span class="badge warn">${x.verification_reason ?? 'unverified'}</span>`} <span class="muted">${x.author_name ?? ''} · ${Array.isArray(x.parents) ? x.parents.length + ' parent(s)' : ''} · <code>${x.ref ?? ''}</code></span>`;
}

export function commitsPage(d) {
  const name = d.head?.full_name ?? 'repo ' + d.repo_id;
  const rows = d.items.map(e => html`<tr><td class="num">${e.seq}</td><td>${when(e.recorded_at)}</td><td>${e.kind}</td><td class="wrap">${entrySummary(e)}</td><td class="mono">${short(e.entry_hash)}</td></tr>`);
  const findingsRows = d.findings.map(f => html`<tr><td>${when(f.detected_at)}</td><td class="bad">${f.kind}</td><td>${f.ref ?? '—'}</td><td class="mono">${short(f.sha)}</td><td class="num">${f.entry_seq ?? '—'}</td></tr>`);
  const more = d.next_cursor ? html`<div class="pager"><a href="/repos/${d.repo_id}/commits?cursor=${d.next_cursor}&amp;limit=${d.limit}">Older →</a></div>` : '';
  const body = html`<p>${name} · head seq ${fmtInt(d.head?.seq)} · mirrored through ${fmtInt(d.head?.mirrored_through)} · inbox ${fmtInt(d.head?.inbox?.pending)} · promotions pending ${fmtInt(d.head?.promotions_pending)}</p>
<p><a class="button" href="/repos/${d.repo_id}/verify">Verify the last 1000 entries</a></p>
<h2>Findings</h2>${table([['Detected'], ['Kind'], ['Ref'], ['Commit'], ['Entry', true]], findingsRows, 'No findings.')}
<h2>Ledger</h2>${table([['Seq', true], ['Recorded'], ['Kind'], ['Entry'], ['Entry hash']], rows, 'Ledger is empty.')}${more}`;
  return page({ title: 'Commit ledger', active: null, api: '/api/repos/' + d.repo_id + '/commits', body });
}

export function verifyPage(d) {
  const r = d.result;
  const body = html`<p>${d.full_name ?? 'repo ' + d.repo_id} · <a href="/repos/${d.repo_id}/commits">back to the ledger</a></p>
<div class="cards">${card('result', r.ok ? 'intact' : 'broken', r.ok ? 'ok' : 'bad')}${card('entries checked', fmtInt(r.checked))}${card('range', r.checked ? fmtInt(r.from) + '–' + fmtInt(r.to) : '—')}${card('head seq', fmtInt(r.head_seq))}</div>
${r.ok ? '' : html`<p class="bad">First break at seq ${r.first_break?.seq}: ${r.first_break?.reason}</p>`}<p class="muted mono">head ${short(d.head.entry_hash, 64)}</p>`;
  return page({ title: 'Commit ledger verification', active: null, api: '/api/repos/' + d.repo_id + '/verify', body });
}

export function promotionsPage(d) {
  const rows = d.items.map(p => html`<tr><td>${when(p.reached_main_at)}</td><td>${repoLink(p.repo_id, p.repo)}</td><td class="mono">${short(p.sha)}</td><td>${p.tag ? html`<code>${p.tag}</code>` : p.missing_tag_finding ? html`<span class="badge bad">missing</span>` : html`<span class="muted">not in window</span>`}</td><td class="num">${p.pr ?? MISSING()}</td><td class="num">${'shadow_to_main_s' in p ? fmtMs(p.shadow_to_main_s * 1000) : MISSING()}</td><td>${p.forced ? html`<span class="badge bad">forced</span>` : ''}</td></tr>`);
  const body = html`<p class="muted">Updates of <code>main</code> from each repository's commit ledger (newest ${d.window_entries_per_repo} entries per repository), with the matching <code>promote/*</code> tag. "Shadow → main" is ledger time from the candidate's push to <code>shadow/pr-&lt;n&gt;</code> to its arrival on <code>main</code>; time from the PR head is not recorded in the ledger.</p>
${table([['Reached main'], ['Repository'], ['Commit'], ['Tag'], ['PR', true], ['Shadow → main', true], ['']], rows, 'No main updates in the ledger window.')}`;
  return page({ title: 'Promotions', active: '/promotions', api: '/api/promotions', body });
}

function metricRows(list, level) {
  const job = level === 'job';
  return list.map(x => html`<tr><td>${repoLink(x.repo_id, x.repo)}</td>${level !== 'repo' ? html`<td class="wrap">${x.workflow ?? MISSING()}</td>` : ''}${job ? html`<td class="wrap">${x.job}</td>` : ''}
<td class="num">${figure(job ? x.jobs : x.runs)}</td><td class="num">${figure(job ? x.job_failure_rate : x.failure_rate)} ${bar(job ? x.job_failure_rate : x.failure_rate, true)}</td>
<td class="num">${figure(job ? x.job_duration_p50 : x.run_duration_p50)}</td><td class="num">${figure(job ? x.job_duration_p95 : x.run_duration_p95)}</td><td class="num">${figure(x.queue_p95)}</td>
${job ? '' : html`<td class="num">${figure(x.billable_minutes)}</td><td class="num">${figure(x.estimated_minutes)}</td>`}<td class="num">${figure(x.cpu_mean)} ${bar(x.cpu_mean)}</td><td class="num">${figure(x.cpu_p95)}</td><td class="num">${figure(x.memory_peak)}</td><td class="num">${figure(x.telemetry_jobs)}</td></tr>`);
}

export function actionsPage(d) {
  const head = level => [['Repository'], ...(level !== 'repo' ? [['Workflow']] : []), ...(level === 'job' ? [['Job']] : []), [level === 'job' ? 'Jobs' : 'Runs', true], ['Failure rate', true],
    ['Duration p50', true], ['Duration p95', true], ['Queue p95', true], ...(level === 'job' ? [] : [['Billable min (reported)', true], ['Minutes (estimated)', true]]),
    ['CPU mean', true], ['CPU p95', true], ['Memory peak', true], ['Telemetry jobs', true]];
  const t = d.total;
  const body = html`<p class="pager"><a href="/actions?days=7"${d.days === 7 ? html` aria-current="page"` : ''}>7 days</a><a href="/actions?days=30"${d.days === 30 ? html` aria-current="page"` : ''}>30 days</a><span class="muted">since ${when(d.since)}</span></p>
<div class="cards">${card('runs', figure(t.runs))}${card('jobs', figure(t.jobs))}${card('failure rate', figure(t.failure_rate), t.failures.value ? 'bad' : '')}${card('duration p50', figure(t.run_duration_p50))}${card('duration p95', figure(t.run_duration_p95))}${card('queue p95', figure(t.queue_p95))}${card('billable minutes (reported)', figure(t.billable_minutes))}${card('minutes without billing data (estimated)', figure(t.estimated_minutes))}${card('jobs with telemetry', figure(t.telemetry_jobs))}</div>
${d.truncated ? html`<p class="warn">Row limit reached; figures cover the newest rows only.</p>` : ''}
<dl class="kv"><dt>measured</dt><dd>${d.provenance.measured}</dd><dt>reported</dt><dd>${d.provenance.reported}</dd><dt>estimated <span class="badge est">est.</span></dt><dd>${d.provenance.estimated}</dd></dl>
<p class="muted">Failure rate counts failure, timed_out and startup_failure against those plus success (cancelled and skipped are excluded). Duration: run start to last update for runs, start to completion for jobs. Queue: job created to started. Reported and estimated minutes cover different runs and are never added together; job rows have no minutes because billing is reported per run. CPU and memory come only from jobs that ran <code>actions/runner-telemetry</code>; CPU mean averages the jobs' means, CPU p95 is the 95th percentile of the jobs' p95s. "missing" means no data, not zero.</p>
<h2>By repository</h2>${table(head('repo'), metricRows(d.by_repository, 'repo'), 'No runs in this window.')}
<h2>By workflow</h2>${table(head('workflow'), metricRows(d.by_workflow, 'workflow'), 'No runs in this window.')}
<h2>By job</h2>${table(head('job'), metricRows(d.by_job, 'job'), 'No jobs in this window.')}`;
  return page({ title: 'Actions', active: '/actions', api: '/api/actions?days=' + d.days, body });
}

export function messagePage(title, message) {
  return page({ title, active: null, api: '/api/overview', body: html`<p>${message}</p>` });
}
