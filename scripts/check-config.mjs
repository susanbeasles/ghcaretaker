import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export function config(){return JSON.parse(fs.readFileSync(path.join(root,'wrangler.jsonc'),'utf8'));}
export function check(c,production=false){
 if(c.name!=='ghcaretaker'||c.main!=='src/index.mjs'||c.workers_dev!==false)throw Error('Unexpected Worker entrypoint or workers.dev ingress');
 if(c.vars.GITHUB_OWNER!=='susanbeasles'||c.vars.GITHUB_OWNER_ID!=='215839550')throw Error('Personal owner must remain pinned');
 if(c.r2_buckets?.length!==3||!c.r2_buckets.some(b=>b.binding==='AUDIT_BUCKET'&&b.bucket_name==='ghcaretaker-audit'))throw Error('Dedicated audit bucket required');
 if(!c.r2_buckets.some(b=>b.binding==='EVENTS'&&b.bucket_name==='github-events'))throw Error('github-events capture bucket required');
 // External anchors live in their own locked bucket, never in the bucket they vouch for (docs/adr/0003).
 if(!c.r2_buckets.some(b=>b.binding==='ANCHORS'&&b.bucket_name==='observatory-anchors'))throw Error('observatory-anchors anchor bucket required');
 if(c.preview_urls!==false)throw Error('Preview URLs must stay disabled');
 if(c.d1_databases?.length!==2||c.d1_databases[0].binding!=='AUDIT_DB'||c.d1_databases[0].database_name!=='ghcaretaker-audit'||c.d1_databases[0].migrations_dir!=='migrations')throw Error('Dedicated audit database required');
 if(!c.durable_objects?.bindings?.some(x=>x.name==='APP_VAULT'&&x.class_name==='AppVault'))throw Error('Credential vault required');
 if(c.vars.AUTH_ORIGIN!=='https://control.vespoli.me'||!c.services?.some(x=>x.binding==='AUTH_GATEWAY'&&x.service==='personal-control'))throw Error('Central auth gate required');
 checkObservatory(c);
 checkDashboard(c);
 if(!production)return;
 if(/REPLACE|example\.com/.test(JSON.stringify(c)))throw Error('Production placeholders are forbidden');
 if(c.vars.PUBLIC_ORIGIN!=='https://mcp.vespoli.me'||c.vars.MCP_PATH!=='/ghcaretaker')throw Error('Unexpected production endpoint');
 if(!c.routes?.some(r=>r.pattern==='mcp.vespoli.me/ghcaretaker*'&&r.zone_name==='vespoli.me'))throw Error('Scoped production route required');
 if(c.routes.some(r=>r.custom_domain||r.pattern==='mcp.vespoli.me/*'))throw Error('Do not take over the shared MCP hostname');
 // The webhook host is routed for exactly one path; no wildcard, so nothing else on hooks.vespoli.me reaches this Worker.
 const hooks=c.routes.filter(r=>r.pattern.startsWith('hooks.vespoli.me'));
 if(hooks.length!==1||hooks[0].pattern!=='hooks.vespoli.me/github'||hooks[0].zone_name!=='vespoli.me')throw Error('Webhook route must be exactly hooks.vespoli.me/github');
 // The dashboard host is routed whole (every path must hit the Access check); nothing else may claim it.
 const dash=c.routes.filter(r=>r.pattern.startsWith('caretaker.vespoli.me'));
 if(dash.length!==1||dash[0].pattern!=='caretaker.vespoli.me/*'||dash[0].zone_name!=='vespoli.me'||dash[0].custom_domain)throw Error('Dashboard route must be exactly caretaker.vespoli.me/*');
 // Activation values that are not secrets but are not known yet. Empty means the dashboard answers 403 to everyone.
 for(const [name,why] of [['ACCESS_AUD','Access application AUD tag'],['OWNER_EMAIL','owner identity'],['OBSERVATORY_APP_ID','observatory App id; GitHub lookups fail closed']])if(c.vars[name]==='')console.warn('Pending activation: '+name+' is empty ('+why+')'+(name==='OBSERVATORY_APP_ID'?'':'; the dashboard denies every request until it is set'));
 if(!c.d1_databases[1].database_id)console.warn('Pending activation: METRICS_DB has no database_id; set the id of D1 ghcaretaker-observatory created by infra');
}
const SECRETS_STORE='b6504fe2d5f64352954629bc7185fb79';
export const OBSERVATORY_CRONS=['7 * * * *','37 */6 * * *'];
const OBSERVATORY_SECRETS=['OBSERVATORY_WEBHOOK_SECRET','OBSERVATORY_WEBHOOK_SECRET_PREVIOUS','OBSERVATORY_APP_KEY','ALERT_WEBHOOK_URL'];
// The observatory is its own read-only GitHub App: its credentials must never share or resemble the MCP App's names.
export const RETIRED_OBSERVATORY_NAMES=/\b(?:CARETAKER_APP_KEY|CARETAKER_APP_ID|GITHUB_WEBHOOK_SECRET(?:_PREVIOUS)?)\b/;
export function retiredNamesInSource(dir=path.join(root,'src')){
 return fs.readdirSync(dir).filter(f=>f.endsWith('.mjs')&&RETIRED_OBSERVATORY_NAMES.test(fs.readFileSync(path.join(dir,f),'utf8')));
}
function checkObservatory(c){
 const retired=RETIRED_OBSERVATORY_NAMES.exec(JSON.stringify(c));
 if(retired)throw Error('Retired observatory credential name in configuration: '+retired[0]+' (use the OBSERVATORY_* names)');
 const inSource=retiredNamesInSource();
 if(inSource.length)throw Error('Retired observatory credential name in source: '+inSource.join(', '));
 if(typeof c.vars.OBSERVATORY_APP_ID!=='string'||!(c.vars.OBSERVATORY_APP_ID===''||/^(?:\d{1,12}|Iv[0-9A-Za-z.]{8,40})$/.test(c.vars.OBSERVATORY_APP_ID)))throw Error('OBSERVATORY_APP_ID must be empty (pending) or a numeric App id / Iv client id');
 if(c.vars.HOOKS_ORIGIN!=='https://hooks.vespoli.me'||c.vars.HOOKS_ORIGIN===c.vars.PUBLIC_ORIGIN)throw Error('Webhook origin must be https://hooks.vespoli.me and distinct from the MCP origin');
 for(const [name,class_name] of [['EVENT_LEDGER','EventLedger'],['COMMIT_LEDGER','CommitLedger']]){
  if(!c.durable_objects.bindings.some(x=>x.name===name&&x.class_name===class_name&&!x.script_name))throw Error('Ledger Durable Object binding required: '+name);
  if(!c.migrations?.some(m=>m.new_sqlite_classes?.includes(class_name)))throw Error('Ledger classes must be SQLite-backed: '+class_name);
 }
 if(!c.services.some(x=>x.binding==='BACKUP'&&x.service==='backup'&&x.entrypoint==='BackupIngest'))throw Error('Backup ingest service binding required');
 // Completeness crons (src/cron.mjs dispatches on these exact strings).
 if(JSON.stringify(c.triggers?.crons)!==JSON.stringify(OBSERVATORY_CRONS))throw Error('Cron triggers must be exactly '+OBSERVATORY_CRONS.join(', '));
 // The secondary anchor seam stays unbound until the backup service ships an anchor entrypoint (docs/adr/0003).
 if(c.services.some(x=>x.binding==='BACKUP_ANCHOR'&&x.entrypoint==='BackupIngest'))throw Error('BACKUP_ANCHOR must not reuse BackupIngest (its contract is capture only)');
 const bound=c.secrets_store_secrets||[];
 for(const name of OBSERVATORY_SECRETS)if(!bound.some(x=>x.binding===name&&x.secret_name===name&&x.store_id===SECRETS_STORE))throw Error('Secrets Store binding required: '+name);
 // Secrets come only from Secrets Store; a same-named plain var is refused.
 for(const name of OBSERVATORY_SECRETS)if(name in c.vars)throw Error('Secret must not be a plain var: '+name);
}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function checkDashboard(c){
 const v=c.vars;
 if(v.DASHBOARD_ORIGIN!=='https://caretaker.vespoli.me')throw Error('Dashboard origin must be https://caretaker.vespoli.me');
 if(new Set([v.DASHBOARD_ORIGIN,v.HOOKS_ORIGIN,v.PUBLIC_ORIGIN,v.AUTH_ORIGIN]).size!==4)throw Error('Dashboard origin must be distinct from every other origin');
 if(v.ACCESS_TEAM_DOMAIN!=='https://vespoli.cloudflareaccess.com')throw Error('Access team domain must be https://vespoli.cloudflareaccess.com');
 if(typeof v.ACCESS_AUD!=='string'||!(v.ACCESS_AUD===''||/^[0-9a-f]{64}$/.test(v.ACCESS_AUD)))throw Error('ACCESS_AUD must be empty (pending) or a 64-hex Access AUD tag');
 if(typeof v.OWNER_EMAIL!=='string'||!(v.OWNER_EMAIL===''||/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(v.OWNER_EMAIL)))throw Error('OWNER_EMAIL must be empty (pending) or one email address');
 const db=c.d1_databases[1];
 if(db.binding!=='METRICS_DB'||db.database_name!=='ghcaretaker-observatory'||db.migrations_dir!=='migrations-observatory')throw Error('Metrics database METRICS_DB (ghcaretaker-observatory, migrations-observatory) required');
 if(db.database_id!==undefined&&!UUID.test(db.database_id))throw Error('METRICS_DB database_id must be a D1 UUID');
 if(!c.services.some(x=>x.binding==='BACKUP_STATUS'&&x.service==='backup'&&x.entrypoint==='BackupStatus'))throw Error('Backup status service binding required');
 // Access configuration is not secret but must never come from Secrets Store or a second source.
 for(const name of ['ACCESS_AUD','OWNER_EMAIL','ACCESS_TEAM_DOMAIN','DASHBOARD_ORIGIN'])if((c.secrets_store_secrets||[]).some(x=>x.binding===name))throw Error('Dashboard var must be a plain var: '+name);
}
if(process.argv[1]===fileURLToPath(import.meta.url)){check(config(),process.argv.includes('--production'));console.log('Configuration checks passed');}
