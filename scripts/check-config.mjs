import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export function config(){return JSON.parse(fs.readFileSync(path.join(root,'wrangler.jsonc'),'utf8'));}
export function check(c,production=false){
 if(c.name!=='ghcaretaker'||c.main!=='src/index.mjs'||c.workers_dev!==false)throw Error('Unexpected Worker entrypoint or workers.dev ingress');
 if(c.vars.GITHUB_OWNER!=='susanbeasles'||c.vars.GITHUB_OWNER_ID!=='215839550')throw Error('Personal owner must remain pinned');
 if(c.r2_buckets?.length!==2||!c.r2_buckets.some(b=>b.binding==='AUDIT_BUCKET'&&b.bucket_name==='ghcaretaker-audit'))throw Error('Dedicated audit bucket required');
 if(!c.r2_buckets.some(b=>b.binding==='EVENTS'&&b.bucket_name==='github-events'))throw Error('github-events capture bucket required');
 if(c.preview_urls!==false)throw Error('Preview URLs must stay disabled');
 if(c.d1_databases?.length!==1||c.d1_databases[0].binding!=='AUDIT_DB'||c.d1_databases[0].database_name!=='ghcaretaker-audit')throw Error('Dedicated audit database required');
 if(!c.durable_objects?.bindings?.some(x=>x.name==='APP_VAULT'&&x.class_name==='AppVault'))throw Error('Credential vault required');
 if(c.vars.AUTH_ORIGIN!=='https://control.vespoli.me'||!c.services?.some(x=>x.binding==='AUTH_GATEWAY'&&x.service==='personal-control'))throw Error('Central auth gate required');
 checkObservatory(c);
 if(!production)return;
 if(/REPLACE|example\.com/.test(JSON.stringify(c)))throw Error('Production placeholders are forbidden');
 if(c.vars.PUBLIC_ORIGIN!=='https://mcp.vespoli.me'||c.vars.MCP_PATH!=='/ghcaretaker')throw Error('Unexpected production endpoint');
 if(!c.routes?.some(r=>r.pattern==='mcp.vespoli.me/ghcaretaker*'&&r.zone_name==='vespoli.me'))throw Error('Scoped production route required');
 if(c.routes.some(r=>r.custom_domain||r.pattern==='mcp.vespoli.me/*'))throw Error('Do not take over the shared MCP hostname');
 // The webhook host is routed for exactly one path; no wildcard, so nothing else on hooks.vespoli.me reaches this Worker.
 const hooks=c.routes.filter(r=>r.pattern.startsWith('hooks.vespoli.me'));
 if(hooks.length!==1||hooks[0].pattern!=='hooks.vespoli.me/github'||hooks[0].zone_name!=='vespoli.me')throw Error('Webhook route must be exactly hooks.vespoli.me/github');
}
const SECRETS_STORE='b6504fe2d5f64352954629bc7185fb79';
const OBSERVATORY_SECRETS=['GITHUB_WEBHOOK_SECRET','GITHUB_WEBHOOK_SECRET_PREVIOUS','CARETAKER_APP_KEY','ALERT_WEBHOOK_URL'];
function checkObservatory(c){
 if(c.vars.HOOKS_ORIGIN!=='https://hooks.vespoli.me'||c.vars.HOOKS_ORIGIN===c.vars.PUBLIC_ORIGIN)throw Error('Webhook origin must be https://hooks.vespoli.me and distinct from the MCP origin');
 for(const [name,class_name] of [['EVENT_LEDGER','EventLedger'],['COMMIT_LEDGER','CommitLedger']]){
  if(!c.durable_objects.bindings.some(x=>x.name===name&&x.class_name===class_name&&!x.script_name))throw Error('Ledger Durable Object binding required: '+name);
  if(!c.migrations?.some(m=>m.new_sqlite_classes?.includes(class_name)))throw Error('Ledger classes must be SQLite-backed: '+class_name);
 }
 if(!c.services.some(x=>x.binding==='BACKUP'&&x.service==='backup'&&x.entrypoint==='BackupIngest'))throw Error('Backup ingest service binding required');
 const bound=c.secrets_store_secrets||[];
 for(const name of OBSERVATORY_SECRETS)if(!bound.some(x=>x.binding===name&&x.secret_name===name&&x.store_id===SECRETS_STORE))throw Error('Secrets Store binding required: '+name);
 // Secrets come only from Secrets Store; a same-named plain var is refused.
 for(const name of OBSERVATORY_SECRETS)if(name in c.vars)throw Error('Secret must not be a plain var: '+name);
}
if(process.argv[1]===fileURLToPath(import.meta.url)){check(config(),process.argv.includes('--production'));console.log('Configuration checks passed');}
