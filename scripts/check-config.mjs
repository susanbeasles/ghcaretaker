import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export function config(){return JSON.parse(fs.readFileSync(path.join(root,'wrangler.jsonc'),'utf8'));}
export function check(c,production=false){
 if(c.name!=='ghcaretaker'||c.main!=='src/index.mjs'||c.workers_dev!==false)throw Error('Unexpected Worker entrypoint or workers.dev ingress');
 if(c.vars.GITHUB_OWNER!=='susanbeasles'||c.vars.GITHUB_OWNER_ID!=='215839550')throw Error('Personal owner must remain pinned');
 if(c.r2_buckets?.length!==1||c.r2_buckets[0].binding!=='AUDIT_BUCKET')throw Error('Dedicated audit bucket required');
 if(c.d1_databases?.length!==1||c.d1_databases[0].binding!=='AUDIT_DB'||c.d1_databases[0].database_name!=='ghcaretaker-audit')throw Error('Dedicated audit database required');
 if(!c.durable_objects?.bindings?.some(x=>x.name==='APP_VAULT'&&x.class_name==='AppVault'))throw Error('Credential vault required');
 if(c.vars.AUTH_ORIGIN!=='https://control.vespoli.me'||!c.services?.some(x=>x.binding==='AUTH_GATEWAY'&&x.service==='personal-control'))throw Error('Central auth gate required');
 if(!production)return;
 if(/REPLACE|example\.com/.test(JSON.stringify(c)))throw Error('Production placeholders are forbidden');
 if(c.vars.PUBLIC_ORIGIN!=='https://mcp.vespoli.me'||c.vars.MCP_PATH!=='/ghcaretaker')throw Error('Unexpected production endpoint');
 if(!c.routes?.some(r=>r.pattern==='mcp.vespoli.me/ghcaretaker*'&&r.zone_name==='vespoli.me'))throw Error('Scoped production route required');
 if(c.routes.some(r=>r.custom_domain||r.pattern==='mcp.vespoli.me/*'))throw Error('Do not take over the shared MCP hostname');
}
if(process.argv[1]===fileURLToPath(import.meta.url)){check(config(),process.argv.includes('--production'));console.log('Configuration checks passed');}
