import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export function config(){return JSON.parse(fs.readFileSync(path.join(root,'wrangler.jsonc'),'utf8'));}
export function check(c,production=false){
 if(c.name!=='ghcaretaker'||c.main!=='src/worker.mjs'||c.workers_dev!==false)throw Error('Unexpected Worker entrypoint or public workers.dev ingress');
 if(c.vars.GITHUB_OWNER!=='susanbeasles')throw Error('Personal owner must be susanbeasles');
 if(c.r2_buckets?.length!==1||c.r2_buckets[0].binding!=='AUDIT_BUCKET')throw Error('Expected dedicated audit bucket binding');
 if(c.d1_databases?.length!==1||c.d1_databases[0].binding!=='AUDIT_DB'||c.d1_databases[0].database_name!=='ghcaretaker-audit')throw Error('Expected dedicated audit database binding');
 if(!production)return;
 if(/REPLACE|example\.com/.test(JSON.stringify(c)))throw Error('Replace all production placeholders before enabling deployment');
 const origin=new URL(c.vars.PUBLIC_ORIGIN);if(origin.protocol!=='https:'||origin.origin!==c.vars.PUBLIC_ORIGIN)throw Error('PUBLIC_ORIGIN must be a bare HTTPS origin');
 const issuer=new URL(c.vars.AUTH_ISSUER),jwks=new URL(c.vars.AUTH_JWKS_URL);
 if(issuer.protocol!=='https:'||jwks.protocol!=='https:'||issuer.username||issuer.password||jwks.username||jwks.password)throw Error('HTTPS issuer/JWKS required');
 if(!c.vars.AUTH_SUBJECT||!/^\d+$/.test(c.vars.GITHUB_APP_ID)||!/^\d+$/.test(c.vars.GITHUB_INSTALLATION_ID))throw Error('Pinned owner subject, App ID and installation ID required');
 if(!/^[a-f0-9-]{36}$/i.test(c.d1_databases[0].database_id))throw Error('D1 database ID required');
 if(!c.routes?.some(r=>r.custom_domain===true&&r.pattern===origin.hostname))throw Error('Configured origin must have a matching custom-domain route');
 if(process.env.WORKER_ORIGIN&&process.env.WORKER_ORIGIN!==origin.origin)throw Error('GitHub WORKER_ORIGIN differs from PUBLIC_ORIGIN');
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {check(config(),process.argv.includes('--production'));console.log('Configuration checks passed');}
