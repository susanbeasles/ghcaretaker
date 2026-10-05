import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {check,config} from './check-config.mjs';
check(config());
for(const dir of ['src','scripts','test'])for(const f of fs.readdirSync(dir))if(f.endsWith('.mjs'))execFileSync(process.execPath,['--check',path.join(dir,f)],{stdio:'inherit'});
const allowed=new Set(['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1','actions/setup-node@820762786026740c76f36085b0efc47a31fe5020','cloudflare/wrangler-action@953926a2e2182532811c01a25e53647d93bf07c0']);
for(const file of fs.readdirSync('.github/workflows')){
 const source=fs.readFileSync(path.join('.github/workflows',file),'utf8');
 if(/pull_request_target:|workflow_run:/.test(source))throw Error('Privileged downstream PR execution is not allowed');
 for(const match of source.matchAll(/\buses:\s*([^\s#]+)/g))if(!allowed.has(match[1]))throw Error('Action is not an approved SHA pin: '+match[1]);
}
console.log('Source and action policy checks passed');
