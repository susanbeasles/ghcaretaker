import {execFileSync} from 'node:child_process';
import {config,check} from './check-config.mjs';
check(config(),true);
const cli='node_modules/wrangler/bin/wrangler.js';
// Wrangler provisions missing R2, D1 and KV bindings during deployment.
// Audit calls fail closed while migrations are pending; no GitHub mutation can pass.
execFileSync(process.execPath,[cli,'deploy'],{stdio:'inherit'});
execFileSync(process.execPath,[cli,'d1','migrations','apply','ghcaretaker-audit','--remote'],{stdio:'inherit'});
