import {execFileSync} from 'node:child_process';
import {config,check} from './check-config.mjs';
check(config(), true);
const cli = 'node_modules/wrangler/bin/wrangler.js';
// Infrastructure IDs are versioned explicitly. OAuth belongs to the shared gate.
execFileSync(process.execPath, [cli, 'deploy'], {stdio:'inherit'});
execFileSync(process.execPath, [cli, 'd1', 'migrations', 'apply', 'ghcaretaker-audit', '--remote'], {stdio:'inherit'});
