import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {config,check} from './check-config.mjs';

const c = config();
check(c, true);
const cli = 'node_modules/wrangler/bin/wrangler.js';

const namespaces = JSON.parse(execFileSync(
  process.execPath,
  [cli, 'kv', 'namespace', 'list'],
  {encoding:'utf8', stdio:['ignore','pipe','inherit']}
));

const binding = c.kv_namespaces.find(x => x.binding === 'OAUTH_KV');
if (!binding) throw Error('Missing OAUTH_KV binding');

if (!binding.id) {
  const matches = namespaces.filter(x => x.title === 'ghcaretaker-oauth-kv');
  if (matches.length > 1) throw Error('Ambiguous OAuth namespace');
  if (matches.length === 1) {
    if (!/^[a-f0-9]{32}$/i.test(matches[0].id)) {
      throw Error('Invalid namespace ID');
    }
    binding.id = matches[0].id;
    fs.writeFileSync('wrangler.jsonc', JSON.stringify(c, null, 2) + '\n');
    console.log('Reusing existing OAuth namespace');
  }
}

execFileSync(process.execPath, [cli, 'deploy'], {stdio:'inherit'});
execFileSync(process.execPath, [
  cli, 'd1', 'migrations', 'apply', 'ghcaretaker-audit', '--remote'
], {stdio:'inherit'});
