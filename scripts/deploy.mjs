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


// Explicit R2 provisioning: never inherit an absent audit binding.
const auditBucket = c.r2_buckets.find(x => x.binding === 'AUDIT_BUCKET');
if (!auditBucket) throw Error('Missing AUDIT_BUCKET binding');

const bucketName = 'ghcaretaker-audit';
const bucketListing = execFileSync(
  process.execPath,
  [cli, 'r2', 'bucket', 'list'],
  {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    env: {...process.env, NO_COLOR: '1', FORCE_COLOR: '0'}
  }
);

const bucketNames = [...bucketListing.matchAll(
  /^name:\s+([a-z0-9-]+)\s*$/gm
)].map(match => match[1]);

if (!bucketNames.includes(bucketName)) {
  execFileSync(
    process.execPath,
    [cli, 'r2', 'bucket', 'create', bucketName],
    {stdio: 'inherit'}
  );
}

auditBucket.bucket_name = bucketName;
fs.writeFileSync('wrangler.jsonc', JSON.stringify(c, null, 2) + '\n');
console.log('Explicitly bound audit bucket:', bucketName);

execFileSync(process.execPath, [cli, 'deploy'], {stdio:'inherit'});
execFileSync(process.execPath, [
  cli, 'd1', 'migrations', 'apply', 'ghcaretaker-audit', '--remote'
], {stdio:'inherit'});
