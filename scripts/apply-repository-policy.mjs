import {execFileSync} from 'node:child_process';
import {rulesets} from './rulesets.mjs';
const repo='susanbeasles/ghcaretaker',version='2026-03-10';
function gh(args,body){return execFileSync('gh',args,{encoding:'utf8',input:body?JSON.stringify(body):undefined,stdio:['pipe','pipe','pipe']});}
function api(method,endpoint,body){const args=['api','--method',method,'-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: '+version,endpoint];if(body)args.push('--input','-');return gh(args,body);}
const me=JSON.parse(api('GET','user'));if(me.login!=='susanbeasles')throw Error('Active gh account must be susanbeasles');
const user=JSON.parse(api('GET','users/susanbeasles'));if(user.id!==me.id)throw Error('Owner identity mismatch');
const metadata=JSON.parse(api('GET','repos/'+repo));if(metadata.owner.login!=='susanbeasles'||metadata.default_branch!=='main')throw Error('Unexpected repository owner/default branch');
api('PUT','repos/'+repo+'/immutable-releases');
api('PUT','repos/'+repo+'/actions/permissions',{enabled:true,allowed_actions:'selected',sha_pinning_required:true});
api('PUT','repos/'+repo+'/actions/permissions/selected-actions',{github_owned_allowed:true,verified_allowed:false,patterns_allowed:['cloudflare/wrangler-action@953926a2e2182532811c01a25e53647d93bf07c0']});
api('PUT','repos/'+repo+'/actions/permissions/workflow',{default_workflow_permissions:'read',can_approve_pull_request_reviews:false});
// Avoid accidentally adding overlapping duplicate rulesets on retries.
const existing=JSON.parse(api('GET','repos/'+repo+'/rulesets?includes_parents=false&per_page=100'));
if(existing.length>=100)throw Error('Too many rulesets for safe single-page reconciliation');
for(const desired of rulesets(user.id)){
 const matches=existing.filter(r=>r.name===desired.name);if(matches.length>1)throw Error('Duplicate ruleset name requires manual reconciliation: '+desired.name);
 const endpoint='repos/'+repo+'/rulesets'+(matches.length?'/'+matches[0].id:'');
 const applied=JSON.parse(api(matches.length?'PUT':'POST',endpoint,desired));
 const actual=JSON.parse(api('GET','repos/'+repo+'/rulesets/'+applied.id));
 for(const key of ['target','enforcement','bypass_actors','conditions','rules']){
  // API may normalize object-key order and append defaults; verify desired fields recursively.
  const contains=(a,b)=>Array.isArray(b)?Array.isArray(a)&&a.length===b.length&&b.every(v=>a.some(item=>contains(item,v))):b&&typeof b==='object'?a&&Object.entries(b).every(([k,v])=>contains(a[k],v)):a===b;
  if(!contains(actual[key],desired[key]))throw Error('Ruleset verification failed: '+desired.name+' '+key);
 }
 console.log('Verified '+desired.name+' ('+applied.id+')');
}
const immutable=JSON.parse(api('GET','repos/'+repo+'/immutable-releases'));if(!immutable.enabled)throw Error('Release immutability not enabled');
const actions=JSON.parse(api('GET','repos/'+repo+'/actions/permissions'));if(!actions.enabled||actions.allowed_actions!=='selected'||!actions.sha_pinning_required)throw Error('Actions policy verification failed');
console.log('Repository policy and release immutability verified');
