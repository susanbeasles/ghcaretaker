import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
export function rulesets(ownerId){
 if(!Number.isSafeInteger(ownerId)||ownerId<1)throw Error('A verified numeric GitHub User ID is required');
 const main={ref_name:{include:['refs/heads/main','~DEFAULT_BRANCH'],exclude:[]}};
 const refRule=type=>({type,...(type==='update'?{parameters:{update_allows_fetch_and_merge:false}}:{})});
 const actor=mode=>[{actor_id:ownerId,actor_type:'User',bypass_mode:mode}];
 return [
  {name:'ghcaretaker-main-integrity',target:'branch',enforcement:'active',bypass_actors:[],conditions:main,rules:[refRule('deletion'),refRule('non_fast_forward'),refRule('required_signatures')]},
  {name:'ghcaretaker-main-review',target:'branch',enforcement:'active',bypass_actors:actor('exempt'),conditions:main,rules:[refRule('creation'),refRule('update'),{type:'pull_request',parameters:{required_approving_review_count:1,dismiss_stale_reviews_on_push:true,require_code_owner_review:false,require_last_push_approval:true,required_review_thread_resolution:true,allowed_merge_methods:['merge','squash','rebase']}},{type:'required_status_checks',parameters:{required_status_checks:[{context:'Validate',integration_id:15368}],strict_required_status_checks_policy:true,do_not_enforce_on_create:false}}]},
  {name:'ghcaretaker-all-branches-owner-control',target:'branch',enforcement:'active',bypass_actors:actor('always'),conditions:{ref_name:{include:['~ALL'],exclude:[]}},rules:[refRule('creation'),refRule('update'),refRule('deletion')]},
  {name:'ghcaretaker-all-tags-integrity',target:'tag',enforcement:'active',bypass_actors:[],conditions:{ref_name:{include:['~ALL'],exclude:[]}},rules:[refRule('update'),refRule('deletion'),refRule('non_fast_forward')]}
 ];
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const ownerId=Number(process.argv[2]),dest=process.argv[3]||'.bootstrap/rulesets';fs.mkdirSync(dest,{recursive:true});
 for(const r of rulesets(ownerId))fs.writeFileSync(path.join(dest,r.name+'.json'),JSON.stringify(r,null,2)+'\n');
 console.log('Wrote 4 rulesets to '+dest);
}
