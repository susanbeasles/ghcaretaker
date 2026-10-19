import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {rulesets} from '../scripts/rulesets.mjs';
import {check,config} from '../scripts/check-config.mjs';
test('all tags require creation authorization and remain immutable without new bypass actors',()=>{
 const generated=rulesets(42).find(r=>r.target==='tag');
 const checked=JSON.parse(fs.readFileSync(new URL('../config/rulesets/ghcaretaker-all-tags-integrity.json',import.meta.url),'utf8'));
 for(const tags of [generated,checked]){
  assert.equal(tags.enforcement,'active');
  assert.deepEqual(tags.conditions,{ref_name:{include:['~ALL'],exclude:[]}});
  assert.deepEqual(tags.bypass_actors,[]);
  assert.deepEqual(tags.rules.map(r=>r.type),['creation','update','deletion','non_fast_forward']);
  assert.deepEqual(tags.rules.find(r=>r.type==='update').parameters,{update_allows_fetch_and_merge:false});
 }
 assert.deepEqual(generated,checked);
});
test('owner exemption never weakens separate main/signature/tag rules',()=>{
 const rs=rulesets(42),main=rs.find(r=>r.name==='ghcaretaker-main-integrity'),review=rs.find(r=>r.name==='ghcaretaker-main-review'),tags=rs.find(r=>r.target==='tag');
 assert.deepEqual(main.bypass_actors,[]);assert.deepEqual(tags.bypass_actors,[]);
 assert.deepEqual(main.conditions.ref_name.include,['refs/heads/main','~DEFAULT_BRANCH']);
 assert.ok(main.rules.some(r=>r.type==='required_signatures'));assert.ok(main.rules.some(r=>r.type==='non_fast_forward'));
 assert.equal(review.bypass_actors[0].actor_type,'User');assert.equal(review.bypass_actors[0].bypass_mode,'exempt');
 const pr=review.rules.find(r=>r.type==='pull_request');assert.equal(pr.parameters.required_approving_review_count,1);assert.equal(pr.parameters.require_last_push_approval,true);
 assert.throws(()=>rulesets(NaN));
});
test('production check enforces the owner, vault and scoped shared-host route',()=>{
 const c=config();assert.doesNotThrow(()=>check(c,true));
 for(const patch of [{PUBLIC_ORIGIN:'https://other.test'},{GITHUB_OWNER_ID:'42'},{MCP_PATH:'/mcp'}]){
  const x=structuredClone(c);Object.assign(x.vars,patch);assert.throws(()=>check(x,true));
 }
 const x=structuredClone(c);x.routes.push({pattern:'mcp.vespoli.me/*'});assert.throws(()=>check(x,true));
});
