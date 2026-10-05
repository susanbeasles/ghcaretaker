import {test} from 'node:test';
import assert from 'node:assert/strict';
import {rulesets} from '../scripts/rulesets.mjs';
import {check,config} from '../scripts/check-config.mjs';
test('owner exemption never weakens separate main/signature/tag rules',()=>{
 const rs=rulesets(42),main=rs.find(r=>r.name==='ghcaretaker-main-integrity'),review=rs.find(r=>r.name==='ghcaretaker-main-review'),tags=rs.find(r=>r.target==='tag');
 assert.deepEqual(main.bypass_actors,[]);assert.deepEqual(tags.bypass_actors,[]);
 assert.deepEqual(main.conditions.ref_name.include,['refs/heads/main','~DEFAULT_BRANCH']);
 assert.ok(main.rules.some(r=>r.type==='required_signatures'));assert.ok(main.rules.some(r=>r.type==='non_fast_forward'));
 assert.equal(review.bypass_actors[0].actor_type,'User');assert.equal(review.bypass_actors[0].bypass_mode,'exempt');
 const pr=review.rules.find(r=>r.type==='pull_request');assert.equal(pr.parameters.required_approving_review_count,1);assert.equal(pr.parameters.require_last_push_approval,true);
 assert.throws(()=>rulesets(NaN));
});
test('production check refuses placeholders and unmatched origins; accepts a configured deployment',()=>{
 const c=config();assert.throws(()=>check(c,true));
 const ready=structuredClone(c);ready.vars={PUBLIC_ORIGIN:'https://caretaker.test',GITHUB_OWNER:'susanbeasles',GITHUB_APP_ID:'123',GITHUB_INSTALLATION_ID:'456',AUTH_ISSUER:'https://auth.test/',AUTH_JWKS_URL:'https://auth.test/keys',AUTH_SUBJECT:'owner'};ready.d1_databases[0].database_id='11111111-1111-4111-8111-111111111111';ready.routes=[{pattern:'caretaker.test',custom_domain:true}];
 assert.doesNotThrow(()=>check(ready,true));ready.routes=[];assert.throws(()=>check(ready,true));
});
