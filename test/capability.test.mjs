import {test} from 'node:test';
import assert from 'node:assert/strict';
import {CaretakerCore} from '../src/capability.mjs';
import {github} from '../src/github.mjs';
import {permissions} from '../src/policy.mjs';
const env={PUBLIC_ORIGIN:'https://legacy.test',AUTH_ORIGIN:'https://control.test',MCP_PATH:'/ghcaretaker',GITHUB_OWNER:'personal',GITHUB_OWNER_ID:'42'};
const session={profile:'caretaker',scopes:['github:read'],repos:['personal/safe'],expires:Date.now()+60000};
function auditEnv(){let reads=0;const e={...env,AUDIT_BUCKET:{put:async()=>{}},AUDIT_DB:{prepare(){return {bind(){return this;},async run(){},async all(){reads++;return {results:[{private:'other repository'}]};},async first(){reads++;throw Error('must not read');}};}}};return {env:e,reads:()=>reads};}
test('repository-scoped MCP sessions cannot read account-wide audit records',async()=>{
 const f=auditEnv(),core=new CaretakerCore(f.env);
 for(const [name,args] of [['audit_recent',{}],['audit_record',{id:'a'.repeat(8)+'-aaaa-aaaa-aaaa-'+'a'.repeat(12)}]]){
  const result=await core.callTool(name,args,session);assert.equal(result.result.isError,true);assert.match(result.result.content[0].text,/Audit access requires the owner-wide repository grant/);
 }
 assert.equal(f.reads(),0);
 const owner=await core.callTool('audit_recent',{}, {...session,repos:['personal/*']});assert.equal(owner.result.isError,false);assert.equal(f.reads(),1);
});
test('malformed or foreign repository sessions fail closed before capability work',async()=>{
 const core=new CaretakerCore(env);
 for(const invalid of [null,{}, {...session,scopes:null},{...session,expires:undefined},{...session,expires:NaN},{...session,repos:['other/safe']},{...session,repos:['personal/..']}]){
  const response=await core.mcp(new Request(env.AUTH_ORIGIN+'/mcp/caretaker',{method:'POST',body:'{}'}),invalid);assert.equal(response.status,403);
 }
});
async function fixture(){
 const {env:e}=auditEnv();return {...e,GITHUB_APP_ID:'456',GITHUB_INSTALLATION_ID:'123',APP_VAULT:{idFromName:()=> 'app',get:()=>({appJWT:async()=> 'synthetic-app-jwt'})}};
}
test('installation token is narrowed to granted repositories and list results cannot escape the grant',async()=>{
 const e=await fixture(),calls=[];
 const result=await github(e,{subject:'42',scopes:['github:read'],repos:['personal/safe']},'list_repositories',{},'fixture',async(url,options)=>{
  calls.push(url);
  if(url.endsWith('/app/installations/123'))return Response.json({id:123,app_id:456,account:{id:42,login:'personal',type:'User'}});
  if(url.endsWith('/access_tokens')){const body=JSON.parse(options.body);assert.deepEqual(body.repositories,['safe']);return Response.json({token:'synthetic-token',expires_at:new Date(Date.now()+60000).toISOString(),permissions:body.permissions});}
  return Response.json({total_count:2,repositories:[{id:1,name:'safe',full_name:'personal/safe',owner:{id:42,login:'personal',type:'User'}},{id:2,name:'private',full_name:'personal/private',owner:{id:42,login:'personal',type:'User'}}]});
 });
 assert.equal(result.data.repositories.length,1);assert.equal(result.data.repositories[0].name,'safe');assert.equal(result.data.total_count,1);assert.equal(calls.length,3);
});
test('numeric owner substitution and repository outside grant stop before token issuance',async()=>{
 const e=await fixture();let calls=0;
 await assert.rejects(github(e,{scopes:['github:read'],repos:['personal/safe']},'get_repository',{repo:'other'},'fixture',async()=>{calls++;throw Error('must not fetch');}));assert.equal(calls,0);
 await assert.rejects(github(e,{scopes:['github:read'],repos:['personal/safe']},'get_repository',{repo:'safe'},'fixture',async()=>{calls++;return Response.json({id:123,app_id:456,account:{id:43,login:'personal',type:'User'}});}));assert.equal(calls,1);
});
