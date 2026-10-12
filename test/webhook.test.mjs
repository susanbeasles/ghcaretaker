import {test} from 'node:test';
import assert from 'node:assert/strict';
import {VaultCore} from '../src/vault-core.mjs';
import {manifest} from '../src/manifest.mjs';

const env={AUTH_ORIGIN:'https://control.example.test',GITHUB_OWNER:'personal',GITHUB_OWNER_ID:'42'};
const secret='synthetic-webhook-fixture-only';
const account={id:42,login:'personal',type:'User'};
const installation={id:123,app_id:456,account};
function fixture(){
 const m=new Map([['app',{id:456,webhook_secret:secret}],['phase','installed'],['installation','123']]);
 const storage={get:async k=>structuredClone(m.get(k)),put:async(k,v)=>{m.set(k,structuredClone(v));},transaction:async f=>f(storage)};
 return {m,core:new VaultCore(storage,env,async()=>{throw Error('No provider call permitted');})};
}
function payload(patch={}){return {action:'completed',installation,repository:{id:987,name:'safe',full_name:'personal/safe',owner:account},workflow_run:{id:543,status:'completed',conclusion:'success'},...patch};}
async function request(value=payload(),{event='workflow_run',id=crypto.randomUUID(),key=secret,raw,headers={},method='POST'}={}){
 const bytes=new TextEncoder().encode(raw??JSON.stringify(value));
 const signingKey=await crypto.subtle.importKey('raw',new TextEncoder().encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const signature=Buffer.from(await crypto.subtle.sign('HMAC',signingKey,bytes)).toString('hex');
 return new Request(env.AUTH_ORIGIN+'/webhooks/github/caretaker',{method,headers:{'content-type':'application/json','x-github-event':event,'x-github-delivery':id,'x-hub-signature-256':'sha256='+signature,...headers},...(method==='POST'?{body:bytes}:{})});
}
test('central manifest subscribes to domain events without new permissions',()=>{
 const m=manifest({...env,PUBLIC_ORIGIN:'https://legacy.example.test',MCP_PATH:'/ghcaretaker'});
 assert.deepEqual(m.hook_attributes,{active:true,url:env.AUTH_ORIGIN+'/webhooks/github/caretaker'});
 assert.ok(m.default_events.includes('workflow_run'));assert.ok(!m.default_events.includes('installation'));
 assert.equal(m.default_permissions.contents,'read');assert.equal(m.default_permissions.actions,'read');
});
test('raw-byte HMAC receipt persists only bounded safe metadata and never calls GitHub',async()=>{
 const {core,m}=fixture(),id=crypto.randomUUID();
 const value=payload({issue:{body:'PRIVATE BODY'},token:'DO NOT RETAIN'});
 const response=await core.webhook(await request(value,{id}));assert.equal(response.status,202);
 const status=await core.status();assert.equal(status.webhook.configured,true);assert.equal(status.webhook.accepted_count,1);
 assert.deepEqual(status.webhook.last_delivery,{id,event:'workflow_run',action:'completed',repository:'personal/safe',received_at:status.webhook.last_delivery.received_at});
 assert.equal(status.webhook.recent.length,1);
 const stored=JSON.stringify([...m.entries()].filter(([k])=>k!=='app'));assert.ok(!stored.includes('PRIVATE BODY'));assert.ok(!stored.includes('DO NOT RETAIN'));assert.ok(!JSON.stringify(status).includes(secret));
});
test('signature mismatch, altered bytes, foreign owner/installation and event confusion are denied',async()=>{
 const {core}=fixture();
 for(const r of [await request(payload(),{key:'wrong'}),await request(payload({installation:{...installation,id:999}})),await request(payload({repository:{id:987,name:'safe',full_name:'other/safe',owner:{...account,id:43}}})),await request(payload(),{event:'push'})])assert.equal((await core.webhook(r)).status,403);
 const signed=await request();const altered=new Request(signed.url,{method:'POST',headers:signed.headers,body:JSON.stringify(payload())+' '});assert.equal((await core.webhook(altered)).status,403);
 assert.equal((await core.status()).webhook.accepted_count,0);
});
test('duplicate deliveries do not increment receipts; conflicting reused ID is rejected',async()=>{
 const {core}=fixture(),id=crypto.randomUUID();
 assert.equal((await core.webhook(await request(payload(),{id}))).status,202);
 const duplicate=await core.webhook(await request(payload(),{id}));assert.equal(duplicate.status,200);assert.equal((await duplicate.json()).duplicate,true);
 assert.equal((await core.webhook(await request(payload({action:'requested'}),{id}))).status,409);
 assert.equal((await core.status()).webhook.accepted_count,1);
});
test('suspension and deletion fail closed; later unsigned or signed unsuspend does not restore authority',async()=>{
 for(const action of ['suspend','deleted']){
  const {core,m}=fixture();assert.equal((await core.webhook(await request({action,installation},{event:'installation'}))).status,202);
  assert.equal(m.get('phase'),'installation-review-required');await assert.rejects(core.config());await assert.rejects(core.appJWT());
  assert.equal((await core.webhook(await request({action:'unsuspend',installation},{event:'installation'}))).status,202);assert.equal(m.get('phase'),'installation-review-required');
 }
});
test('new installation event is observed but cannot automatically enroll or replace installation',async()=>{
 const {core,m}=fixture();m.set('phase','created');m.delete('installation');
 assert.equal((await core.webhook(await request({action:'created',installation},{event:'installation'}))).status,202);
 assert.equal(m.get('phase'),'created');assert.equal(m.has('installation'),false);
 const other=await request({action:'created',installation:{...installation,account:{id:1,type:'User',login:'other'}}},{event:'installation'});assert.equal((await core.webhook(other)).status,403);
});
test('route, method, signature header, encoding, JSON and payload byte limits reject',async()=>{
 const {core}=fixture();
 const cases=[['GET',405],['bad-type',415],['bad-signature',403],['bad-json',400],['too-large',413],['encoding',415],['route',404]];
 for(const [kind,code] of cases){
  let r=await request(payload(),kind==='GET'?{method:'GET'}:kind==='bad-type'?{headers:{'content-type':'text/plain'}}:kind==='bad-signature'?{headers:{'x-hub-signature-256':'sha256=zz'}}:kind==='bad-json'?{raw:'{'}:kind==='too-large'?{raw:' '.repeat(262145)}:kind==='encoding'?{headers:{'content-encoding':'gzip'}}:{});
  if(kind==='route')r=new Request(env.AUTH_ORIGIN+'/arbitrary',r);
  assert.equal((await core.webhook(r)).status,code,kind);
 }
 assert.equal((await core.status()).webhook.accepted_count,0);
});
test('missing vault secret reports unavailable and cannot accept a webhook',async()=>{
 const {core,m}=fixture();m.set('app',{id:456});assert.equal((await core.status()).webhook.configured,false);assert.equal((await core.webhook(await request())).status,503);
});
test('receipt history is bounded without dropping deduplication records within the retention window',async()=>{
 const {core}=fixture();let first;
 for(let i=0;i<105;i++){const id=crypto.randomUUID();first??=id;assert.equal((await core.webhook(await request(payload({action:'completed',workflow_run:{id:i+1}}),{id}))).status,202);}
 assert.equal((await core.status()).webhook.recent.length,20);assert.equal((await core.status()).webhook.accepted_count,105);
 assert.equal((await core.webhook(await request(payload({action:'completed',workflow_run:{id:1}}),{id:first}))).status,200);
});
test('a signed prefix from a stalled body is rejected at the deadline without invalidating authority',{timeout:15000},async()=>{
 const {core,m}=fixture(),signed=await request({action:'suspend',installation},{event:'installation'}),bytes=new Uint8Array(await signed.arrayBuffer());let cancelled=false;
 const stalled=new Request(signed.url,{method:'POST',headers:signed.headers,duplex:'half',body:new ReadableStream({start(controller){controller.enqueue(bytes);},cancel(){cancelled=true;}})});
 const response=await core.webhook(stalled);assert.equal(response.status,408);assert.equal(cancelled,true);assert.equal(m.get('phase'),'installed');assert.equal((await core.status()).webhook.accepted_count,0);
});
test('signed invalidation survives ordinary receipt capacity and delivery-ID collisions',async()=>{
 for(const collision of [false,true]){
  const {core,m}=fixture(),id=crypto.randomUUID();
  m.set('webhook:ledger',{count:1024,recent:[],seen:Array.from({length:1024},(_,i)=>({id:i===0&&collision?id:crypto.randomUUID(),event:'workflow_run',digest:'0'.repeat(64),at:Date.now()}))});
  const response=await core.webhook(await request({action:'suspend',installation},{id,event:'installation'}));assert.equal(response.status,202);assert.equal((await response.json()).metadata_limited,true);
  assert.equal(m.get('phase'),'installation-review-required');assert.equal(m.get('installation:revision'),1);assert.equal(m.get('webhook:ledger').seen.length,1024);
  const duplicate=await core.webhook(await request({action:'suspend',installation},{id,event:'installation'}));assert.equal(duplicate.status,200);assert.equal(m.get('installation:revision'),1);
 }
});
test('signed suspension before the first installation invalidates initial verification too',async()=>{
 const {core,m}=fixture();m.delete('installation');m.set('phase','created');
 const response=await core.webhook(await request({action:'suspend',installation},{event:'installation'}));assert.equal(response.status,202);assert.equal(m.get('phase'),'installation-review-required');assert.equal(m.get('installation:revision'),1);
});
