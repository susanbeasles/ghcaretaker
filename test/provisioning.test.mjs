import {test} from 'node:test';
import assert from 'node:assert/strict';
import {VaultCore,normalizeKey} from '../src/vault-core.mjs';
import {manifest,assertApp} from '../src/manifest.mjs';
import {permissions} from '../src/policy.mjs';
import {appJWT} from '../src/crypto.mjs';
const env={PUBLIC_ORIGIN:'https://mcp.vespoli.me',MCP_PATH:'/ghcaretaker',GITHUB_OWNER:'susanbeasles',GITHUB_OWNER_ID:'215839550',AUDIT_BUCKET:{put:async()=>{}},AUDIT_DB:{prepare:()=>({bind(){return this;},run:async()=>{}})}};
function storage(){const m=new Map();const s={get:async k=>m.get(k),put:async(k,v)=>m.set(k,structuredClone(v)),delete:async k=>m.delete(k),transaction:async f=>f(s)};return s;}
function app(){return {id:123,slug:'personal-caretaker',owner:{id:215839550,login:'susanbeasles',type:'User'},permissions:{...permissions},client_id:'client',client_secret:'hidden'};}
async function pem(){const k=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);const bytes=await crypto.subtle.exportKey('pkcs8',k.privateKey);return '-----BEGIN PRIVATE KEY-----\n'+Buffer.from(bytes).toString('base64')+'\n-----END PRIVATE KEY-----';}
test('manifest has exact collaboration-only permissions and server callbacks',()=>{
 const m=manifest(env);assert.equal(m.public,false);assert.deepEqual(m.default_permissions,permissions);assert.equal(m.redirect_url,'https://mcp.vespoli.me/ghcaretaker/setup/callback');assert.equal(m.hook_attributes.active,false);assert.deepEqual(m.default_events,[]);
 assert.doesNotThrow(()=>assertApp(app(),env));
 for(const bad of [{...app(),owner:{id:1,type:'User',login:'susanbeasles'}},{...app(),permissions:{...permissions,contents:'write'}},{...app(),permissions:{...permissions,administration:'read'}}])assert.throws(()=>assertApp(bad,env));
});
test('conversion is owner-bound, single-use, persists secrets without returning them',async()=>{
 const a={...app(),pem:await pem()},s=storage();let calls=0;
 const v=new VaultCore(s,env,async(url,options)=>{calls++;assert.equal(options.redirect,'error');assert.equal(url,'https://api.github.com/app-manifests/one-code/conversions');return Response.json(a);});
 const state=await v.begin('owner');await assert.rejects(v.convert('one-code',state,'attacker'));assert.equal(calls,0);
 const status=await v.convert('one-code',state,'owner');assert.equal(status.phase,'created');assert.ok(!JSON.stringify(status).includes('hidden'));assert.ok(!JSON.stringify(status).includes('PRIVATE KEY'));
 await assert.rejects(v.convert('one-code',state,'owner'));await assert.rejects(v.begin('owner'));assert.equal(calls,1);
 assert.equal((await v.appJWT()).split('.').length,3);
});
test('permission escalation quarantines registration and prevents credential use',async()=>{
 const s=storage(),v=new VaultCore(s,env,async()=>Response.json({...app(),permissions:{...permissions,contents:'write'}}));
 const state=await v.begin('owner');await assert.rejects(v.convert('code',state,'owner'));assert.equal((await v.status()).phase,'quarantined');await assert.rejects(v.appJWT());await assert.rejects(v.begin('owner'));
});
test('uncertain manifest exchange stays locked and is not retried',async()=>{
 let calls=0;const v=new VaultCore(storage(),env,async()=>{calls++;throw Error('timeout');});const state=await v.begin('owner');await assert.rejects(v.convert('code',state,'owner'));await assert.rejects(v.convert('code',state,'owner'));assert.equal(calls,1);assert.equal((await v.status()).phase,'exchanging');
});
test('GitHub PKCS1 key normalization produces a usable PKCS8 key',async()=>{
 const {generateKeyPairSync}=await import('node:crypto');const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs1',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 const normalized=normalizeKey(privateKey);assert.match(normalized,/BEGIN PRIVATE KEY/);assert.equal((await appJWT({GITHUB_APP_ID:'123',GITHUB_APP_PRIVATE_KEY:normalized})).split('.').length,3);
});
test('owner verification restores a reviewed installation only after a fresh pinned GitHub check',async()=>{
 const s=storage(),a={...app(),pem:await pem()};await s.put('app',a);await s.put('phase','installation-review-required');await s.put('installation','789');
 const response={id:789,app_id:123,account:a.owner,permissions:a.permissions};let calls=0;
 const v=new VaultCore(s,env,async()=>{calls++;return Response.json([response]);});
 await assert.rejects(v.appJWT());assert.equal((await v.install()).phase,'installed');assert.equal(calls,1);
 await s.put('phase','installation-review-required');response.suspended_at=new Date().toISOString();await assert.rejects(v.install());assert.equal((await v.status()).phase,'installation-review-required');
});
test('a suspension arriving during owner verification prevents stale reactivation',async()=>{
 const s=storage(),a={...app(),pem:await pem()};await s.put('app',a);await s.put('phase','installed');await s.put('installation','789');
 const v=new VaultCore(s,env,async()=>{await s.put('phase','installation-review-required');await s.put('installation:revision',1);return Response.json([{id:789,app_id:123,account:a.owner,permissions:a.permissions}]);});
 await assert.rejects(v.install(),/changed during verification/);assert.equal((await v.status()).phase,'installation-review-required');
});
test('oversized credential conversion stops the stream and remains locked without retaining a partial key',async()=>{
 const s=storage();let cancelled=false;
 const v=new VaultCore(s,env,async()=>new Response(new ReadableStream({pull(controller){controller.enqueue(new Uint8Array(262145));},cancel(){cancelled=true;}})));
 const state=await v.begin('owner');await assert.rejects(v.convert('code',state,'owner'));assert.equal(cancelled,true);assert.equal((await v.status()).phase,'exchanging');assert.equal(await s.get('app'),undefined);
});
test('signed suspension racing the first GitHub installation lookup cannot commit stale authority',async()=>{
 const secret='synthetic-webhook-fixture-only',s=storage(),a={...app(),pem:await pem(),webhook_secret:secret},e={...env,AUTH_ORIGIN:'https://control.example.test'};
 await s.put('app',a);await s.put('phase','created');
 const installation={id:789,app_id:a.id,account:a.owner,permissions:a.permissions};
 const v=new VaultCore(s,e,async()=>{
  const bytes=new TextEncoder().encode(JSON.stringify({action:'suspend',installation}));
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const signature=Buffer.from(await crypto.subtle.sign('HMAC',key,bytes)).toString('hex');
  const response=await v.webhook(new Request(e.AUTH_ORIGIN+'/webhooks/github/caretaker',{method:'POST',headers:{'content-type':'application/json','x-github-delivery':crypto.randomUUID(),'x-github-event':'installation','x-hub-signature-256':'sha256='+signature},body:bytes}));
  assert.equal(response.status,202);return Response.json([installation]);
 });
 await assert.rejects(v.install(),/changed during verification/);assert.equal((await v.status()).phase,'installation-review-required');assert.equal(await s.get('installation'),undefined);
});
