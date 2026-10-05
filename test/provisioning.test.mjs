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
test('login token is revoked and only the pinned numeric GitHub owner is accepted',async()=>{
 const s=storage();await s.put('app',app());await s.put('phase','installed');let revoke=0;
 const v=new VaultCore(s,env,async(url,opts)=>{
  if(url==='https://github.com/login/oauth/access_token'){assert.equal(JSON.parse(opts.body).redirect_uri,'https://mcp.vespoli.me/ghcaretaker/auth/callback');return Response.json({access_token:'never-persist'});}
  if(url==='https://api.github.com/user')return Response.json({id:42,login:'susanbeasles',type:'User'});
  assert.equal(opts.method,'DELETE');revoke++;return new Response(null,{status:204});
 });
 await assert.rejects(v.identify('code','verifier'));assert.equal(revoke,1);assert.ok(!JSON.stringify(await s.get('app')).includes('never-persist'));
});
import {bootstrapIdentity} from '../src/bootstrap.mjs';
import {b64} from '../src/crypto.mjs';
test('installation Access JWT enforces signature, issuer, audience, email and lifetime',async()=>{
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']),jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);jwk.kid='fixed';
 const e={SETUP_ACCESS_ISSUER:'https://owner.cloudflareaccess.com',SETUP_ACCESS_AUD:'setup-only',SETUP_OWNER_EMAIL:'owner@test.invalid'},claims={iss:e.SETUP_ACCESS_ISSUER,aud:['setup-only'],email:e.SETUP_OWNER_EMAIL,sub:'owner',nbf:Date.now()/1000-10,exp:Date.now()/1000+120};
 async function req(patch={}){const enc=new TextEncoder(),input=b64(enc.encode(JSON.stringify({alg:'RS256',kid:'fixed'})))+'.'+b64(enc.encode(JSON.stringify({...claims,...patch})));const token=input+'.'+b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,enc.encode(input)));return new Request('https://mcp.vespoli.me/ghcaretaker/setup',{headers:{'Cf-Access-Jwt-Assertion':token}});}
 const fetcher=async(url,opts)=>{assert.equal(url,e.SETUP_ACCESS_ISSUER+'/cdn-cgi/access/certs');assert.equal(opts.redirect,'error');return Response.json({keys:[jwk]});};
 assert.equal(await bootstrapIdentity(await req(),e,fetcher),'owner');
 for(const bad of [{iss:'https://attacker.cloudflareaccess.com'},{aud:['different-app']},{email:'attacker@test.invalid'},{exp:0},{nbf:Date.now()/1000+600}])await assert.rejects(bootstrapIdentity(await req(bad),e,fetcher));
 await assert.rejects(bootstrapIdentity(await req(),{},fetcher));
});
