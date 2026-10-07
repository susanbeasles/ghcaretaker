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
