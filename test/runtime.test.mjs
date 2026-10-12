import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {build} from 'esbuild';
import {readFile} from 'node:fs/promises';
test('real Worker runtime serves scoped OAuth discovery and delegates discovery to the central gate and redirects setup',async()=>{
 const output=await build({entryPoints:['src/index.mjs'],bundle:true,write:false,format:'esm',platform:'browser',external:['cloudflare:workers']});
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:output.outputFiles[0].text,compatibilityDate:'2026-10-05',compatibilityFlags:['global_fetch_strictly_public'],serviceBindings:{AUTH_GATEWAY:async request=>request.url.includes('.well-known')?Response.json({issuer:'https://control.vespoli.me',resource:'https://control.vespoli.me/mcp/caretaker',token_endpoint:'https://control.vespoli.me/oauth/token'}):Response.json({error:'invalid_token'},{status:401,headers:{'www-authenticate':'Bearer resource_metadata="https://control.vespoli.me/.well-known/oauth-protected-resource/mcp/caretaker"'}})},bindings:{AUTH_ORIGIN:'https://control.vespoli.me',PUBLIC_ORIGIN:'https://mcp.vespoli.me',MCP_PATH:'/ghcaretaker',GITHUB_OWNER:'susanbeasles',GITHUB_OWNER_ID:'215839550'},durableObjects:{APP_VAULT:{className:'AppVault',useSQLite:true}},kvNamespaces:['OAUTH_KV'],r2Buckets:['AUDIT_BUCKET'],d1Databases:['AUDIT_DB']}));
 try{
  const db=await mf.getD1Database('AUDIT_DB');await db.exec((await readFile('migrations/0001.sql','utf8')).replaceAll('\n',' '));
  let r=await mf.dispatchFetch('https://mcp.vespoli.me/.well-known/oauth-protected-resource/ghcaretaker');assert.equal(r.status,200);assert.equal((await r.json()).resource,'https://control.vespoli.me/mcp/caretaker');
  r=await mf.dispatchFetch('https://mcp.vespoli.me/.well-known/oauth-authorization-server/ghcaretaker/auth');assert.equal(r.status,200);const d=await r.json();assert.equal(d.issuer,'https://control.vespoli.me');assert.equal(d.token_endpoint,'https://control.vespoli.me/oauth/token');
  r=await mf.dispatchFetch('https://mcp.vespoli.me/ghcaretaker',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'});assert.equal(r.status,401);assert.match(r.headers.get('www-authenticate'),/oauth-protected-resource\/mcp\/caretaker/);
  r=await mf.dispatchFetch('https://mcp.vespoli.me/ghcaretaker/setup',{redirect:'manual'});assert.equal(r.status,303);assert.equal(r.headers.get('location'),'https://control.vespoli.me/owner/apps/caretaker');
 }finally{await mf.dispose();}
});
test('actual gateway binding forwards signed bytes through capability RPC into the existing vault',async()=>{
 const secret='synthetic-runtime-webhook-fixture',origin='https://control.example.test';
 const source=`export {default,CaretakerCapability} from './src/index.mjs';
 import {AppVault} from './src/vault.mjs';
 export class FixtureAppVault extends AppVault {
  constructor(ctx,env){super(ctx,env);ctx.blockConcurrencyWhile(async()=>{
   if(!await ctx.storage.get('app')){await ctx.storage.put('app',{id:456,webhook_secret:${JSON.stringify(secret)}});await ctx.storage.put('phase','installed');await ctx.storage.put('installation','123');}
  });}
 }`;
 const compiled=await build({stdin:{contents:source,resolveDir:process.cwd(),sourcefile:'synthetic-runtime-fixture.mjs'},bundle:true,write:false,format:'esm',platform:'browser',external:['cloudflare:workers']});
 const noNetwork=async()=>{throw Error('No provider network is permitted by this fixture');};
 const mf=new Miniflare(convertV4MiniflareOptions({workers:[
  {name:'gateway',modules:true,compatibilityDate:'2026-10-05',script:`export default {async fetch(request,env){return new URL(request.url).pathname==='/status'?Response.json(await env.CARETAKER.status()):env.CARETAKER.webhook(request);}}`,serviceBindings:{CARETAKER:{name:'caretaker',entrypoint:'CaretakerCapability'}},outboundService:noNetwork},
  {name:'caretaker',modules:true,compatibilityDate:'2026-10-05',script:compiled.outputFiles[0].text,bindings:{AUTH_ORIGIN:origin,PUBLIC_ORIGIN:'https://legacy.example.test',MCP_PATH:'/ghcaretaker',GITHUB_OWNER:'personal',GITHUB_OWNER_ID:'42'},durableObjects:{APP_VAULT:{className:'FixtureAppVault',useSQLite:true}},serviceBindings:{AUTH_GATEWAY:'gateway'},outboundService:noNetwork}
 ]}));
 try{
  const gateway=await mf.getWorker('gateway'),component=await mf.getWorker('caretaker');
  const send=async(action,id=crypto.randomUUID())=>{
   const bytes=new TextEncoder().encode(JSON.stringify({action,installation:{id:123,app_id:456,account:{id:42,login:'personal',type:'User'}}}));
   const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
   const signature=Buffer.from(await crypto.subtle.sign('HMAC',key,bytes)).toString('hex');
   return gateway.fetch(origin+'/webhooks/github/caretaker',{method:'POST',headers:{'content-type':'application/json','x-github-event':'installation','x-github-delivery':id,'x-hub-signature-256':'sha256='+signature},body:bytes});
  };
  let response=await component.fetch('https://legacy.example.test/webhooks/github/caretaker',{method:'POST',body:'{}'});assert.equal(response.status,404);
  response=await gateway.fetch(origin+'/webhooks/github/caretaker',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});assert.equal(response.status,403);
  const id=crypto.randomUUID();response=await send('suspend',id);assert.equal(response.status,202,await response.text());response=await send('suspend',id);assert.equal(response.status,200);
  const status=await (await gateway.fetch(origin+'/status')).json();assert.equal(status.phase,'installation-review-required');assert.equal(status.webhook.accepted_count,1);assert.equal(status.webhook.last_delivery.action,'suspend');assert.ok(!JSON.stringify(status).includes(secret));
 }finally{await mf.dispose();}
});
