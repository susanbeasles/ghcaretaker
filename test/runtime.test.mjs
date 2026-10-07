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
