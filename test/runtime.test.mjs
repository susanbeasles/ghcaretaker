import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {build} from 'esbuild';
import {readFile} from 'node:fs/promises';
test('real Worker runtime serves scoped OAuth discovery and refuses setup without Access',async()=>{
 const output=await build({entryPoints:['src/index.mjs'],bundle:true,write:false,format:'esm',platform:'browser',external:['cloudflare:workers']});
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:output.outputFiles[0].text,compatibilityDate:'2026-10-05',compatibilityFlags:['global_fetch_strictly_public'],bindings:{PUBLIC_ORIGIN:'https://mcp.vespoli.me',MCP_PATH:'/ghcaretaker',GITHUB_OWNER:'susanbeasles',GITHUB_OWNER_ID:'215839550'},durableObjects:{APP_VAULT:{className:'AppVault',useSQLite:true}},kvNamespaces:['OAUTH_KV'],r2Buckets:['AUDIT_BUCKET'],d1Databases:['AUDIT_DB']}));
 try{
  const db=await mf.getD1Database('AUDIT_DB');await db.exec((await readFile('migrations/0001.sql','utf8')).replaceAll('\n',' '));
  let r=await mf.dispatchFetch('https://mcp.vespoli.me/.well-known/oauth-protected-resource/ghcaretaker');assert.equal(r.status,200);assert.equal((await r.json()).resource,'https://mcp.vespoli.me/ghcaretaker');
  r=await mf.dispatchFetch('https://mcp.vespoli.me/.well-known/oauth-authorization-server/ghcaretaker/auth');assert.equal(r.status,200);const d=await r.json();assert.equal(d.issuer,'https://mcp.vespoli.me/ghcaretaker/auth');assert.equal(d.token_endpoint,'https://mcp.vespoli.me/ghcaretaker/auth/token');
  r=await mf.dispatchFetch('https://mcp.vespoli.me/ghcaretaker',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'});assert.equal(r.status,401);assert.match(r.headers.get('www-authenticate'),/oauth-protected-resource\/ghcaretaker/);
  r=await mf.dispatchFetch('https://mcp.vespoli.me/ghcaretaker/setup');assert.equal(r.status,403);assert.ok(!JSON.stringify(await r.json()).includes('secret'));
 }finally{await mf.dispose();}
});
