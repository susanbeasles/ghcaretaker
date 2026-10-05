import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {build} from 'esbuild';
import {readFile} from 'node:fs/promises';
test('official OAuth provider enforces PKCE, rejects replay and binds owner props to the exact resource',async()=>{
 const result=await build({stdin:{contents:await readFile('test/fixtures/oauth-worker.txt','utf8'),resolveDir:process.cwd(),loader:'js'},bundle:true,write:false,format:'esm',platform:'browser',external:['cloudflare:workers']});
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:result.outputFiles[0].text,compatibilityDate:'2026-10-05',compatibilityFlags:['global_fetch_strictly_public'],kvNamespaces:['OAUTH_KV']}));
 try{const r=await mf.dispatchFetch('https://test.invalid/');assert.equal(r.status,200,await r.text());}finally{await mf.dispose();}
});
