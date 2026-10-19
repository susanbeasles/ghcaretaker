import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {audit,recent,readRecord} from '../src/audit.mjs';
import {handle} from '../src/worker.mjs';
import {CaretakerCore} from '../src/capability.mjs';
import {d1Database,memoryR2} from './fakes.mjs';
const base=readFileSync('migrations/0001.sql','utf8');
const migration='migrations/0002-audit-repository.sql';
const session=repos=>({profile:'caretaker',revoked:false,expires:null,scopes:['github:read'],repos});
function setup(){
 const env={GITHUB_OWNER:'personal',GITHUB_OWNER_ID:'1',PUBLIC_ORIGIN:'https://worker.test',AUTH_ORIGIN:'https://control.test',MCP_PATH:'/mcp',AUDIT_DB:d1Database(base),AUDIT_BUCKET:memoryR2()};
 if(existsSync(migration))env.AUDIT_DB.db.exec(readFileSync(migration,'utf8'));
 return env;
}
const seed=(env,repository,body='synthetic private data')=>audit(env,{repository,category:'success',phase:'result',operation:'get_repository',response:{body}});
test('repository session cannot list or fetch another repository or unscoped audit',async()=>{
 const env=setup(),core=new CaretakerCore(env);
 const own=await seed(env,'personal/allowed'),other=await seed(env,'personal/private'),legacy=await seed(env,null);
 const result=await core.callTool('audit_recent',{},session(['personal/allowed']));
 const text=JSON.stringify(result);
 assert.ok(text.includes(own));assert.ok(!text.includes(other));assert.ok(!text.includes(legacy));
 for(const id of [other,legacy,crypto.randomUUID()]){
  let gets=0;const get=env.AUDIT_BUCKET.get;env.AUDIT_BUCKET.get=async key=>{gets++;return get(key);};
  const denied=await core.callTool('audit_record',{id},session(['personal/allowed']));
  env.AUDIT_BUCKET.get=get;assert.equal(denied.result.isError,true);assert.equal(gets,0);
  assert.match(JSON.stringify(denied),/Audit record not found/);
 }
 assert.ok(!(await core.callTool('audit_record',{id:own},session(['personal/allowed']))).result.isError);
});
test('exact, multiple and owner wildcard grants filter before the recent limit; missing grants deny',async()=>{
 const env=setup(),a=await seed(env,'personal/a'),b=await seed(env,'personal/b');
 await seed(env,'someone/a');await seed(env,null);
 for(let i=0;i<101;i++)await seed(env,'personal/private');
 assert.deepEqual((await recent(env,'all',session(['personal/a']))).map(r=>r.id),[a]);
 assert.deepEqual(new Set((await recent(env,'success',session(['personal/a','personal/b']))).map(r=>r.id)),new Set([a,b]));
 const rows=await recent(env,'all',session(['personal/*']));assert.equal(rows.length,100);assert.ok(rows.every(r=>r.repository.startsWith('personal/')));
 assert.deepEqual(await recent(env),[]);
 await assert.rejects(readRecord(env,a),/Audit record not found/);
 assert.deepEqual(await recent(env,'all',session(['someone/*'])),[]);
});
test('migration preserves immutable historical records and old writers remain unscoped',async()=>{
 const env=setup();
 const old=d1Database(base);
 const insert="INSERT INTO audit (id,at,correlation_id,category,phase,operation,status,object_key,sha256) VALUES (?,?,?,?,?,?,?,?,?)";
 old.db.prepare(insert).run('old','2020','corr','success','result','read_file',200,'old.json','digest');
 old.db.exec(readFileSync(migration,'utf8'));
 old.db.prepare(insert).run('old-writer','2020','corr','success','result','read_file',200,'old-writer.json','digest');
 env.AUDIT_DB=old;
 assert.equal(env.AUDIT_DB.db.prepare("SELECT repository FROM audit WHERE id='old'").get().repository,null);
 assert.throws(()=>env.AUDIT_DB.db.exec("UPDATE audit SET repository='personal/a' WHERE id='old'"),/append only/);
 assert.throws(()=>env.AUDIT_DB.db.exec("DELETE FROM audit WHERE id='old'"),/append only/);
 assert.ok(!(await recent(env,'all',session(['personal/*']))).some(r=>r.id==='old'));
});

test('request and response scopes are explicit; aggregate audit replies cannot launder private records',async()=>{
 const env=setup(),identity=session(['personal/a','personal/b']);
 const request=(name,args)=>new Request(env.PUBLIC_ORIGIN+'/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})});
 const deps={authenticate:async()=>identity,github:async()=>({body:'synthetic private response'})};
 assert.equal((await handle(request('get_repository',{repo:'b'}),env,deps)).status,200);
 const rows=await recent(env,'all',identity);assert.equal(rows.length,2);assert.ok(rows.every(r=>r.repository==='personal/b'));
 const core=new CaretakerCore(env);
 await core.callTool('audit_recent',{},identity);
 await core.callTool('audit_record',{id:rows[0].id},identity);
 assert.deepEqual(await recent(env,'all',session(['personal/a'])),[]);
 assert.equal((await recent(env,'all',identity)).length,2,'audit tool responses remain unscoped');
 await handle(request('get_repository',{repo:'a',repository:'personal/b'}),env,deps);
 assert.deepEqual(await recent(env,'all',session(['personal/a'])),[],'invalid arguments never label a record');
});
test('missing migration stops requests before upstream work',async()=>{
 const env=setup();env.AUDIT_DB=d1Database(base);let called=false;
 const response=await handle(new Request(env.PUBLIC_ORIGIN+'/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'get_repository',arguments:{repo:'a'}}})}),env,{authenticate:async()=>session(['personal/a']),github:async()=>{called=true;}});
 assert.equal(response.status,503);assert.equal(called,false);
});
