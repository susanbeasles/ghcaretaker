import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { sqlStorage, sha } from './fakes.mjs';
import { CommitLedgerCore } from '../src/commit-ledger-core.mjs';

// Exercise the production wrapper with local SQLite; only the runtime base class is replaced.
const hooks=registerHooks({resolve(specifier,context,next){
 if(specifier==='cloudflare:workers')return {url:'data:text/javascript,export class DurableObject {}',shortCircuit:true};
 return next(specifier,context);
}});
const {CommitLedger}=await import('../src/ledgers.mjs');
hooks.deregister();
const marker='migration:exact-promotion-evidence:v1';
function legacy(){
 const storage=sqlStorage();new CommitLedgerCore(storage,{});
 storage.sql.exec('DELETE FROM meta WHERE key = ?',marker);
 storage.sql.exec("INSERT INTO promotions (sha,delivery_id,due_at,next_check_at,status,resolved_by) VALUES (?,?,0,0,'satisfied','api')",sha(2),crypto.randomUUID());
 return storage;
}
function instantiate(storage){
 let ready;
 const ctx={storage,blockConcurrencyWhile:fn=>{ready=Promise.resolve().then(fn);return ready;}};
 const ledger=new CommitLedger(ctx,{});
 assert.ok(ready,'production constructor must register initialization before serving RPCs');
 return {ledger,ready};
}
test('idle read initialization arms reconciliation without manual scheduling or ingestion',async()=>{
 const storage=legacy(),start=Date.now();
 const {ledger,ready}=instantiate(storage);await ready;
 assert.ok(storage.alarmAt>=start&&storage.alarmAt<=Date.now()+1000);
 assert.equal(storage.sql.exec('SELECT status FROM promotions').one().status,'pending');
 assert.ok(ledger.core.meta(marker));
});
test('failed alarm setup rejects initialization and retries despite completed migration marker',async()=>{
 const storage=legacy(),setAlarm=storage.setAlarm;
 storage.setAlarm=async()=>{throw Error('synthetic alarm failure');};
 const first=instantiate(storage);await assert.rejects(first.ready,/synthetic alarm failure/);
 const migrated=storage.sql.exec('SELECT * FROM promotions').one();
 assert.equal(migrated.status,'pending');assert.ok(first.ledger.core.meta(marker));assert.equal(storage.alarmAt,null);
 storage.setAlarm=setAlarm;
 const retry=instantiate(storage);await retry.ready;
 assert.ok(storage.alarmAt!==null);
 assert.deepEqual(storage.sql.exec('SELECT * FROM promotions').one(),migrated,'retry schedules without rerunning invalidation');
});
