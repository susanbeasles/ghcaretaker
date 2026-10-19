import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OUTBOX_SCHEMA, enqueue, drain, BACKFILL_MAX_ATTEMPTS, BACKFILL_MAX_AGE_MS, BACKFILL_MAX_PENDING } from '../src/outbox.mjs';
import { sqlStorage, clock } from './fakes.mjs';
function setup() { const storage=sqlStorage(),now=clock();for(const s of OUTBOX_SCHEMA)storage.sql.exec(s);return {sql:storage.sql,now}; }
const row=sql=>sql.exec("SELECT * FROM outbox WHERE kind='backfill' ORDER BY id LIMIT 1").toArray()[0];
test('deterministic backfill error is terminal, retained and escalated; no more requests',async()=>{
 const {sql,now}=setup();enqueue(sql,{kind:'backfill',dedupe_key:'one',payload:{}},now());let calls=0;
 const handlers={backfill:async()=>{calls++;throw Object.assign(Error('bound'),{code:'compare_too_many_commits'});}};
 await drain(sql,handlers,{now,source:'test'});assert.ok(row(sql).done_at);assert.equal(row(sql).last_error,'compare_too_many_commits');
 now.advance(3600000);await drain(sql,handlers,{now,source:'test'});assert.equal(calls,1);assert.equal(sql.exec("SELECT COUNT(*) AS n FROM outbox WHERE kind='alert'").toArray()[0].n,1);
});
test('transient retry can recover; deferred consumes no attempt but cannot outlive age bound',async()=>{
 const {sql,now}=setup();enqueue(sql,{kind:'backfill',dedupe_key:'one',payload:{}},now());
 await drain(sql,{backfill:async()=>{throw Object.assign(Error('down'),{code:'github_http_502'});}},{now});assert.equal(row(sql).attempts,1);assert.equal(row(sql).done_at,null);
 now.advance(3600000);await drain(sql,{backfill:async()=>{}},{now});assert.ok(row(sql).done_at);
 enqueue(sql,{kind:'backfill',dedupe_key:'two',payload:{}},now());await drain(sql,{backfill:async()=>{throw Object.assign(Error('budget'),{code:'deferred'});}},{now});let r=sql.exec("SELECT * FROM outbox WHERE dedupe_key='two'").toArray()[0];assert.equal(r.attempts,0);
 now.advance(BACKFILL_MAX_AGE_MS);let called=false;await drain(sql,{backfill:async()=>{called=true;}},{now});assert.equal(called,false);r=sql.exec("SELECT * FROM outbox WHERE dedupe_key='two'").toArray()[0];assert.ok(r.done_at);
});
test('backfill attempts and pending quota are bounded without limiting alert delivery',async()=>{
 const {sql,now}=setup();enqueue(sql,{kind:'backfill',dedupe_key:'one',payload:{}},now());sql.exec('UPDATE outbox SET attempts=?',BACKFILL_MAX_ATTEMPTS-1);
 await drain(sql,{backfill:async()=>{throw Object.assign(Error('down'),{code:'github_http_502'});}},{now});assert.ok(row(sql).done_at);
 for(let i=0;i<BACKFILL_MAX_PENDING;i++)enqueue(sql,{kind:'backfill',dedupe_key:'p'+i,payload:{}},now());assert.equal(enqueue(sql,{kind:'backfill',dedupe_key:'overflow',payload:{}},now()),false);assert.equal(sql.exec("SELECT COUNT(*) AS n FROM outbox WHERE kind='backfill' AND done_at IS NULL").toArray()[0].n,BACKFILL_MAX_PENDING);
});
