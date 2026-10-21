import {hash} from './crypto.mjs';
const secretKey=/authorization|cookie|token|secret|password|private.?key|client.?secret|temp_clone_token/i;
export function redact(value){
 if(Array.isArray(value)) return value.map(redact);
 if(value&&typeof value==='object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,secretKey.test(k)?'[REDACTED]':redact(v)]));
 if(typeof value==='string') return value.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,'[REDACTED PRIVATE KEY]').replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g,'[REDACTED TOKEN]').replace(/\bBearer\s+[A-Za-z0-9._~+/-]+/gi,'Bearer [REDACTED]');
 return value;
}
export async function audit(env,event){
 const repository=typeof event.repository==='string'&&/^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]{1,100}$/.test(event.repository)?event.repository:null;
 const id=crypto.randomUUID(), at=new Date().toISOString(), record=redact({id,at,...event,repository});
 const bytes=JSON.stringify(record), digest=await hash(bytes), key=at.slice(0,10)+'/'+record.category+'/'+id+'.json';
 // R2 object first, then query index. Caller must await both before any mutation.
 await env.AUDIT_BUCKET.put(key,bytes,{httpMetadata:{contentType:'application/json'},customMetadata:{sha256:digest}});
 await env.AUDIT_DB.prepare('INSERT INTO audit (id,at,correlation_id,category,phase,operation,status,object_key,sha256,repository) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id,at,event.correlation_id||id,event.category,event.phase,event.operation||'unknown',event.status||0,key,digest,repository).run();
 // Structured logs contain no bodies, credentials or URL query strings.
 (record.category==='credential'?console.error:record.category==='error'?console.warn:console.log)(JSON.stringify({severity:record.category==='credential'?'critical':record.category==='error'?'error':'info',audit_id:id,correlation_id:record.correlation_id,category:record.category,phase:record.phase,operation:record.operation,status:record.status}));
 return id;
}
// Grants come only from the authenticated capability identity, never tool arguments.
function access(env,identity){
 const prefix=env.GITHUB_OWNER+'/';
 const grants=Array.isArray(identity?.repos)?identity.repos.filter(r=>typeof r==='string'&&r.startsWith(prefix)):[];
 return {sql:'repository IS NOT NULL AND (repository IN (SELECT value FROM json_each(?)) OR (? = 1 AND substr(repository,1,?) = ?))',bindings:[JSON.stringify(grants.filter(r=>r!==prefix+'*')),grants.includes(prefix+'*')?1:0,prefix.length,prefix]};
}
export async function recent(env,category='all',identity){
 const scope=access(env,identity);
 const sql='SELECT id,at,correlation_id,category,phase,operation,status,object_key,sha256,repository FROM audit WHERE '+scope.sql+(category==='all'?'':' AND category = ?')+' ORDER BY at DESC LIMIT 100';
 return (await env.AUDIT_DB.prepare(sql).bind(...scope.bindings,...(category==='all'?[]:[category])).all()).results;
}

export async function readRecord(env,id,identity){
 const scope=access(env,identity);
 const row=await env.AUDIT_DB.prepare('SELECT object_key,sha256 FROM audit WHERE id = ? AND '+scope.sql).bind(id,...scope.bindings).first();
 if(!row)throw Error('Audit record not found');
 const object=await env.AUDIT_BUCKET.get(row.object_key);if(!object)throw Error('Audit object missing');
 const text=await object.text();if(await hash(text)!==row.sha256)throw Error('Audit digest mismatch');
 return JSON.parse(text);
}
