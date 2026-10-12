// GitHub machine authentication stays in the existing AppVault. No payload body,
// key, token, issue text or source content is retained in the receipt ledger.
export const webhookEvents=Object.freeze(['issues','issue_comment','pull_request','pull_request_review','pull_request_review_comment','workflow_run','workflow_job','repository']);
const acceptedEvents=new Set(['ping','installation','installation_repositories',...webhookEvents]);
const encoder=new TextEncoder();
const reply=(data,status=200)=>Response.json(data,{status,headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const deny=()=>{throw Object.assign(Error('webhook-denied'),{status:403});};
const id=value=>Number.isSafeInteger(value)&&value>0;
export function webhookURL(env){
 if(!env.AUTH_ORIGIN)return null;
 const origin=new URL(env.AUTH_ORIGIN);
 if(origin.protocol!=='https:'||origin.origin!==env.AUTH_ORIGIN||origin.username||origin.password)throw Error('Invalid shared control origin');
 return origin.origin+'/webhooks/github/caretaker';
}
function secretAvailable(app){return typeof app?.webhook_secret==='string'&&app.webhook_secret.length>=16&&app.webhook_secret.length<=8192;}
export async function webhookStatus(storage,env,app){
 const ledger=await storage.get('webhook:ledger');
 return {configured:secretAvailable(app),url:webhookURL(env),events:[...webhookEvents],last_delivery:ledger?.recent?.[0]||null,recent:ledger?.recent||[],accepted_count:ledger?.count||0};
}
async function readBytes(request){
 const reader=request.body?.getReader();if(!reader)throw Object.assign(Error('empty-body'),{status:400});
 const chunks=[];let length=0,timer;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{reject(Object.assign(Error('body-timeout'),{status:408}));void reader.cancel().catch(()=>{});},10000);});
 try{
  while(true){const {done,value}=await Promise.race([reader.read(),timeout]);if(done)break;length+=value.byteLength;if(length>262144){void reader.cancel().catch(()=>{});throw Object.assign(Error('oversized-body'),{status:413});}chunks.push(value);}
  const result=new Uint8Array(length);let offset=0;for(const chunk of chunks){result.set(chunk,offset);offset+=chunk.byteLength;}return result;
 }finally{clearTimeout(timer);}
}
function validatePayload(value,event,app,installation,env){
 if(!value||typeof value!=='object'||Array.isArray(value))deny();
 if(value.organization||value.enterprise)deny();
 if(event==='ping')return {action:null,repository:null};
 if(typeof value.action!=='string'||!/^[a-z_]{1,64}$/.test(value.action))deny();
 const entry=value.installation;
 if(!id(entry?.id))deny();
 if(installation&&String(entry.id)!==installation)deny();
 if(entry.app_id!==undefined&&String(entry.app_id)!==String(app.id))deny();
 if(event==='installation'||event==='installation_repositories'){
  if(!id(entry.app_id)||String(entry.app_id)!==String(app.id)||String(entry.account?.id)!==env.GITHUB_OWNER_ID||entry.account?.type!=='User'||entry.account?.login?.toLowerCase()!==env.GITHUB_OWNER)deny();
  const actions=event==='installation'?['created','deleted','suspend','unsuspend','new_permissions_accepted']:['added','removed'];
  if(!actions.includes(value.action))deny();
  return {action:value.action,repository:null};
 }
 if(!installation)deny();
 const repository=value.repository;
 if(!id(repository?.id)||typeof repository.name!=='string'||!/^[A-Za-z0-9_.-]{1,100}$/.test(repository.name)||['.','..'].includes(repository.name)||repository.full_name!==env.GITHUB_OWNER+'/'+repository.name||String(repository.owner?.id)!==env.GITHUB_OWNER_ID||repository.owner?.type!=='User'||repository.owner?.login?.toLowerCase()!==env.GITHUB_OWNER)deny();
 return {action:value.action,repository:repository.full_name};
}
export async function receiveWebhook(storage,env,request){
 if(request.url!==webhookURL(env))return reply({error:'not-found'},404);
 if(request.method!=='POST')return new Response(null,{status:405,headers:{allow:'POST','cache-control':'no-store'}});
 if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json'||request.headers.has('content-encoding'))return reply({error:'json-required'},415);
 const event=request.headers.get('x-github-event'),delivery=request.headers.get('x-github-delivery'),signature=request.headers.get('x-hub-signature-256');
 if(!acceptedEvents.has(event)||!/^[-a-f0-9]{36}$/i.test(delivery||'')||!/^sha256=[a-f0-9]{64}$/.test(signature||''))return reply({error:'webhook-denied'},403);
 try{
  const app=await storage.get('app');
  if(!secretAvailable(app))return reply({error:'webhook-not-configured'},503);
  const bytes=await readBytes(request);
  const key=await crypto.subtle.importKey('raw',encoder.encode(app.webhook_secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
  const signed=Uint8Array.from(signature.slice(7).match(/../g),byte=>parseInt(byte,16));
  if(!await crypto.subtle.verify('HMAC',key,signed,bytes))return reply({error:'webhook-denied'},403);
  let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return reply({error:'invalid-json'},400);}
  const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
  const result=await storage.transaction(async tx=>{
   // Re-read installation and key identity inside the same transaction as state
   // invalidation and receipt storage. Signed events never activate an install.
   const current=await tx.get('app'),installation=await tx.get('installation');
   if(current?.id!==app.id||current?.webhook_secret!==app.webhook_secret)deny();
   const summary=validatePayload(value,event,current,installation,env);
   const now=Date.now(),ledger=await tx.get('webhook:ledger')||{count:0,recent:[],seen:[]};
   ledger.seen=ledger.seen.filter(entry=>entry.at>now-7*86400000);
   const previous=ledger.seen.find(entry=>entry.id===delivery);
   if(previous?.digest===digest&&previous.event===event||ledger.critical?.id===delivery&&ledger.critical.digest===digest&&ledger.critical.event===event)return {accepted:true,duplicate:true,status:200};
   const critical=event==='installation'&&['suspend','deleted'].includes(value.action);
   const receipt={id:delivery,event,...summary,received_at:new Date(now).toISOString()};
   // Security invalidation must survive ordinary receipt saturation and an
   // unsigned delivery-ID collision, including initial installation verification.
   if(critical){
    await tx.put('phase','installation-review-required');
    await tx.put('installation:revision',(await tx.get('installation:revision')||0)+1);
    ledger.critical={id:delivery,event,digest};
   }
   if(previous&&!critical)return {error:'delivery-conflict',status:409};
   // Refuse excess unique deliveries until records expire; never silently evict
   // active deduplication records to make room for an attacker-controlled ID.
   const limited=!!previous||ledger.seen.length>=1024;
   if(limited&&!critical)return {error:'receipt-capacity',status:503};
   ledger.count++;ledger.recent=[receipt,...ledger.recent].slice(0,20);
   if(!limited)ledger.seen.push({id:delivery,event,digest,at:now});
   await tx.put('webhook:ledger',ledger);
   return {accepted:true,duplicate:false,...(limited?{metadata_limited:true}:{}),status:202};
  });
  const {status,...body}=result;return reply(body,status);
 }catch(error){return reply({error:error.status===403?'webhook-denied':error.status===413?'payload-too-large':error.status===408?'body-timeout':'webhook-unavailable'},error.status||503);}
}
