import {appJWT} from './crypto.mjs';
import {permissions,route} from './policy.mjs';
import {audit,redact} from './audit.mjs';
import {inlineFile} from './content.mjs';
export class UpstreamError extends Error {constructor(status,category){super('GitHub request failed');this.status=status;this.category=category;}}
export function category(status,headers){return status===401?'credential':status===403?(headers.get('x-ratelimit-remaining')==='0'||headers.has('retry-after')?'error':'credential'):status>=400?'error':'success';}
async function bounded(response,limit=4*1024*1024){
 if(!response.body) return '';
 const reader=response.body.getReader(),chunks=[]; let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel();throw Error('Upstream response exceeds limit');}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return new TextDecoder().decode(bytes);
}
export async function github(env,identity,name,args,correlation,fetcher=fetch){
 const req=route(name,args,env.GITHUB_OWNER);
 async function call(path,method,token,body,operation,credential=false){
  await audit(env,{correlation_id:correlation,category:'success',phase:'intent',operation,request:{method,path,body}});
  let response,text;
  try{response=await fetcher('https://api.github.com'+path,{method,redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'ghcaretaker/0.0.1-beta.2',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});text=await bounded(response);}
  catch{await audit(env,{correlation_id:correlation,category:'error',phase:'uncertain',operation,response:{message:'Network failure, redirect, timeout or oversized response. Mutation outcome may be unknown.'}});throw new UpstreamError(502,'error');}
  let data;try{data=JSON.parse(text);}catch{data={text};}
  const cat=category(response.status,response.headers);
  // Never archive token response bodies, even for malformed responses.
  await audit(env,{correlation_id:correlation,category:cat,phase:'result',operation,status:response.status,response:credential?{message:response.ok?'Credential minted':'Credential rejected; inspect GitHub request ID',permissions:data.permissions,expires_at:data.expires_at}:data,headers:{github_request_id:response.headers.get('x-github-request-id'),rate_remaining:response.headers.get('x-ratelimit-remaining'),retry_after:response.headers.get('retry-after')}});
  if(!response.ok) throw new UpstreamError(response.status,cat);
  return {data,link:response.headers.get('link')};
 }
 // Verify configured installation really belongs to this personal account; no org installation accepted.
 let jwt;try{jwt=await appJWT(env);}catch{throw new UpstreamError(401,'credential');}
 const installation=(await call('/app/installations/'+env.GITHUB_INSTALLATION_ID,'GET',jwt,undefined,'verify_installation')).data;
 if(installation.account?.login?.toLowerCase()!==env.GITHUB_OWNER.toLowerCase()||installation.account?.type!=='User'||installation.suspended_at) throw new UpstreamError(403,'credential');
 const p={...permissions};if(!identity.scopes.includes('github:collaborate')){p.issues='read';p.pull_requests='read';}
 const minted=(await call('/app/installations/'+env.GITHUB_INSTALLATION_ID+'/access_tokens','POST',jwt,{permissions:p},'mint_installation_token',true)).data;
 if(typeof minted.token!=='string'||!Number.isFinite(Date.parse(minted.expires_at))||Date.parse(minted.expires_at)<=Date.now()) throw Error('Invalid token response');
 if(!minted.permissions||Object.entries(minted.permissions).some(([k,v])=>!p[k]||v!==p[k])||Object.entries(p).some(([k,v])=>minted.permissions[k]!==v)){
  await call('/installation/token','DELETE',minted.token,undefined,'revoke_unexpected_token',true);
  throw new UpstreamError(403,'credential');
 }
 const result=await call(req.path,req.method,minted.token,req.body,name);
 // A separate audit intent/result exists for each upstream call; no automatic retries of writes.
 return {data:redact(name==='read_file'?inlineFile(result.data):result.data),pagination:result.link?{link:result.link,note:'Use page + 1 with the same tool; links are data, never fetched automatically.'}:null};
}
