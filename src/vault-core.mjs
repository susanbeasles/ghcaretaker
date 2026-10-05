import {appJWT,hash,b64,unb64} from './crypto.mjs';
import {assertApp,resource} from './manifest.mjs';
import {audit} from './audit.mjs';
function der(tag,bytes){let n=bytes.length,len=n<128?[n]:n<256?[129,n]:[130,n>>8,n&255];return new Uint8Array([tag,...len,...bytes]);}
export function normalizeKey(pem){
 if(pem.includes('BEGIN PRIVATE KEY'))return pem;
 if(!pem.includes('BEGIN RSA PRIVATE KEY'))throw Error('Unsupported App key format');
 const raw=unb64(pem.replace(/-----[^-]+-----|\s/g,''));
 const algorithm=[48,13,6,9,42,134,72,134,247,13,1,1,1,5,0];
 const wrapped=der(48,new Uint8Array([2,1,0,...algorithm,...der(4,raw)]));
 return '-----BEGIN PRIVATE KEY-----\n'+b64(wrapped).replaceAll('-','+').replaceAll('_','/')+'\n-----END PRIVATE KEY-----';
}
export class VaultCore{
 constructor(storage,env,fetcher=fetch){this.storage=storage;this.env=env;this.fetcher=fetcher;}
 async record(category,operation,status){await audit(this.env,{correlation_id:crypto.randomUUID(),category,phase:'provisioning',operation,status});}
 async call(url,options,deferResponseAudit=false){
  const operation=url.includes('/conversions')?'manifest_credentials':url.includes('/access_token')?'login_credentials':url.includes('/applications/')?'revoke_login_token':url.endsWith('/user')?'verify_login_owner':'verify_app_installation';
  await this.record('success',operation+'_intent',0);
  const r=await this.fetcher(url,{...options,redirect:'error',signal:AbortSignal.timeout(20000)});
  if(!deferResponseAudit)await this.record(r.ok?'success':r.status===401||r.status===403?'credential':'error',operation+'_response',r.status);
  if(!r.ok){await this.record(r.status===401||r.status===403?'credential':'error','app_vault_upstream',r.status);throw Error('GitHub credential operation failed');}
  if(r.status===204)return null;
  const body=await r.text();if(body.length>262144)throw Error('Oversized credential response');return JSON.parse(body);
 }
 headers(token){return {Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'ghcaretaker'};}
 async status(){const a=await this.storage.get('app');return {phase:await this.storage.get('phase')||'empty',app_id:a?.id,slug:a?.slug,installation_id:await this.storage.get('installation')};}
 async begin(subject){
  return this.storage.transaction(async tx=>{
   if(await tx.get('phase'))throw Error('App creation is locked; inspect setup status');
   const state=crypto.randomUUID()+crypto.randomUUID();await tx.put('state',{digest:await hash(state),subject,expires:Date.now()+600000});return state;
  });
 }
 async convert(code,state,subject){
  if(!/^[a-zA-Z0-9_\-]{1,256}$/.test(code||''))throw Error('Invalid manifest code');
  await this.storage.transaction(async tx=>{
   const s=await tx.get('state');if(await tx.get('phase')||!s||s.subject!==subject||s.expires<Date.now()||s.digest!==await hash(state||''))throw Error('Invalid or consumed setup state');
   await tx.delete('state');await tx.put('phase','exchanging');
  });
  await this.record('success','manifest_exchange_intent',0);
  try{
   const app=await this.call('https://api.github.com/app-manifests/'+code+'/conversions',{method:'POST',headers:{Accept:'application/vnd.github+json','User-Agent':'ghcaretaker'}},true);
   // Store once before further network calls. Never return the response or key.
   await this.storage.put('app',app);await this.storage.put('phase','quarantined');
   await this.record('success','manifest_credentials_response_stored',201);
   assertApp(app,this.env);
   if(typeof app.client_id!=='string'||typeof app.client_secret!=='string'||typeof app.pem!=='string')throw Error('Incomplete credential response');
   app.pem=normalizeKey(app.pem);await appJWT({GITHUB_APP_ID:String(app.id),GITHUB_APP_PRIVATE_KEY:app.pem});
   await this.storage.put('app',app);await this.storage.put('phase','created');await this.record('success','manifest_exchange_complete',201);
   return this.status();
  }catch{await this.record('credential','manifest_exchange_failed_reconcile_required',0);throw Error('Setup stopped; reconcile GitHub App registration before retrying');}
 }
 async appJWT(){const a=await this.storage.get('app'),phase=await this.storage.get('phase');if(!a||!['created','installed'].includes(phase))throw Error('App is not provisioned');return appJWT({GITHUB_APP_ID:String(a.id),GITHUB_APP_PRIVATE_KEY:a.pem});}
 async install(){
  await this.record('success','installation_verify_intent',0);
  const all=await this.call('https://api.github.com/app/installations?per_page=100',{headers:this.headers(await this.appJWT())});
  const matches=all.filter(x=>String(x.account?.id)===this.env.GITHUB_OWNER_ID&&x.account?.type==='User'&&!x.suspended_at);
  if(matches.length!==1)throw Error('Install the App on the pinned personal account first');
  const app=await this.storage.get('app');assertApp({...app,permissions:matches[0].permissions},this.env);
  await this.storage.put('installation',String(matches[0].id));await this.storage.put('phase','installed');await this.record('success','installation_verified',200);return this.status();
 }
 async config(){const s=await this.status();if(s.phase!=='installed')throw Error('App installation is incomplete');return {GITHUB_APP_ID:String(s.app_id),GITHUB_INSTALLATION_ID:s.installation_id};}
 async clientID(){const a=await this.storage.get('app');if(await this.storage.get('phase')!=='installed')throw Error('App installation is incomplete');return a.client_id;}
 async identify(code,verifier){
  if(!/^[a-zA-Z0-9_\-]{1,256}$/.test(code||'')||typeof verifier!=='string'||verifier.length>256)throw Error('Invalid authorization callback');
  const a=await this.storage.get('app');if(await this.storage.get('phase')!=='installed')throw Error('App installation is incomplete');
  await this.record('success','owner_login_intent',0);
  const data=await this.call('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:a.client_id,client_secret:a.client_secret,code,code_verifier:verifier,redirect_uri:resource(this.env)+'/auth/callback'})});
  if(typeof data.access_token!=='string')throw Error('GitHub login rejected');
  let user;
  try{user=await this.call('https://api.github.com/user',{headers:this.headers(data.access_token)});}
  finally{
   // Login tokens are not retained. Revoke immediately before issuing any MCP grant.
   await this.call('https://api.github.com/applications/'+a.client_id+'/token',{method:'DELETE',headers:{Authorization:'Basic '+btoa(a.client_id+':'+a.client_secret),Accept:'application/vnd.github+json','Content-Type':'application/json','User-Agent':'ghcaretaker'},body:JSON.stringify({access_token:data.access_token})});
  }
  if(String(user.id)!==this.env.GITHUB_OWNER_ID||user.login?.toLowerCase()!==this.env.GITHUB_OWNER||user.type!=='User'){await this.record('credential','owner_login_denied',403);throw Error('Only the pinned personal GitHub account may authorize');}
  await this.record('success','owner_login_verified',200);return {subject:String(user.id)};
 }
}
