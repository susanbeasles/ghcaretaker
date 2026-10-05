import {OAuthAuthorizationServer} from '@cloudflare/workers-oauth-provider';
import {handle,metadata} from './worker.mjs';
import {manifest,resource,vault} from './manifest.mjs';
import {bootstrapIdentity,escape,page,sameOrigin} from './bootstrap.mjs';
import {hash} from './crypto.mjs';
import {audit} from './audit.mjs';
export {AppVault} from './vault.mjs';
export function server(env){return new OAuthAuthorizationServer({issuer:resource(env)+'/auth',resources:[resource(env)],authorizeEndpoint:resource(env)+'/auth/authorize',tokenEndpoint:resource(env)+'/auth/token',clientRegistrationEndpoint:resource(env)+'/auth/register',scopesSupported:['github:read','github:collaborate','offline_access'],accessTokenTTL:300,refreshTokenTTL:86400,clientIdMetadataDocumentEnabled:false,onError:()=>{console.error(JSON.stringify({category:'credential',operation:'oauth_rejected'}));}});}
async function setup(request,env){
 const subject=await bootstrapIdentity(request,env),u=new URL(request.url),v=vault(env),base=resource(env);
 if(request.method!=='GET'&&request.method!=='POST')return new Response(null,{status:405});
 if(u.pathname===env.MCP_PATH+'/setup/callback'){
  if(request.method!=='GET')throw Error('Invalid callback method');
  await v.convert(u.searchParams.get('code'),u.searchParams.get('state'),subject);
  return Response.redirect(base+'/setup',303);
 }
 const s=await v.status();
 if(request.method==='POST'){
  sameOrigin(request,env);const f=await request.formData();
  if(f.get('action')==='verify-installation'){await v.install();return Response.redirect(base+'/setup',303);}
  throw Error('Unsupported setup action');
 }
 if(s.phase==='empty'){
  const state=await v.begin(subject);
  return page('<p>Create the personal GitHub App with the reviewed repository manifest. Secrets remain inside Cloudflare.</p><form method="POST" action="https://github.com/settings/apps/new?state='+escape(state)+'"><input type="hidden" name="manifest" value="'+escape(JSON.stringify(manifest(env)))+'"><button>Create GitHub App</button></form>');
 }
 if(s.phase==='created')return page('<p>App created. Install it on your personal account, then verify.</p><p><a href="https://github.com/apps/'+escape(s.slug)+'/installations/new">Install GitHub App</a></p><form method="POST" action="'+base+'/setup"><input type="hidden" name="action" value="verify-installation"><button>Verify installation</button></form>');
 if(s.phase==='installed')return page('<p>Ready. Connector endpoint: '+escape(base)+'</p><p>App ID: '+escape(s.app_id)+'; installation ID: '+escape(s.installation_id)+'</p>');
 return page('<p>Setup requires reconciliation. Phase: '+escape(s.phase)+'. Inspect the audit trail and GitHub registration before attempting recovery. App creation is locked.</p>');
}
async function authorize(request,env,oauth){
 const api=oauth.getOAuthApi(env),u=new URL(request.url),base=resource(env);
 if(u.pathname===env.MCP_PATH+'/auth/callback'){
  const {request:original,data,headers}=await api.finishUpstream(request);
  if(u.searchParams.has('error'))throw Error('GitHub sign-in declined');
  const user=await vault(env).identify(u.searchParams.get('code'),data.verifier);
  const {redirectTo}=await api.completeAuthorization({request:original,userId:user.subject,metadata:{},scope:original.scope,props:{subject:user.subject}});
  headers.set('Location',redirectTo);headers.set('Referrer-Policy','no-referrer');return new Response(null,{status:302,headers});
 }
 if(request.method==='GET'){
  const auth=await api.parseAuthRequest(request);if(auth.codeChallengeMethod!=='S256'||!auth.codeChallenge)throw Error('PKCE S256 required');const client=await api.lookupClient(auth.clientId),consent=await api.beginConsent(auth);
  const headers=Object.fromEntries(consent.headers.entries());
  return page('<p>Client: '+escape(client?.clientName||auth.clientId)+'</p><p>Return address: '+escape(auth.redirectUri)+'</p><p>Read repository contents and Actions. Optionally allow issue and PR comments, reviews, and issue management.</p><form method="POST" action="'+base+'/auth/authorize"><input type="hidden" name="handle" value="'+escape(consent.handle)+'"><label><input type="checkbox" name="collaborate" value="yes">Allow issue and PR collaboration</label><p><button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></p></form>',headers);
 }
 if(request.method!=='POST')return new Response(null,{status:405});
 sameOrigin(request,env);const f=await request.formData(),handle=String(f.get('handle')||'');
 if(f.get('decision')==='deny'){const denied=await api.denyConsent(request,handle);return new Response(null,{status:302,headers:denied.headers});}
 if(f.get('decision')!=='allow')throw Error('Explicit consent required');
 const scope=['github:read'];if(f.get('collaborate')==='yes')scope.push('github:collaborate');
 const approved=await api.approveConsent(request,handle,{scope});
 const verifier=crypto.randomUUID()+crypto.randomUUID();
 const upstream=await api.beginUpstream(approved.request,{data:{verifier},headers:approved.headers});
 const target=new URL('https://github.com/login/oauth/authorize');target.search=new URLSearchParams({client_id:await vault(env).clientID(),redirect_uri:base+'/auth/callback',state:upstream.state,code_challenge:await hash(verifier),code_challenge_method:'S256'});
 upstream.headers.set('Location',target.href);return new Response(null,{status:302,headers:upstream.headers});
}
export default {
 async dispatch(request,env,ctx){
  const u=new URL(request.url),base=env.MCP_PATH,correlation=crypto.randomUUID();
  if(u.origin!==env.PUBLIC_ORIGIN)return new Response('Not found',{status:404});
  // Health does not disclose credentials and does not claim installation readiness.
  if(u.pathname===base+'/health')return Response.json({service:'ghcaretaker',version:'0.0.1-beta.2'},{headers:{'Cache-Control':'no-store'}});
  const oauth=server(env);
  if(u.pathname==='/.well-known/oauth-protected-resource'+base)return Response.json({...metadata(env),authorization_servers:[resource(env)+'/auth'],scopes_supported:['github:read']},{headers:{'Cache-Control':'no-store'}});
  try{
   if(u.pathname===base+'/setup'||u.pathname.startsWith(base+'/setup/'))return await setup(request,env);
   if(u.pathname===base+'/auth/authorize'||u.pathname===base+'/auth/callback')return await authorize(request,env,oauth);
   if(u.pathname===base){
    return await handle(request,{...env,AUTH_ISSUER:resource(env)+'/auth'}, {authenticate:async()=>{
     const token=request.headers.get('Authorization')?.match(/^Bearer ([^ ]+)$/)?.[1];if(!token||token.length>16000)throw Error('Missing token');
     const result=await oauth.validateToken(resource(env),token,env);
     if(!result)throw Error('Invalid token');
     // Validated token fields are checked against owner and baseline scopes before any GitHub request.
     const subject=result.props?.subject,scopes=result.scope;
     if(result.audience!==resource(env)||result.userId!==env.GITHUB_OWNER_ID||subject!==env.GITHUB_OWNER_ID||!Array.isArray(scopes)||!scopes.includes('github:read'))throw Error('Invalid owner or scope');
     return {subject,scopes};
    },github:async(...args)=>{
     const [{github},config]=await Promise.all([import('./github.mjs'),vault(env).config()]);args[0]={...env,...config};return github(...args);
    }});
   }
   return await oauth.fetch(request,env,ctx);
  }catch(error){
   const known = new Set([
    'Configure owner-only Cloudflare Access before setup',
    'Invalid Access issuer',
    'Access authentication required',
    'Invalid Access token',
    'Invalid Access signature',
    'Access unavailable',
    'Unknown Access key',
    'Owner-only Access identity required'
   ]);
   console.error(JSON.stringify({
    category:'setup_rejected',
    correlation_id:correlation,
    reason:known.has(error?.message)?error.message:'Other setup or authorization failure'
   }));
   try{await audit(env,{correlation_id:correlation,category:'credential',phase:'rejected',operation:u.pathname.startsWith(base+'/setup')?'setup':'oauth',status:403});}catch{console.error(JSON.stringify({category:'audit_or_internal_failure',correlation_id:correlation}));return Response.json({error:'Audit unavailable',correlation_id:correlation},{status:503});}
   return Response.json({error:'Setup or authorization stopped. Inspect the audit trail.',correlation_id:correlation},{status:403,headers:{'Cache-Control':'no-store'}});
  }
 },
 async fetch(request,env,ctx){
  const correlation=crypto.randomUUID(),url=new URL(request.url);
  if(url.origin!==env.PUBLIC_ORIGIN)return new Response('Not found',{status:404});
  try{
   await audit(env,{correlation_id:correlation,category:'success',phase:'http_request',operation:url.pathname,request:{method:request.method,path:url.pathname,body:'Credential-bearing protocol payloads omitted'}});
   const response=await this.dispatch(request,env,ctx);
   await audit(env,{correlation_id:correlation,category:response.status===401||response.status===403?'credential':response.status>=400?'error':'success',phase:'http_response',operation:url.pathname,status:response.status,response:{body:'OAuth/setup payloads omitted; MCP results logged separately'}});
   return response;
  }catch{
   console.error(JSON.stringify({category:'audit_or_internal_failure',correlation_id:correlation}));
   return Response.json({error:'Operation stopped; reconcile before retrying',correlation_id:correlation},{status:503,headers:{'Cache-Control':'no-store'}});
  }
 }
};
