import {handle} from './worker.mjs';
import {vault,manifest as appManifest} from './manifest.mjs';
import {tools,repositoryGrant,authorizeTool} from './policy.mjs';
import {github} from './github.mjs';
export class CaretakerCore {
  constructor(env){this.env=env;}
  status(){return vault(this.env).status();}
  webhook(request){return vault(this.env).webhook(request);}
  begin(owner){return vault(this.env).begin(owner);}
  convert(code,state,owner){return vault(this.env).convert(code,state,owner);}
  install(){return vault(this.env).install();}
  manifest(){const m=appManifest(this.env);m.redirect_url=this.env.AUTH_ORIGIN+'/owner/apps/caretaker/callback';m.setup_url=this.env.AUTH_ORIGIN+'/owner/apps/caretaker';delete m.callback_urls;return m;}
  tools(scopes){return tools.filter(t=>t.annotations.readOnlyHint||scopes.includes('github:collaborate'));}
  async mcp(request,session){
    try{if(!session||session.profile!=='caretaker'||session.revoked||session.expires!==null&&(!Number.isSafeInteger(session.expires)||session.expires<=Date.now())||!Array.isArray(session.scopes)||!session.scopes.includes('github:read')||session.scopes.some(scope=>!['github:read','github:collaborate'].includes(scope)))throw Error('Invalid session');repositoryGrant(session.repos,this.env.GITHUB_OWNER);}catch{return Response.json({error:'capability-not-granted'},{status:403});}
    if(request.headers.has('origin')&&request.headers.get('origin')!==this.env.AUTH_ORIGIN)return Response.json({error:'origin-denied'},{status:403});
    const headers=new Headers(request.headers);headers.delete('authorization');headers.delete('cookie');headers.delete('cf-access-jwt-assertion');headers.delete('origin');
    const internal=new Request(this.env.PUBLIC_ORIGIN+this.env.MCP_PATH,{method:request.method,headers,body:request.body,duplex:'half'});
    return handle(internal,this.env,{authenticate:async()=>({subject:this.env.GITHUB_OWNER_ID,scopes:session.scopes,repos:session.repos}),authorizeTool:(name,args)=>authorizeTool(name,args,session.repos,this.env.GITHUB_OWNER),github:async(_env,identity,name,args,...rest)=>{
      return github({...this.env,...await vault(this.env).config()},identity,name,args,...rest);
    }});
  }
  async callTool(name,args,session){const response=await this.mcp(new Request(this.env.AUTH_ORIGIN+'/mcp/caretaker',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:crypto.randomUUID(),method:'tools/call',params:{name,arguments:args}})}),session);return response.json();}
}
