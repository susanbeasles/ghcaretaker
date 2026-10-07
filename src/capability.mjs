import {handle} from './worker.mjs';
import {vault,manifest as appManifest} from './manifest.mjs';
import {tools} from './policy.mjs';
import {github} from './github.mjs';
export class CaretakerCore {
  constructor(env){this.env=env;}
  status(){return vault(this.env).status();}
  begin(owner){return vault(this.env).begin(owner);}
  convert(code,state,owner){return vault(this.env).convert(code,state,owner);}
  install(){return vault(this.env).install();}
  manifest(){const m=appManifest(this.env);m.redirect_url=this.env.AUTH_ORIGIN+'/owner/apps/caretaker/callback';m.setup_url=this.env.AUTH_ORIGIN+'/owner/apps/caretaker';delete m.callback_urls;return m;}
  tools(scopes){return tools.filter(t=>t.annotations.readOnlyHint||scopes.includes('github:collaborate'));}
  async mcp(request,session){
    if(session.profile!=='caretaker'||session.revoked||session.expires!==null&&session.expires<=Date.now()||!session.scopes.includes('github:read')||!Array.isArray(session.repos)||!session.repos.length)return Response.json({error:'capability-not-granted'},{status:403});
    if(request.headers.has('origin')&&request.headers.get('origin')!==this.env.AUTH_ORIGIN)return Response.json({error:'origin-denied'},{status:403});
    const headers=new Headers(request.headers);headers.delete('authorization');headers.delete('cookie');headers.delete('cf-access-jwt-assertion');headers.delete('origin');
    const internal=new Request(this.env.PUBLIC_ORIGIN+this.env.MCP_PATH,{method:request.method,headers,body:request.body,duplex:'half'});
    return handle(internal,this.env,{authenticate:async()=>({subject:this.env.GITHUB_OWNER_ID,scopes:session.scopes}),github:async(_env,identity,name,args,...rest)=>{
      const all=session.repos.includes(this.env.GITHUB_OWNER+'/*');
      if(!all&&(name==='list_repositories'||!session.repos.includes(this.env.GITHUB_OWNER+'/'+args.repo)))throw Error('Repository not granted');
      return github({...this.env,...await vault(this.env).config()},identity,name,args,...rest);
    }});
  }
  async callTool(name,args,session){const response=await this.mcp(new Request(this.env.AUTH_ORIGIN+'/mcp/caretaker',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:crypto.randomUUID(),method:'tools/call',params:{name,arguments:args}})}),session);return response.json();}
}
