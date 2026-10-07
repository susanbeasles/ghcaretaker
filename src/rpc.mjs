import {WorkerEntrypoint} from 'cloudflare:workers';
import {CaretakerCore} from './capability.mjs';
export class CaretakerCapability extends WorkerEntrypoint {
  status(){return new CaretakerCore(this.env).status();}
  begin(owner){return new CaretakerCore(this.env).begin(owner);}
  convert(code,state,owner){return new CaretakerCore(this.env).convert(code,state,owner);}
  install(){return new CaretakerCore(this.env).install();}
  manifest(){return new CaretakerCore(this.env).manifest();}
  tools(scopes){return new CaretakerCore(this.env).tools(scopes);}
  mcp(request,session){return new CaretakerCore(this.env).mcp(request,session);}
  callTool(name,args,session){return new CaretakerCore(this.env).callTool(name,args,session);}
}
