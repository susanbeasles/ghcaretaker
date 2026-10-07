import {DurableObject} from 'cloudflare:workers';
import {VaultCore} from './vault-core.mjs';
export class AppVault extends DurableObject{
 constructor(ctx,env){super(ctx,env);this.core=new VaultCore(ctx.storage,env);}
 fetch(){return new Response('Not found',{status:404});}
 status(){return this.core.status();}
 begin(subject){return this.core.begin(subject);}
 convert(code,state,subject){return this.core.convert(code,state,subject);}
 install(){return this.core.install();}
 appJWT(){return this.core.appJWT();}
 config(){return this.core.config();}
}
