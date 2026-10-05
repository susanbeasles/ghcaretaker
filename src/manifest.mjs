import {permissions} from './policy.mjs';
export const resource=env=>env.PUBLIC_ORIGIN+(env.MCP_PATH||'/mcp');
export const vault=env=>env.APP_VAULT.get(env.APP_VAULT.idFromName('personal-app'));
export function manifest(env){
 const base=resource(env);
 return {name:'ghcaretaker-personal',url:'https://github.com/susanbeasles/ghcaretaker',description:'Audited personal GitHub caretaker; repository contents and Actions are read-only.',public:false,redirect_url:base+'/setup/callback',callback_urls:[base+'/auth/callback'],setup_url:base+'/setup/installed',hook_attributes:{active:false},default_permissions:{...permissions},default_events:[]};
}
export function assertApp(app,env){
 if(String(app.owner?.id)!==env.GITHUB_OWNER_ID||app.owner?.type!=='User'||app.owner?.login?.toLowerCase()!==env.GITHUB_OWNER)throw Error('App owner mismatch');
 if(!app.permissions||Object.entries(app.permissions).some(([k,v])=>permissions[k]!==v)||Object.entries(permissions).some(([k,v])=>app.permissions[k]!==v))throw Error('App permission mismatch');
 if(!Number.isSafeInteger(app.id)||!app.slug?.match(/^[a-zA-Z0-9-]+$/))throw Error('Invalid App identity');
}
